// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// failure_reset_sole_writer_injection_test.go — доказательство способности
// гейта «счёт решает один писатель» упасть И смолчать.
//
// Инъекция герметична и подаётся в ТОТ ЖЕ вердикт, что судит дерево
// (`check.JudgeFailureReset` с синтетическим корпусом): проверяются не только
// классификатор одного файла, но и обход, ведомость, сравнение с координатой
// дома и обе переписи. Прежняя редакция судила инъекцией лишь классификатор, и
// сборка вердикта на КРАСНОМ корпусе не исполнялась ни разу.
//
// Оси инъекции — по одной на каждую законную форму записи предмета и на каждое
// правило ведомости; каждый случай роняет ТОЛЬКО проверяемое.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const frHome = check.FailureResetHomeRel

// frHomeSource — дом: зовёт порт, поэтому премиса гейта выполнена.
const frHomeSource = `package humansession
func resetFailuresOnCompletedLogin(ctx ctxT, w Writer, in completedLogin) error {
	return w.ResetFailures(ctx, FailureByAddress, in.AddressKey)
}
`

// frPortSource — порт и его адаптер: объявление и реализация, не обнуление.
const frPortSource = `package humansession
type Writer interface {
	ResetFailures(ctx ctxT, scope FailureScope, key string) error
}
`

const frAdapterSource = `package pg
func (w *humanSessionWriter) ResetFailures(ctx ctxT, scope humansession.FailureScope, key string) error {
	return w.exec(ctx, key)
}
`

// frGoodLane — законная полоса: пишет уровень сессии и зовёт дом.
const frGoodLane = `package humansession
func (uc *LoginUseCase) issue(ctx ctxT, w Writer, user U, key string) error {
	if _, _, err := IssueSession(ctx, w, IssueInput{User: user}); err != nil {
		return err
	}
	return resetFailuresOnCompletedLogin(ctx, w, completedLogin{AddressKey: key})
}
`

// baseCorpus — корпус, на котором гейт обязан МОЛЧАТЬ.
func frBaseCorpus() check.TreeCorpus {
	return check.TreeCorpus{
		frHome: frHomeSource,
		"internal/apps/kaname/api/humansession/iface.go": frPortSource,
		"internal/repo/kaname/pg/human_session_repo.go":  frAdapterSource,
		"internal/apps/kaname/api/humansession/login.go": frGoodLane,
	}
}

func frJudge(t *testing.T, corpus check.TreeCorpus, ledger map[string]check.FailureResetLedgerEntry) ([]string, check.FailureResetVerdictCensus) {
	t.Helper()
	findings, census, err := check.JudgeFailureReset(corpus, frHome, ledger)
	if err != nil {
		t.Fatalf("вердикт на инъекции: %v", err)
	}
	return findings, census
}

// TestFailureResetGateIsSilentOnALawfulTree — КОНТРОЛЬ: на законном корпусе
// молчат все проверки. Без него красное ниже неотличимо от гейта, который
// краснеет всегда.
func TestFailureResetGateIsSilentOnALawfulTree(t *testing.T) {
	t.Parallel()
	findings, census := frJudge(t, frBaseCorpus(), nil)
	if len(findings) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ корпусе: %s", strings.Join(findings, "; "))
	}
	if census.HomeCalls == 0 {
		t.Fatalf("премиса не выполнена: дом не прочитан как зовущий порт (%+v)", census)
	}
	if census.LevelWritingFiles != 1 || census.ThroughHome != 1 {
		t.Fatalf("перепись популяции неверна: полос %d, через дом %d (ожидалось 1 и 1)",
			census.LevelWritingFiles, census.ThroughHome)
	}
}

// TestFailureResetGateRedsOnEveryReachingForm — КРАСНОЕ: обнуление достижимо
// мимо дома, в каждой форме, в которой оно записывается.
func TestFailureResetGateRedsOnEveryReachingForm(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, src, want string }{
		{"прямой вызов из полосы", `package humansession
func (uc *StepUpUseCase) settle(ctx ctxT, w Writer, key string) error {
	if err := w.PresentInSession(ctx, key); err != nil {
		return err
	}
	return w.ResetFailures(ctx, FailureByAddress, key)
}
`, "мимо единственного писателя"},
		{"значение-метод", `package humansession
func (uc *StepUpUseCase) settle(ctx ctxT, w Writer, key string) error {
	if err := w.PresentInSession(ctx, key); err != nil {
		return err
	}
	reset := w.ResetFailures
	return reset(ctx, FailureByAddress, key)
}
`, "мимо единственного писателя"},
		{"полоса пишет уровень и счёт не решает ВОВСЕ", `package registration
func (uc *RegisterUseCase) commit(ctx ctxT, w Writer, user U) error {
	_, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{User: user})
	return err
}
`, "счёт по адресу не решает"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := frBaseCorpus()
			corpus["internal/apps/kaname/api/humansession/some_lane.go"] = tc.src
			findings, census := frJudge(t, corpus, nil)
			if len(findings) == 0 {
				t.Fatalf("гейт НЕ покраснел на форме %q (%+v)", tc.name, census)
			}
			if !strings.Contains(strings.Join(findings, "\n"), tc.want) {
				t.Fatalf("находка не о предмете: ожидалось %q, получено:\n  %s", tc.want, strings.Join(findings, "\n  "))
			}
			if !strings.Contains(strings.Join(findings, "\n"), "some_lane.go") {
				t.Fatalf("находка без координаты: %s", strings.Join(findings, "; "))
			}
			t.Logf("красное: %s", findings[0])
		})
	}
}

// TestFailureResetLedgerExpiresBothWays — ведомость самоистекает В ОБЕ СТОРОНЫ:
// на нуле и на расхождении ЧИСЛА. Вторая половина — та, которой у ключа-файла
// не было: второй прямой вызов прощался вместе с первым.
func TestFailureResetLedgerExpiresBothWays(t *testing.T) {
	t.Parallel()

	oneReset := `package humansession
func (uc *CompleteRecoveryUseCase) complete(ctx ctxT, w Writer, user U, key string) error {
	if _, _, err := IssueSession(ctx, w, IssueInput{User: user}); err != nil {
		return err
	}
	return w.ResetFailures(ctx, FailureByAddress, key)
}
`
	twoResets := strings.Replace(oneReset, "	return w.ResetFailures(ctx, FailureByAddress, key)",
		"	if err := w.ResetFailures(ctx, FailureByAddress, key); err != nil {\n		return err\n	}\n	return w.ResetFailures(ctx, FailureBySource, key)", 1)
	const rel = "internal/apps/kaname/api/humansession/recovery_complete.go"
	ledger := map[string]check.FailureResetLedgerEntry{rel: {
		Resets: 1, Subject: "расхождение приёмок", Refs: "PRO-Robotech/kaname#305",
		Removal: "gh issue view 305 -R PRO-Robotech/kaname --json state -q .state → CLOSED",
	}}

	t.Run("число сошлось — молчит", func(t *testing.T) {
		t.Parallel()
		corpus := frBaseCorpus()
		corpus[rel] = oneReset
		if findings, _ := frJudge(t, corpus, ledger); len(findings) != 0 {
			t.Fatalf("ведомость по факту обязана молчать: %s", strings.Join(findings, "; "))
		}
	})

	t.Run("обращений стало больше — находка", func(t *testing.T) {
		t.Parallel()
		corpus := frBaseCorpus()
		corpus[rel] = twoResets
		findings, _ := frJudge(t, corpus, ledger)
		if len(findings) == 0 {
			t.Fatalf("второй прямой вызов прощён вместе с первым: ведомость прощает ФАЙЛ, а не число")
		}
		if !strings.Contains(strings.Join(findings, "\n"), "ПО ФАКТУ, а не потолком") {
			t.Fatalf("находка не о числе: %s", strings.Join(findings, "; "))
		}
	})

	t.Run("предмета не стало — находка", func(t *testing.T) {
		t.Parallel()
		findings, _ := frJudge(t, frBaseCorpus(), ledger)
		if len(findings) == 0 {
			t.Fatalf("запись без предмета не истекла")
		}
		if !strings.Contains(strings.Join(findings, "\n"), "больше нечего исключать") {
			t.Fatalf("находка не о самоистечении: %s", strings.Join(findings, "; "))
		}
	})

	t.Run("полоса без счёта названа ведомостью — молчит", func(t *testing.T) {
		t.Parallel()
		const reg = "internal/apps/kaname/api/registration/register.go"
		corpus := frBaseCorpus()
		corpus[reg] = `package registration
func (uc *RegisterUseCase) commit(ctx ctxT, w Writer, user U) error {
	_, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{User: user})
	return err
}
`
		findings, census := frJudge(t, corpus, map[string]check.FailureResetLedgerEntry{
			reg: {Resets: 0, Subject: "регистрация: счёта по новому адресу нет",
				Removal: "git grep -nE 'resetFailuresOnCompletedLogin|ResetFailures' -- " + reg + " → непусто"},
		})
		if len(findings) != 0 {
			t.Fatalf("названная ведомостью полоса обязана молчать: %s", strings.Join(findings, "; "))
		}
		if census.InLedger != 1 {
			t.Fatalf("перепись не отнесла полосу к ведомости: %+v", census)
		}
	})

	t.Run("полоса из ведомости перешла на дом — находка", func(t *testing.T) {
		t.Parallel()
		const reg = "internal/apps/kaname/api/registration/register.go"
		corpus := frBaseCorpus()
		corpus[reg] = `package registration
func (uc *RegisterUseCase) commit(ctx ctxT, w Writer, user U, key string) error {
	if _, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{User: user}); err != nil {
		return err
	}
	return resetFailuresOnCompletedLogin(ctx, w, completedLogin{AddressKey: key})
}
`
		findings, _ := frJudge(t, corpus, map[string]check.FailureResetLedgerEntry{
			reg: {Resets: 0, Subject: "регистрация: счёта по новому адресу нет", Removal: "полоса зовёт дом"},
		})
		if len(findings) == 0 {
			t.Fatalf("запись о полосе, решающей счёт через дом, не истекла: исключать ей нечего")
		}
		if !strings.Contains(strings.Join(findings, "\n"), "решает счёт через дом") {
			t.Fatalf("находка не о самоистечении по дому: %s", strings.Join(findings, "; "))
		}
	})
}

// TestFailureResetLedgerRelaxationNamesItsSubject — запись, прощающая ПРЯМОЕ
// обращение к порту, есть послабление: условие обнуления решается мимо дома.
// Такое послабление обязано назвать предмет трекера и исполнимый предикат
// снятия; без них оно неотличимо от забытого. Запись без прямых обращений
// (полоса счёта не трогает вовсе — безопасная сторона) предмета трекера не
// требует, но предикат снятия несёт и она.
func TestFailureResetLedgerRelaxationNamesItsSubject(t *testing.T) {
	t.Parallel()

	const rel = "internal/apps/kaname/api/humansession/recovery_complete.go"
	const direct = `package humansession
func (uc *CompleteRecoveryUseCase) complete(ctx ctxT, w Writer, user U, key string) error {
	if _, _, err := IssueSession(ctx, w, IssueInput{User: user}); err != nil {
		return err
	}
	return w.ResetFailures(ctx, FailureByAddress, key)
}
`
	const removal = "gh issue view 305 -R PRO-Robotech/kaname --json state -q .state → CLOSED"
	cases := []struct {
		name  string
		entry check.FailureResetLedgerEntry
		// want — пусто: запись законна и обязана молчать.
		want string
	}{
		{"прощает обращение, предмет трекера не назван — находка",
			check.FailureResetLedgerEntry{Resets: 1, Subject: "расхождение приёмок", Removal: removal},
			"предмета трекера"},
		{"прощает обращение, ссылка не в форме «владелец/репозиторий#номер» — находка",
			check.FailureResetLedgerEntry{Resets: 1, Subject: "расхождение приёмок", Refs: "#305", Removal: removal},
			"предмета трекера"},
		{"прощает обращение, предиката снятия нет — находка",
			check.FailureResetLedgerEntry{Resets: 1, Subject: "расхождение приёмок", Refs: "PRO-Robotech/kaname#305"},
			"предиката снятия"},
		{"прощает обращение, предмет и предикат названы — молчит",
			check.FailureResetLedgerEntry{Resets: 1, Subject: "расхождение приёмок", Refs: "PRO-Robotech/kaname#305", Removal: removal},
			""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := frBaseCorpus()
			corpus[rel] = direct
			findings, _ := frJudge(t, corpus, map[string]check.FailureResetLedgerEntry{rel: tc.entry})
			joined := strings.Join(findings, "\n")
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("законная запись обязана молчать: %s", joined)
				}
				return
			}
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("послабление без %q не покраснело либо находка не о предмете:\n  %s", tc.want, joined)
			}
			if !strings.Contains(joined, rel) {
				t.Fatalf("находка без координаты записи: %s", joined)
			}
			t.Logf("красное: %s", findings[0])
		})
	}

	t.Run("полоса без обращений: предмет трекера не нужен, предикат снятия нужен", func(t *testing.T) {
		t.Parallel()
		const reg = "internal/apps/kaname/api/registration/register.go"
		corpus := frBaseCorpus()
		corpus[reg] = `package registration
func (uc *RegisterUseCase) commit(ctx ctxT, w Writer, user U) error {
	_, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{User: user})
	return err
}
`
		if findings, _ := frJudge(t, corpus, map[string]check.FailureResetLedgerEntry{
			reg: {Resets: 0, Subject: "регистрация", Removal: "полоса начала решать счёт"},
		}); len(findings) != 0 {
			t.Fatalf("запись без прямых обращений предмета трекера не требует: %s", strings.Join(findings, "; "))
		}
		findings, _ := frJudge(t, corpus, map[string]check.FailureResetLedgerEntry{
			reg: {Resets: 0, Subject: "регистрация"},
		})
		if !strings.Contains(strings.Join(findings, "\n"), "предиката снятия") {
			t.Fatalf("запись без предиката снятия не покраснела: %s", strings.Join(findings, "; "))
		}
	})
}

// TestFailureResetGateStaysSilentOnLegitimateTwins — МОЛЧАНИЕ на законных
// формах того же имени: без этой половины гейт ловил бы имя, а не существо.
func TestFailureResetGateStaysSilentOnLegitimateTwins(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, rel, src string }{
		{"объявление порта в интерфейсе", "internal/apps/kaname/api/humansession/iface.go", frPortSource},
		{"реализация порта адаптером", "internal/repo/kaname/pg/human_session_repo.go", frAdapterSource},
		{"файл без порта и без записи уровня", "internal/apps/kaname/api/humansession/logout.go", `package humansession
func (uc *LogoutUseCase) Execute(ctx ctxT, w Writer) error { return w.EndSession(ctx) }
`},
		{"имя дома в ПРОЗЕ, а не вызовом", "internal/apps/kaname/api/humansession/doc.go", `package humansession
// Полосы зовут resetFailuresOnCompletedLogin, а порт напрямую не зовут —
// ResetFailures здесь только назван, и это комментарий, а не обращение.
`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := frBaseCorpus()
			corpus[tc.rel] = tc.src
			if findings, _ := frJudge(t, corpus, nil); len(findings) != 0 {
				t.Fatalf("гейт краснеет на законной форме %q: %s", tc.name, strings.Join(findings, "; "))
			}
		})
	}
}

// TestFailureResetJudgeReportsBothCensuses — перепись ДВЕ, и вторая растёт от
// полос, которых первая не видит: полоса без обращения к порту в перепись по
// порту не попадает вовсе.
func TestFailureResetJudgeReportsBothCensuses(t *testing.T) {
	t.Parallel()
	corpus := frBaseCorpus()
	corpus["internal/apps/kaname/api/registration/register.go"] = `package registration
func (uc *RegisterUseCase) commit(ctx ctxT, w Writer, user U) error {
	_, _, err := humansession.IssueSession(ctx, w, humansession.IssueInput{User: user})
	return err
}
`
	_, census := frJudge(t, corpus, nil)
	if census.FilesNamingPort != 3 {
		t.Fatalf("перепись по порту: называющих порт %d, ожидалось 3 (дом, порт, адаптер)", census.FilesNamingPort)
	}
	if census.LevelWritingFiles != 2 {
		t.Fatalf("перепись популяции: полос %d, ожидалось 2 (вход и регистрация)", census.LevelWritingFiles)
	}
	t.Logf("первая перепись видит %d файлов по порту, вторая — %d полос: регистрация есть только во второй",
		census.FilesNamingPort, census.LevelWritingFiles)
}

// ───────────────────────── посылка гейта ─────────────────────────
//
// Гейт судит ИМЯ порта; «счёт не обнуляется мимо дома» из этого следует, пока
// строки счёта удаляются по ключу ТОЛЬКО реализацией порта. Посылка — свойство
// адаптера, а не разбора, поэтому она судится отдельно: по ключу — только
// `ResetFailures`, по возрасту — только `SweepAgedFailures`, иными операторами —
// нигде.

// frAdapterRows — адаптер, на котором посылка ВЫПОЛНЕНА: одно удаление по
// ключу в реализации порта, одно по возрасту в уборщике, чтение и вставка.
const frAdapterRows = "package pg\n" +
	"func (r *HumanSessionRepo) CountFailures(ctx ctxT, scope S, key string, since T) (int, error) {\n" +
	"	return r.one(ctx, `SELECT count(*) FROM login_failures WHERE scope = $1 AND key = $2 AND failed_at > $3`, scope, key, since)\n" +
	"}\n" +
	"func (r *HumanSessionRepo) SweepAgedFailures(ctx ctxT, grace D, batch int) (int64, bool, error) {\n" +
	"	return r.exec(ctx, `\n" +
	"		DELETE FROM login_failures\n" +
	"		 WHERE ctid IN (\n" +
	"		       SELECT ctid FROM login_failures WHERE failed_at <= now() - $1::interval LIMIT $2)`, grace, batch)\n" +
	"}\n" +
	"func (w *humanSessionWriter) RecordFailure(ctx ctxT, scope S, key string, at T) error {\n" +
	"	return w.exec(ctx, `INSERT INTO login_failures (scope, key, failed_at) VALUES ($1, $2, $3)`, scope, key, at)\n" +
	"}\n" +
	"func (w *humanSessionWriter) ResetFailures(ctx ctxT, scope S, key string) error {\n" +
	"	return w.exec(ctx, `DELETE FROM login_failures WHERE scope = $1 AND key = $2`, scope, key)\n" +
	"}\n"

const frRowsRel = "internal/repo/kaname/pg/human_session_repo.go"

func frRowsCorpus() check.TreeCorpus {
	return check.TreeCorpus{frRowsRel: frAdapterRows}
}

// TestFailureRowRemovalPremiseIsSilentOnTheLawfulAdapter — КОНТРОЛЬ посылки:
// на законном адаптере молчит и называет обе положительные половины.
func TestFailureRowRemovalPremiseIsSilentOnTheLawfulAdapter(t *testing.T) {
	t.Parallel()
	findings, census, err := check.JudgeFailureRowRemovals(frRowsCorpus())
	if err != nil {
		t.Fatalf("вердикт посылки: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("посылка краснеет на ЗАКОННОМ адаптере: %s", strings.Join(findings, "; "))
	}
	if census.ByKeyInPort != 1 || census.ByAgeInSweep != 1 || census.Removals != 2 {
		t.Fatalf("перепись посылки неверна: удалений %d, по ключу в порту %d, по возрасту в уборщике %d (ожидалось 2, 1, 1)",
			census.Removals, census.ByKeyInPort, census.ByAgeInSweep)
	}
}

// TestFailureRowRemovalPremiseRedsOnEveryOtherRemoval — КРАСНОЕ: строки счёта
// снимаются мимо реализации порта либо мимо уборщика, в каждой форме записи,
// которую разбор знает; форма, которую он не классифицирует, — тоже находка,
// а не молчание.
func TestFailureRowRemovalPremiseRedsOnEveryOtherRemoval(t *testing.T) {
	t.Parallel()
	lane := func(body string) string {
		return "package pg\nfunc (w *humanSessionWriter) EndSession(ctx ctxT, key string) error {\n" + body + "\n}\n"
	}
	cases := []struct{ name, src, want string }{
		{"удаление по ключу в другом методе", lane("	return w.exec(ctx, `DELETE FROM login_failures WHERE scope = $1 AND key = $2`, key)"),
			"по ключу"},
		{"удаление по ключу со схемой", lane("	return w.exec(ctx, `delete from kaname.login_failures where key = $1`, key)"),
			"по ключу"},
		{"удаление по ключу склейкой литералов", lane(`	return w.exec(ctx, "DELETE FROM " + "login_failures WHERE key = $1", key)`),
			"по ключу"},
		{"удаление по ключу внутри CTE", lane("	return w.exec(ctx, `WITH gone AS (DELETE FROM login_failures WHERE key = $1 RETURNING 1) SELECT count(*) FROM gone`, key)"),
			"по ключу"},
		{"удаление по возрасту мимо уборщика", lane("	return w.exec(ctx, `DELETE FROM login_failures WHERE failed_at < $1`, key)"),
			"по возрасту"},
		{"перенос следа в прошлое оператором UPDATE", lane("	return w.exec(ctx, `UPDATE login_failures SET failed_at = now() - interval '1 day' WHERE key = $1`, key)"),
			"неизвестным посылке способом"},
		{"опустошение таблицы", lane("	return w.exec(ctx, `TRUNCATE TABLE login_failures`)"),
			"неизвестным посылке способом"},
		{"удаление без условия", lane("	return w.exec(ctx, `DELETE FROM login_failures`)"),
			"неизвестным посылке способом"},
		{"удаление по ключу текстом в объявлении пакета", "package pg\nconst wipe = `DELETE FROM login_failures WHERE key = $1`\n",
			"вне функции"},
		{"одноимённая свободная функция, а не реализация порта",
			"package pg\nfunc ResetFailures(ctx ctxT, q Q, key string) error {\n	return q.exec(ctx, `DELETE FROM login_failures WHERE key = $1`, key)\n}\n",
			"по ключу"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := frRowsCorpus()
			corpus["internal/repo/kaname/pg/some_repo.go"] = tc.src
			findings, census, err := check.JudgeFailureRowRemovals(corpus)
			if err != nil {
				t.Fatalf("вердикт посылки: %v", err)
			}
			joined := strings.Join(findings, "\n")
			if len(findings) == 0 {
				t.Fatalf("посылка НЕ покраснела на форме %q (удалений %d)", tc.name, census.Removals)
			}
			if !strings.Contains(joined, tc.want) || !strings.Contains(joined, "some_repo.go") {
				t.Fatalf("находка не о предмете либо без координаты: ожидалось %q, получено:\n  %s", tc.want, joined)
			}
			t.Logf("красное: %s", findings[0])
		})
	}
}

// TestFailureRowRemovalPremiseStaysSilentOnLegitimateTwins — МОЛЧАНИЕ на
// законных формах того же вида: без этой половины посылка ловила бы слово, а
// не оператор.
func TestFailureRowRemovalPremiseStaysSilentOnLegitimateTwins(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, src string }{
		{"чтение и вставка в другом месте", "package pg\nfunc (r *Repo) Oldest(ctx ctxT) error {\n" +
			"	_ = `SELECT min(failed_at) FROM login_failures WHERE key = $1`\n" +
			"	return r.exec(ctx, `INSERT INTO login_failures (scope, key, failed_at) VALUES ($1, $2, $3)`)\n}\n"},
		{"оператор в прозе строки и в комментарии", "package pg\n" +
			"// DELETE FROM login_failures WHERE key = $1 — так делает только реализация порта.\n" +
			"func (r *Repo) Explain() string {\n	return \"refused to delete from login_failures by key outside the port\"\n}\n"},
		{"удаление по ключу из ДРУГОЙ таблицы", "package pg\nfunc (r *Repo) Purge(ctx ctxT, key string) error {\n" +
			"	if err := r.exec(ctx, `DELETE FROM login_failures_archive WHERE key = $1`, key); err != nil {\n		return err\n	}\n" +
			"	return r.exec(ctx, `DELETE FROM recovery_codes WHERE key = $1`, key)\n}\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			corpus := frRowsCorpus()
			corpus["internal/repo/kaname/pg/some_repo.go"] = tc.src
			findings, _, err := check.JudgeFailureRowRemovals(corpus)
			if err != nil {
				t.Fatalf("вердикт посылки: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("посылка краснеет на законной форме %q: %s", tc.name, strings.Join(findings, "; "))
			}
		})
	}
}

// TestFailureRowRemovalPremiseNamesAnEmptyAdapter — «ноль находок» отличим от
// «ноль прочитанного»: корпус без адаптера даёт нули обеих положительных
// половин, и проба дерева роняет на них прогон, а не зеленеет.
func TestFailureRowRemovalPremiseNamesAnEmptyAdapter(t *testing.T) {
	t.Parallel()
	findings, census, err := check.JudgeFailureRowRemovals(check.TreeCorpus{
		"internal/apps/kaname/api/humansession/logout.go": "package humansession\nfunc (uc *LogoutUseCase) Execute() error { return nil }\n",
	})
	if err != nil {
		t.Fatalf("вердикт посылки: %v", err)
	}
	if len(findings) != 0 || census.ByKeyInPort != 0 || census.ByAgeInSweep != 0 || census.Files != 1 {
		t.Fatalf("корпус без адаптера: находок %d, по ключу в порту %d, по возрасту в уборщике %d, файлов %d "+
			"(ожидалось 0, 0, 0, 1)", len(findings), census.ByKeyInPort, census.ByAgeInSweep, census.Files)
	}
}

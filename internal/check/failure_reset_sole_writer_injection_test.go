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

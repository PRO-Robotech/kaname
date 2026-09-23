// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// completed_login_test.go — РЕШЕНИЕ единственного писателя, закреплённое по
// каждой полосе, и ПРЕМИСА оси «заведено» (Ф12 Р7 ред. 11; Ф3 Р10 ред. 11;
// kaname#287).
//
// Гейт дерева `internal/check/failure_reset_sole_writer_test.go` держит МЕСТО:
// всякая полоса, завершающая вход, зовёт единственного писателя. Здесь держится
// ОТВЕТ: что он решает на каждом сочетании заведённого и предъявленного. Два
// разных свойства, и ни одно не выводится из другого.
//
// Ось «заведено» ВЫВОДИТСЯ из словаря способов, а не выписывается: способ,
// добавленный в словарь и не разобранный здесь, роняет премису. Выписанная
// таблица не может заметить строки, которой в ней нет, — перепись считала бы
// собственное объявление.
package humansession

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// resetSpyWriter — дублёр записи, отвечающий ТОЛЬКО за обнуление. Порт встроен
// нулевым интерфейсом намеренно: всякий иной вызов роняет пробу паникой, то
// есть дублёр структурно неспособен молча проглотить чужой путь.
type resetSpyWriter struct {
	Writer
	called bool
}

func (w *resetSpyWriter) ResetFailures(context.Context, FailureScope, string) error {
	w.called = true
	return nil
}

// axisVerdict — может ли способ попасть в ось «заведено».
type axisVerdict struct {
	// InAxis — способ выводится из строк способов входа, значит в оси бывает.
	InAxis bool
	// Why — почему так; у исключённого — чем это грозит и когда снимается.
	Why string
}

// axisDecision — РЕШЕНИЕ по каждому способу словаря `assurance.Methods()`.
// Способ без записи роняет премису: словарь расширили, а ось не разобрали.
var axisDecision = map[string]axisVerdict{
	assurance.MethodPassword.String():     {InAxis: true, Why: "строка способа входа `password` — вид словаря `domain.LoginMethodKinds`"},
	assurance.MethodTOTP.String():         {InAxis: true, Why: "строка `totp` в состоянии `active`"},
	assurance.MethodLookupSecret.String(): {InAxis: true, Why: "выводится из той же строки `totp`: набор запасных кодов чеканится вместе с ней"},
	assurance.MethodRecoveryCode.String(): {InAxis: false, Why: "код восстановления не заводится строкой способа входа: он выдаётся потоком восстановления, даёт «1» и ко «2» не прибавляет"},
	assurance.MethodWebAuthn.String(): {InAxis: false, Why: "ключ доступа — ресурс СВОЕЙ таблицы, строки `webauthn` в способах входа НЕТ " +
		"(`internal/domain/access_key.go`). Следствие названо прямо: у личности, чей второй фактор — ключ, " +
		"требуемый уровень считается как «1», и вход одним паролём счёт обнулит. Сегодня недостижимо — " +
		"потребителя, поднимающего уровень сессии утверждением ключа, в прод-коде нет; появится (Ф13) — " +
		"ось обязана учесть ключи тем же изменением"},
}

// TestEnrolledAxisReadsExactlyTheLoginMethodKinds — ПРЕМИСА оси «заведено».
//
// Ось выводится из строк способов входа, поэтому в ней ровно те способы, что
// объявлены видами `domain.LoginMethodKinds` (плюс запасной код, выводимый из
// строки `totp`). Расширится словарь видов — премиса покраснеет здесь, а не
// молча откроет окно подбора у полосы, которая о ключах не знает.
func TestEnrolledAxisReadsExactlyTheLoginMethodKinds(t *testing.T) {
	t.Parallel()

	vocabulary := assurance.Methods()
	if len(vocabulary) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: словарь способов пуст — решать не о чем")
	}
	kinds := map[string]bool{}
	for _, k := range domain.LoginMethodKinds() {
		kinds[string(k)] = true
	}
	if len(kinds) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: видов способов входа прочитано 0")
	}

	inAxis := 0
	for _, m := range vocabulary {
		name := m.String()
		decision, ok := axisDecision[name]
		if !ok {
			t.Fatalf("способ %q есть в словаре `assurance.Methods()`, а решения об оси «заведено» у него НЕТ.\n"+
				"Способ, добавленный в словарь и не разобранный здесь, попадёт в ось молча либо молча из неё "+
				"выпадет — и второе откроет окно подбора второго фактора (kaname#287).", name)
		}
		if decision.InAxis {
			inAxis++
		}
		// Запасной код — единственный, кто в оси есть, а видом строки не является.
		viaRow := kinds[name] || name == assurance.MethodLookupSecret.String()
		if decision.InAxis != viaRow {
			t.Fatalf("решение об оси и дерево разошлись у способа %q: решение говорит «в оси = %v», "+
				"а вид строки способа входа %v.\nПричина решения: %s",
				name, decision.InAxis, kinds[name], decision.Why)
		}
	}
	t.Logf("перепись: способов в словаре %d, видов строк способов входа %d, в оси «заведено» %d; "+
		"исключены: код восстановления и ключ доступа — у обоих строки способа входа нет",
		len(vocabulary), len(kinds), inAxis)
}

// TestLoginCompletedToEnrolledLevel — решение по каждой полосе. Строки названы
// полосой, которая приводит к сочетанию, поэтому таблица читается ведомостью
// решений по всем семи полосам, завершающим вход.
func TestLoginCompletedToEnrolledLevel(t *testing.T) {
	t.Parallel()

	var (
		noFactor   = []assurance.Method{assurance.MethodPassword}
		withFactor = []assurance.Method{assurance.MethodPassword, assurance.MethodTOTP, assurance.MethodLookupSecret}
	)
	password := []string{assurance.MethodPassword.String()}
	passwordTOTP := []string{assurance.MethodPassword.String(), assurance.MethodTOTP.String()}
	passwordBackup := []string{assurance.MethodPassword.String(), assurance.MethodLookupSecret.String()}
	recovery := []string{assurance.MethodRecoveryCode.String()}
	key := []string{assurance.MethodWebAuthn.String()}

	cases := []struct {
		lane      string
		enrolled  []assurance.Method
		presented []string
		want      bool
	}{
		// вход (login.go)
		{"вход паролём у личности БЕЗ фактора — завершённый вход (Ф3 Р10 без изменений)", noFactor, password, true},
		{"вход паролём у личности С фактором — сессия «1», вход НЕ завершён (Ф12-14, замок #287)", withFactor, password, false},
		{"вход паролём и кодом по времени — «2» (Ф12-11)", withFactor, passwordTOTP, true},
		{"вход паролём и запасным кодом — «2» (Ф12-12)", withFactor, passwordBackup, true},

		// церемония (step_up.go)
		{"церемония кодом из сессии «1» — доводит до «2» (Ф12-15/18)", withFactor, passwordTOTP, true},
		{"церемония паролем у личности С фактором — остаётся «1» (замок #287)", withFactor, password, false},
		{"церемония паролем у личности БЕЗ фактора — «1» и есть её полный уровень", noFactor, password, true},

		// глаголы под сессией (sf_enroll.go, sf_remove.go, sf_backup_codes.go).
		// Снимок «заведено» берётся ДО транзакции, поэтому подтверждение видит
		// строку ещё `pending`, а снятие — ещё `active`; решение от этого не
		// меняется, и обе пары закреплены здесь.
		{"подтверждение заведения: код принят, строка ещё `pending`", noFactor, passwordTOTP, true},
		{"подтверждение заведения: строка уже `active` (снимок после записи)", withFactor, passwordTOTP, true},
		{"снятие фактора: код принят, строка ещё `active`", withFactor, passwordTOTP, true},
		{"снятие фактора: строка уже снята (снимок после записи)", noFactor, passwordTOTP, true},
		{"перечеканка запасных кодов: код принят, фактор на месте", withFactor, passwordBackup, true},

		// восстановление (recovery_complete.go) — сегодня зовёт порт НАПРЯМУЮ и
		// сюда не приходит; строки показывают, ЧТО решил бы дом, поэтому
		// расхождение приёмок видно числом, а не спором.
		{"восстановление у личности БЕЗ фактора: код восстановления даёт «1»", noFactor, recovery, true},
		{"восстановление у личности С фактором: «1» ниже «2»", withFactor, recovery, false},

		// ключ доступа: в ось «заведено» не входит (см. TestEnrolledAxis…).
		// Предъявленный ключ уровень ПОДНИМАЕТ — эта половина работает;
		// заведённый ключ требуемый уровень НЕ поднимает, и это названный
		// остаток, а не молчание.
		{"ключ предъявлен: «2» достигнуто, требуемое «1» — обнуляет", noFactor, key, true},
		{"ключ ЗАВЕДЁН как второй фактор, предъявлен один пароль: ось ключа не видит, требуемое «1» — " +
			"обнуляет (остаток, снимается вместе с потребителем Ф13)", noFactor, password, true},

		// fail-closed
		{"заведённого нет вовсе — уровень неизвестен", nil, password, false},
		{"предъявленного нет вовсе — уровня нет", withFactor, nil, false},
		{"предъявлено слово вне словаря — уровня нет", withFactor, []string{"smoke-signal"}, false},
	}
	// ПРЕМИСА: пустая таблица зеленеет, печатая «закреплено 0», — число
	// печаталось бы, не утверждая ничего. Непустота требуется отдельно.
	if len(cases) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: сочетаний в таблице 0 — решение не закреплено ни одним")
	}
	// ПОКРЫТИЕ ВЫВОДИТСЯ из словаря: способ, добавленный в `assurance.Methods()`
	// и не встреченный ни одной строкой, роняет пробу. Выписанная таблица
	// строки, которой в ней нет, заметить не может.
	seen := map[string]bool{}
	for _, tc := range cases {
		for _, m := range tc.enrolled {
			seen[m.String()] = true
		}
		for _, m := range tc.presented {
			seen[m] = true
		}
	}
	covered := 0
	for _, m := range assurance.Methods() {
		if !seen[m.String()] {
			t.Fatalf("способ %q есть в словаре `assurance.Methods()`, а в таблице решений не встречается "+
				"ни как заведённый, ни как предъявленный: решение по нему не закреплено ничем", m.String())
		}
		covered++
	}

	for _, tc := range cases {
		t.Run(tc.lane, func(t *testing.T) {
			t.Parallel()
			if got := loginCompletedToEnrolledLevel(tc.presented, tc.enrolled); got != tc.want {
				t.Fatalf("вход завершён до уровня всех заведённых способов = %v, ожидалось %v\n"+
					"  заведено:    %v\n  предъявлено: %v", got, tc.want, tc.enrolled, tc.presented)
			}
		})
	}
	// Единица счёта названа: способы СЛОВАРЯ, а не все встреченные слова —
	// среди последних есть заведомо чужое, поданное ради fail-closed.
	t.Logf("перепись: сочетаний закреплено %d; способов словаря покрыто %d из %d (слов встречено всего %d)",
		len(cases), covered, len(assurance.Methods()), len(seen))
}

// TestResetFailuresRefusesOnUnknownEnrollment — fail-closed: «заведённое
// неизвестно» счёт не обнуляет. Отличается от «ничего не заведено» отдельным
// полем, потому что пустое значение обязано означать «пусто».
func TestResetFailuresRefusesOnUnknownEnrollment(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   completedLogin
		want bool
	}{
		{"заведённое прочитано, вход завершён — обнуляет", completedLogin{
			Enrolled: []assurance.Method{assurance.MethodPassword}, EnrolledKnown: true,
			AddressKey: "a@example.invalid", Presented: []string{assurance.MethodPassword.String()},
		}, true},
		{"заведённое НЕ прочитано — счёт остаётся", completedLogin{
			EnrolledKnown: false,
			AddressKey:    "a@example.invalid", Presented: []string{assurance.MethodPassword.String()},
		}, false},
		{"ключа адреса нет — обнулять нечего", completedLogin{
			Enrolled: []assurance.Method{assurance.MethodPassword}, EnrolledKnown: true,
			AddressKey: "", Presented: []string{assurance.MethodPassword.String()},
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			w := &resetSpyWriter{}
			if err := resetFailuresOnCompletedLogin(t.Context(), w, tc.in); err != nil {
				t.Fatalf("обнуление: %v", err)
			}
			if w.called != tc.want {
				t.Fatalf("порт обнуления позван = %v, ожидалось %v", w.called, tc.want)
			}
		})
	}
}

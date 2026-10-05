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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
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
	assurance.MethodWebAuthn.String(): {InAxis: true, Why: "ключ доступа — ресурс СВОЕЙ таблицы, строки `webauthn` в способах входа НЕТ " +
		"(`internal/domain/access_key.go`); в ось входит отдельным чтением `AccessKeyEnrolled` с тех пор, как ключ " +
		"стал производителем уровня сессии (Ф13). Без него у личности с паролем и ключом требуемый уровень был бы «1», " +
		"и вход одним паролём счёт обнулял бы"},
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
		// Запасной код и ключ — в оси есть, а видом строки способа входа не
		// являются: первый выводится из строки `totp`, второй читается своей
		// таблицей (`enrolledForCompletion`).
		viaRow := kinds[name] || name == assurance.MethodLookupSecret.String() || name == assurance.MethodWebAuthn.String()
		if decision.InAxis != viaRow {
			t.Fatalf("решение об оси и дерево разошлись у способа %q: решение говорит «в оси = %v», "+
				"а вид строки способа входа %v.\nПричина решения: %s",
				name, decision.InAxis, kinds[name], decision.Why)
		}
	}
	t.Logf("перепись: способов в словаре %d, видов строк способов входа %d, в оси «заведено» %d; "+
		"исключён: код восстановления — строки способа входа у него нет; ключ доступа — в оси своим чтением",
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

	withKey := []assurance.Method{assurance.MethodPassword, assurance.MethodWebAuthn}
	passwordKey := []string{assurance.MethodWebAuthn.String(), assurance.MethodPassword.String()}

	// reached — уровень ЗАПИСИ сессии после успеха (выданный либо легший
	// предъявлением внутри сессии); presented — слова записи, ради переписи
	// покрытия словаря: решение их не читает (kaname#208, `session_level.go`).
	cases := []struct {
		lane      string
		enrolled  []assurance.Method
		presented []string
		reached   string
		want      bool
	}{
		// вход (login.go)
		{"вход паролём у личности БЕЗ фактора — завершённый вход (Ф3 Р10 без изменений)", noFactor, password, "1", true},
		{"вход паролём у личности С фактором — сессия «1», вход НЕ завершён (Ф12-14, замок #287)", withFactor, password, "1", false},
		{"вход паролём и кодом по времени — «2» (Ф12-11)", withFactor, passwordTOTP, "2", true},
		{"вход паролём и запасным кодом — «2» (Ф12-12)", withFactor, passwordBackup, "2", true},

		// церемония (step_up.go)
		{"церемония кодом из сессии «1» — доводит до «2» (Ф12-15/18)", withFactor, passwordTOTP, "2", true},
		{"церемония паролем у личности С фактором — остаётся «1» (замок #287)", withFactor, password, "1", false},
		{"церемония паролем у личности БЕЗ фактора — «1» и есть её полный уровень", noFactor, password, "1", true},

		// глаголы под сессией (sf_enroll.go, sf_remove.go, sf_backup_codes.go).
		// Снимок «заведено» берётся ДО транзакции, поэтому подтверждение видит
		// строку ещё `pending`, а снятие — ещё `active`; решение от этого не
		// меняется, и обе пары закреплены здесь.
		{"подтверждение заведения: код принят, строка ещё `pending`", noFactor, passwordTOTP, "2", true},
		{"подтверждение заведения: строка уже `active` (снимок после записи)", withFactor, passwordTOTP, "2", true},
		{"снятие фактора: код принят, строка ещё `active`", withFactor, passwordTOTP, "2", true},
		{"снятие фактора: строка уже снята (снимок после записи)", noFactor, passwordTOTP, "2", true},
		{"перечеканка запасных кодов: код принят, фактор на месте", withFactor, passwordBackup, "2", true},

		// завершение восстановления (recovery_complete.go; Ф5 Р5, Ф5-25,
		// kaname#305): сессия восстановления — «1»; у заблокированной дом не
		// зовётся вовсе — сессии нет.
		{"восстановление у личности БЕЗ фактора: код восстановления даёт «1»", noFactor, recovery, "1", true},
		{"восстановление у личности С фактором: «1» ниже «2»", withFactor, recovery, "1", false},

		// ключ доступа (Ф13): в оси «заведено» — своим чтением и худшим исходом
		// флагов (`assurance.GuaranteedLevels`): заведённый ключ требует «2».
		{"вход ключом без проверки пользователя у личности с паролем и ключом — «2» (Ф13-32)", withKey, key, "2", true},
		{"вход ключом с проверкой пользователя — «3»", withKey, key, "3", true},
		{"вход паролём у личности с паролем и ключом — «1» ниже «2»: НЕ обнуляет (окно подбора закрыто)", withKey, password, "1", false},
		{"предъявление пароля внутри сессии ключа — запись «3» прежняя", withKey, passwordKey, "3", true},
		{"ключ без пароля у личности без иных способов — «2»", []assurance.Method{assurance.MethodWebAuthn}, key, "2", true},

		// fail-closed
		{"заведённого нет вовсе — уровень неизвестен", nil, password, "1", false},
		{"уровня нет вовсе", withFactor, nil, "", false},
		{"уровень вне оси", withFactor, []string{"smoke-signal"}, "smoke-signal", false},
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
			if got := loginCompletedToEnrolledLevel(tc.reached, tc.enrolled); got != tc.want {
				t.Fatalf("вход завершён до уровня всех заведённых способов = %v, ожидалось %v\n"+
					"  заведено:    %v\n  достигнуто: %q (слова записи %v)", got, tc.want, tc.enrolled, tc.reached, tc.presented)
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
			AddressKey: "a@example.invalid", Level: "1",
		}, true},
		{"заведённое НЕ прочитано — счёт остаётся", completedLogin{
			EnrolledKnown: false,
			AddressKey:    "a@example.invalid", Level: "1",
		}, false},
		{"ключа адреса нет — обнулять нечего", completedLogin{
			Enrolled: []assurance.Method{assurance.MethodPassword}, EnrolledKnown: true,
			AddressKey: "", Level: "1",
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

// absentMethodsStore и absentUsers — непустые значения портов, которые никто не
// зовёт: сборка обязана отказать РАНЬШЕ, на пустом хранилище способов входа.
type (
	absentMethodsStore struct{ Store }
	absentUsers        struct{ UserDirectory }
)

// enrollmentReaders — полосы пакета, зовущие `enrollmentBeforeWrite`: имена
// типов-приёмников, выведенные РАЗБОРОМ исходников пакета, а не выписанные.
func enrollmentReaders(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог пакета не прочитан: %v", err)
	}
	readers := map[string]bool{}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: разбор %s: %v", name, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil || fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			calls := false
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "enrollmentBeforeWrite" {
						calls = true
					}
				}
				return !calls
			})
			if !calls {
				continue
			}
			recv := fd.Recv.List[0].Type
			if star, ok := recv.(*ast.StarExpr); ok {
				recv = star.X
			}
			if id, ok := recv.(*ast.Ident); ok {
				readers[id.Name] = true
			}
		}
	}
	return readers
}

// TestEveryEnrollmentReaderRefusesToBuildWithoutTheMethodStore — ПОСЫЛКА того,
// что у `enrollmentBeforeWrite` нет ветви «хранилища способов нет»: всякая
// полоса, которая его зовёт, без хранилища способов входа НЕ СОБИРАЕТСЯ, а
// журнал ей подставляет конструктор. Перечень полос выводится разбором пакета:
// новый вызывающий без строки сборки здесь роняет пробу, строка без
// вызывающего — тоже.
func TestEveryEnrollmentReaderRefusesToBuildWithoutTheMethodStore(t *testing.T) {
	t.Parallel()
	store := absentMethodsStore{}
	build := map[string]func() error{
		"LoginUseCase": func() error {
			_, err := NewLoginUseCase(LoginDeps{Store: store, Users: absentUsers{}})
			return err
		},
		"StepUpUseCase": func() error {
			_, err := NewStepUpUseCase(SecondFactorDeps{Store: store})
			return err
		},
		"ConfirmSecondFactorUseCase": func() error {
			_, err := NewConfirmSecondFactorUseCase(SecondFactorDeps{Store: store})
			return err
		},
		"RemoveSecondFactorUseCase": func() error {
			_, err := NewRemoveSecondFactorUseCase(SecondFactorDeps{Store: store})
			return err
		},
		"RegenerateBackupCodesUseCase": func() error {
			_, err := NewRegenerateBackupCodesUseCase(SecondFactorDeps{Store: store})
			return err
		},
		// Вход ключом (Ф13): хранилище испытаний дано, хранилища способов нет.
		"AccessKeyLoginUseCase": func() error {
			_, err := NewAccessKeyLoginUseCase(AccessKeyLoginDeps{Store: store, Keys: noKeyLoginStore{}})
			return err
		},
	}

	readers := enrollmentReaders(t)
	if len(readers) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: полос, зовущих enrollmentBeforeWrite, разбором найдено 0")
	}
	names := make([]string, 0, len(readers))
	for name := range readers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		b, ok := build[name]
		if !ok {
			t.Fatalf("полоса %s зовёт enrollmentBeforeWrite, а строки «сборка без хранилища способов» у неё здесь нет: "+
				"посылка снятой ветви о ней не проверена", name)
		}
		err := b()
		if err == nil || !strings.Contains(err.Error(), "login method store required") {
			t.Fatalf("полоса %s собирается без хранилища способов входа (ошибка сборки: %v) — ветвь "+
				"«хранилища нет» у enrollmentBeforeWrite снова достижима", name, err)
		}
	}
	for name := range build {
		if !readers[name] {
			t.Fatalf("строке %s больше нечего проверять: полоса не зовёт enrollmentBeforeWrite", name)
		}
	}
	t.Logf("перепись: полос, читающих заведённое до транзакции, %d (%s) — все отказывают в сборке без хранилища способов",
		len(names), strings.Join(names, ", "))
}

// TestEnrolledForCompletionReadsTheKeyTable — ключ доступа попадает в ось
// «заведено» ТОЛЬКО по ответу своего чтения: есть строка ключа — `webauthn` в
// оси; нет — оси прежние; чтение отказало — отказ всего вывода (fail-closed:
// неизвестное «заведено» счёт не обнуляет).
func TestEnrolledForCompletionReadsTheKeyTable(t *testing.T) {
	t.Parallel()
	read := func(_ context.Context, _ domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
		if kind == domain.LoginMethodPassword {
			return domain.LoginMethod{Kind: kind}, nil
		}
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "not found")
	}
	keys := func(has bool, err error) accessKeyRead {
		return func(context.Context, domain.UserID) (bool, error) { return has, err }
	}
	got, err := enrolledForCompletion(t.Context(), read, keys(true, nil), "usr-a")
	if err != nil || len(got) != 2 || got[1] != assurance.MethodWebAuthn {
		t.Fatalf("строка ключа есть: ось %v, ошибка %v — ожидалось [password webauthn]", got, err)
	}
	got, err = enrolledForCompletion(t.Context(), read, keys(false, nil), "usr-a")
	if err != nil || len(got) != 1 || got[0] != assurance.MethodPassword {
		t.Fatalf("строки ключа нет: ось %v, ошибка %v — ожидалось [password]", got, err)
	}
	if _, err := enrolledForCompletion(t.Context(), read, keys(false, errors.New("store down")), "usr-a"); err == nil {
		t.Fatal("чтение ключей отказало, а ось выведена — неизвестное прочитано как «нет ключа»")
	}
}

// noKeyLoginStore — хранилище испытаний полосы входа ключом, которое сборка
// лишь проверяет на присутствие; его методы проба не зовёт.
type noKeyLoginStore struct{ AccessKeyLoginStore }

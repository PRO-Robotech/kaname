// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_admission_gates_test.go — гейты дерева приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456, §9 пп. 4, 15;
// EV-86) и условий аудита поверхности: по РЕАЛЬНОМУ дереву и инъекцией в обе
// стороны — дефект краснеет с координатой, законный близнец молчит, пустой
// обход — находка. Предмет и границы — в шапке `address_admission_gates.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// ─── Один писатель отметки ──────────────────────────────────────────────────

// TestTheAddressMarkHasOneWriterTheConfirmVerb — у отметки подтверждения ровно
// ДВА вызывающих писателя в непроверочном коде: глагол подтверждения и
// завершение восстановления, заводящее первый пароль личности без способа
// входа (Ф5 Р9 п. 3–4, редакция 7 — Д16; `kaname#608`). Оператор отметки один;
// вызывающих двое, и каждый назван файлом. Третий — находка.
func TestTheAddressMarkHasOneWriterTheConfirmVerb(t *testing.T) {
	t.Parallel()
	calls, parsed, err := check.MarkWriterCalls(prodGoFiles(t, moduleRoot(t)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов %d · вызовов писателя отметки %d: %v", parsed, len(calls), calls)
	if parsed == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: обход пуст")
	}
	if len(calls) != len(markWriterCallers) {
		t.Fatalf("писатель отметки зовётся не ровно названными вызывающими %v: %v", markWriterCallers, calls)
	}
	for i, c := range calls {
		if !strings.HasPrefix(c, markWriterCallers[i]+":") {
			t.Fatalf("вызов %s — не из названного вызывающего %s: %v", c, markWriterCallers[i], calls)
		}
	}
}

// markWriterCallers — названные вызывающие писателя отметки, в порядке обхода
// (пути по алфавиту): завершение восстановления (первый пароль, Ф5 Р9) и глагол
// подтверждения (Ф6).
var markWriterCallers = []string{
	"internal/apps/kaname/api/humansession/recovery_complete.go",
	"internal/apps/kaname/api/humansession/verification.go",
}

// TestTheAddressMarkWriterInjection — второй вызывающий (путь хука поставщика,
// переносящий флаг поставщика) краснеет; законный близнец — один глагол —
// молчит.
func TestTheAddressMarkWriterInjection(t *testing.T) {
	t.Parallel()
	confirm := `package humansession
func (uc *X) Execute() { _, _ = w.MarkEmailVerified(ctx, id, email, now) }
`
	hook := `package user
func (uc *Y) doUpsert() { _ = methods.MarkEmailVerified(ctx, id, email, now) }
`
	decl := `package pg
func (r *LoginMethodRepo) MarkEmailVerified(ctx context.Context) error { return nil }
`
	calls, _, err := check.MarkWriterCalls(map[string]string{
		"internal/apps/kaname/api/humansession/verification.go": confirm,
		"internal/apps/kaname/api/user/internal_upsert.go":      hook,
		"internal/repo/kaname/pg/login_method_repo.go":          decl,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 {
		t.Fatalf("инъекция второго вызывающего не найдена: %v", calls)
	}
	twin, _, _ := check.MarkWriterCalls(map[string]string{
		"internal/apps/kaname/api/humansession/verification.go": confirm,
		"internal/repo/kaname/pg/login_method_repo.go":          decl,
	})
	if len(twin) != 1 {
		t.Fatalf("законный близнец: объявление метода вызовом не считается, вызов один: %v", twin)
	}
}

// ─── Полосы выдачи спрашивают правило (§9 п. 15) ────────────────────────────

// issuanceLanes — полосы выдачи удостоверения человеку. Знаменатель — виды
// выдачи токен-эндпоинта (машинные и словарь церемонии фундамента) и полоса
// базового секрета. Хуков выпуска и обновления внешнего поставщика, прежде
// стоявших здесь, больше нет (kaname#363).
var issuanceLanes = []check.IssuanceLane{
	{Name: tokenpolicy.GrantTypeClientCredentials, File: "internal/apps/kaname/api/client_token/issue.go", Func: "weighCutoff"},
	{Name: tokenpolicy.GrantTypeJWTBearer, File: "internal/apps/kaname/api/client_token/issue.go", Func: "weighCutoff"},
	{Name: string(oauthceremony.GrantAuthorizationCode), File: "internal/ceremonyport/access_tokens.go", Func: "IssueAccessToken"},
	{Name: string(oauthceremony.GrantRefreshToken), File: "internal/ceremonyport/access_tokens.go", Func: "IssueAccessToken"},
	{Name: "базовый секрет", File: "internal/repo/kaname/pg/basic_credential_repo.go", Func: "ownerAdmission"},
}

// TestEveryHumanIssuanceLaneAsksTheRule — гейт переписи полос выдачи.
func TestEveryHumanIssuanceLaneAsksTheRule(t *testing.T) {
	t.Parallel()
	// Предпосылка: словарь видов выдачи церемонии фундамента покрыт перечнем.
	for _, k := range oauthceremony.GrantKinds() {
		var named bool
		for _, l := range issuanceLanes {
			if l.Name == string(k) {
				named = true
			}
		}
		if !named {
			t.Errorf("вид выдачи церемонии %q полосой перечня не назван — перечень разошёлся со словарём фундамента", k)
		}
	}
	inspected, findings, err := check.IssuanceLaneFindings(prodGoFiles(t, moduleRoot(t)), issuanceLanes)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: полос %d · осмотрено функций %d", len(issuanceLanes), inspected)
	for _, f := range findings {
		t.Error(f)
	}
}

// TestIssuanceLaneInjection — полоса, выдающая мимо правила, краснеет с
// координатой; законный близнец молчит; пустой перечень — находка.
func TestIssuanceLaneInjection(t *testing.T) {
	t.Parallel()
	bypass := `package lane
func issue() error { return sign() }
`
	lawful := `package lane
func issue() error { v, _ := revocationpolicy.AtIssuance(ctx, r, p, at); _ = v; return sign() }
`
	lane := []check.IssuanceLane{{Name: "probe", File: "internal/lane/issue.go", Func: "issue"}}
	_, f, err := check.IssuanceLaneFindings(map[string]string{"internal/lane/issue.go": bypass}, lane)
	if err != nil || len(f) != 1 || !strings.Contains(f[0], "internal/lane/issue.go") {
		t.Fatalf("полоса мимо правила не найдена: %v %v", f, err)
	}
	_, f, _ = check.IssuanceLaneFindings(map[string]string{"internal/lane/issue.go": lawful}, lane)
	if len(f) != 0 {
		t.Fatalf("законный близнец дал находки: %v", f)
	}
	_, f, _ = check.IssuanceLaneFindings(map[string]string{}, nil)
	if len(f) == 0 {
		t.Fatal("пустой перечень — не вердикт")
	}
}

// ─── Формы двери решения (§9 п. 4) ──────────────────────────────────────────

// doorForms — перепись форм двери решения по трём строкам.
var doorForms = map[string]check.DoorRow{
	"Check":                      check.DoorUnderPredicate,
	"CheckWithContext":           check.DoorUnderPredicate,
	"CheckWithContextConsistent": check.DoorUnderPredicate,
	"BatchCheckWithContext":      check.DoorUnderPredicate,
	"ListSubjects":               check.DoorUnderPredicate,
	"ListUsers":                  check.DoorUnderPredicate,
	"Sources":                    check.DoorRecords,
	"DirectRelations":            check.DoorRecords,
	"DirectRelationsMany":        check.DoorRecords,
	"FormReachable":              check.DoorLiveness,
}

func doorSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "internal", "authzcascade", "own_gates.go"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return string(b)
}

// TestEveryDoorFormIsDeclaredAndUnderThePredicate — гейт переписи форм двери.
func TestEveryDoorFormIsDeclaredAndUnderThePredicate(t *testing.T) {
	t.Parallel()
	inspected, findings, err := check.DoorFormFindings(doorSource(t), doorForms)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: под предикатом %d · отвечают записями %d · живость %d",
		inspected[check.DoorUnderPredicate], inspected[check.DoorRecords], inspected[check.DoorLiveness])
	for _, f := range findings {
		t.Error(f)
	}
	if inspected[check.DoorUnderPredicate] != 6 || inspected[check.DoorRecords] != 3 || inspected[check.DoorLiveness] != 1 {
		t.Errorf("перепись форм не совпала с приёмкой (6 · 3 · 1): %v", inspected)
	}
}

// TestDoorFormInjection — форма без строки и форма «под предикатом» мимо
// предиката краснеют; законный близнец молчит.
func TestDoorFormInjection(t *testing.T) {
	t.Parallel()
	src := doorSource(t)
	undeclared := src + `
func (c *Client) ListObjectsProbe() ([]string, error) { return nil, nil }
`
	_, f, err := check.DoorFormFindings(undeclared, doorForms)
	if err != nil || !strings.Contains(strings.Join(f, "\n"), "ListObjectsProbe") {
		t.Fatalf("форма без строки не найдена: %v %v", f, err)
	}
	bypass := strings.Replace(src, "admitted, err := admission.Subject(ctx, c.form, subject)\n\tif err != nil || !admitted {\n\t\treturn false, err\n\t}\n", "", 1)
	if bypass == src {
		t.Fatal("НЕ-ВЫПОЛНИЛОСЬ: инъекция не легла — форма предиката в CheckWithContext переписана")
	}
	_, f, _ = check.DoorFormFindings(bypass, doorForms)
	if !strings.Contains(strings.Join(f, "\n"), "CheckWithContext") {
		t.Fatalf("форма мимо предиката не найдена: %v", f)
	}
	_, f, _ = check.DoorFormFindings(src, doorForms)
	if len(f) != 0 {
		t.Fatalf("законный близнец дал находки: %v", f)
	}
}

// ─── Писатели очереди наших писем (условие аудита) ──────────────────────────

// TestEveryMailWriterChargesItsWindowFirst — каждый писатель очереди НАШИХ
// писем списывает окно раньше постановки.
func TestEveryMailWriterChargesItsWindowFirst(t *testing.T) {
	t.Parallel()
	census, findings, err := check.MailWriterFindings(prodGoFiles(t, moduleRoot(t)))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: файлов %d · писателей %d (%v) · окно сами %d · предел у вызывающего %d",
		census.FilesParsed, len(census.Writers), census.Writers, census.ChargedHere, census.ChargedByCaller)
	for _, f := range findings {
		t.Error(f)
	}
	if len(census.Writers) != 3 {
		t.Errorf("писателей очереди писем не три (приглашение, восстановление, подтверждение): %v", census.Writers)
	}
}

// TestMailWriterInjection — новый писатель письма без списания окна краснеет с
// координатой; законный близнец (через списание) молчит; пустой обход —
// находка.
func TestMailWriterInjection(t *testing.T) {
	t.Parallel()
	bare := `package pg
func (w *writer) EmitNewsletter() error { return invite_mail_outbox.EmitNewsletterTx(ctx, w.tx) }
`
	charged := `package pg
func (w *writer) EmitNewsletter() error {
	if _, err := chargeInviteMailWindowTx(ctx, w.tx, k, to, l); err != nil { return err }
	return invite_mail_outbox.EmitNewsletterTx(ctx, w.tx)
}
`
	_, f, err := check.MailWriterFindings(map[string]string{"internal/repo/kaname/pg/newsletter.go": bare})
	if err != nil || !strings.Contains(strings.Join(f, "\n"), "internal/repo/kaname/pg/newsletter.go") {
		t.Fatalf("писатель без окна не найден: %v %v", f, err)
	}
	_, f, _ = check.MailWriterFindings(map[string]string{"internal/repo/kaname/pg/newsletter.go": charged})
	if len(f) != 0 {
		t.Fatalf("законный близнец дал находки: %v", f)
	}
	_, f, _ = check.MailWriterFindings(map[string]string{"internal/x/x.go": "package x\n"})
	if len(f) == 0 {
		t.Fatal("пустой обход — не вердикт")
	}
}

// ─── EV-86 — посадка не пишет в строки людей ────────────────────────────────

// TestEV86_LandingWritesNothingIntoPeopleRows — EV-86.
func TestEV86_LandingWritesNothingIntoPeopleRows(t *testing.T) {
	t.Parallel()
	root := moduleRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "internal", "migrations", "20260927190000_address_verification_is_our_verb.sql"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	writes, lines := check.PeopleRowWrites(string(b))
	t.Logf("перепись: строк наката %d · операторов записи в строки людей %d", lines, len(writes))
	if lines == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: накат пуст")
	}
	if len(writes) != 0 {
		t.Errorf("посадка пишет в строки людей: %v", writes)
	}
	// Контроль в обратную сторону: тот же распознаватель находит оператор
	// писателя отметки в адаптере.
	adapter, err := os.ReadFile(filepath.Join(root, "internal", "repo", "kaname", "pg", "login_method_repo.go"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	control, _ := check.PeopleRowWrites("-- +goose Up\n" + string(adapter))
	if len(control) == 0 {
		t.Fatal("контроль: оператор писателя отметки в адаптере не найден — распознаватель слеп")
	}
}

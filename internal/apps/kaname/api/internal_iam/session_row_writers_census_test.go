// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

// session_row_writers_census_test.go — ПЕРЕПИСЬ ПИСАТЕЛЕЙ СТРОК СЕССИИ ВХОДА:
// у каждого писателя в дереве есть сцена внахлёст с удалением личности, у
// каждой сцены — писатель в дереве (задача kaname#382).
//
// Сцены (`session_row_writers_identity_deletion_integration_test.go`) держат
// ПОРЯДОК ЗАМКОВ каждого писателя, но только тех, о которых знают. Писатель,
// заведённый завтра, остался бы без сцены молча — и порядок его захвата не
// держало бы ничто, кроме текста его запроса. Эта перепись делает такого
// писателя находкой.
//
// # Что считается писателем
//
// Функция прод-дерева, ссылающаяся на дверь, пишущую строки `human_sessions`:
// методы писателя сессии (`InsertSession`, `EndSession`, `EndOtherSessions`,
// `RotateBearer`, `PresentInSession`), выдача (`IssueSession`) и уборка
// (`SweepUnservableSessions`). Сами двери — адаптер `internal/repo/kaname/pg`
// и тело `IssueSession` — писателями не считаются: писатель — тот, кто их
// зовёт.
//
// # Все законные формы ссылки
//
//	w.EndSession(ctx, …)                 — вызов метода;
//	humansession.IssueSession(ctx, …)    — вызов функции другого пакета;
//	IssueSession(ctx, …)                 — вызов функции своего пакета;
//	Sweep: r.Sessions.SweepUnservableSessions — метод значением, без вызова.
//
// Каждая форма доказана инъекцией (`TestSessionRowWriterCensusKnowsEveryForm`).

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// sessionRowDoors — двери, пишущие строки `human_sessions`.
var sessionRowDoors = map[string]bool{
	"InsertSession": true, "EndSession": true, "EndOtherSessions": true,
	"RotateBearer": true, "PresentInSession": true,
	"IssueSession": true, "SweepUnservableSessions": true,
}

// writerSceneLedger — писатель → сцена внахлёст с удалением личности либо
// причина, по которой её нет. Ключ — «пакет.Получатель.функция».
var writerSceneLedger = map[string]string{
	"humansession.ChangePasswordUseCase.Execute":        "TestIntegration_PasswordChangeAndIdentityDeletionDoNotDeadlock",
	"humansession.CompleteRecoveryUseCase.complete":     "TestIntegration_SessionWriterRecoveryCompletionAndIdentityDeletionDoNotDeadlock",
	"humansession.ConfirmSecondFactorUseCase.Execute":   "TestIntegration_SessionWriterSecondFactorConfirmAndIdentityDeletionDoNotDeadlock",
	"humansession.LoginUseCase.issue":                   "TestIntegration_SessionWriterSecondFactorLoginAndIdentityDeletionDoNotDeadlock",
	"humansession.LogoutUseCase.Execute":                "TestIntegration_SessionWriterLogoutAndIdentityDeletionDoNotDeadlock",
	"humansession.RegenerateBackupCodesUseCase.Execute": "TestIntegration_SessionWriterBackupCodesAndIdentityDeletionDoNotDeadlock",
	"humansession.RemoveSecondFactorUseCase.Execute":    "TestIntegration_SessionWriterSecondFactorRemovalAndIdentityDeletionDoNotDeadlock",
	"humansession.StepUpUseCase.Execute":                "TestIntegration_SessionWriterStepUpAndIdentityDeletionDoNotDeadlock",
	"internal_iam.Handler.commitOwnForceLogout":         "TestIntegration_ForceLogoutAndIdentityDeletionDoNotDeadlock",
	"retention.WithHumanSessions":                       "TestIntegration_SessionWriterSweepAndIdentityDeletionDoNotDeadlock",
	// Регистрация выдаёт сессию той же транзакцией, что ЗАВОДИТ личность:
	// удалению не к чему прийти внахлёст — личности в зафиксированном
	// состоянии ещё нет.
	"registration.RegisterUseCase.Execute": exemptNoOverlap,
}

// exemptNoOverlap — сцены нет by construction; причина — у строки ведомости.
const exemptNoOverlap = "—"

// doorBodies — тела дверей: они зовут двери, но писателями не являются.
var doorBodies = map[string]bool{"humansession.IssueSession": true}

// writerCensus — объём осмотренного.
type writerCensus struct {
	files, funcs, refs int
}

// sessionRowWriters — писатели в файлах каталогов dirs (обход рекурсивный,
// тестовые файлы и адаптер базы — вне обхода), с координатой первой ссылки.
func sessionRowWriters(dirs []string, skip func(path string) bool) (map[string]string, writerCensus, error) {
	found := map[string]string{}
	var c writerCensus
	fset := token.NewFileSet()
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || skip(path) {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
			if perr != nil {
				return perr
			}
			c.files++
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				c.funcs++
				key := f.Name.Name + "." + funcKey(fn)
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					name, pos := doorRef(n)
					if name == "" {
						return true
					}
					c.refs++
					if doorBodies[key] {
						return true
					}
					if _, seen := found[key]; !seen {
						found[key] = fset.Position(pos).String()
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			return nil, c, err
		}
	}
	return found, c, nil
}

// funcKey — «Получатель.функция» либо «функция».
func funcKey(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	t := fn.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// doorRef — имя двери, на которую ссылается узел, во ВСЕХ законных формах:
// селектор (вызов метода, функция другого пакета, метод значением) и вызов
// голого имени своего пакета.
func doorRef(n ast.Node) (string, token.Pos) {
	switch v := n.(type) {
	case *ast.SelectorExpr:
		if sessionRowDoors[v.Sel.Name] {
			return v.Sel.Name, v.Pos()
		}
	case *ast.CallExpr:
		if id, ok := v.Fun.(*ast.Ident); ok && sessionRowDoors[id.Name] {
			return id.Name, v.Pos()
		}
	}
	return "", token.NoPos
}

// judgeWriterCensus — писатели без сцены, сцены без писателя, названные сцены,
// которых нет среди проб.
func judgeWriterCensus(found map[string]string, ledger map[string]string, scenes map[string]bool) []string {
	var out []string
	for key, at := range found {
		scene, ok := ledger[key]
		switch {
		case !ok:
			out = append(out, "писатель строк сессии "+key+" ("+at+") без сцены внахлёст с удалением личности: "+
				"порядок его захвата не держит ничто, кроме текста его запроса")
		case scene != exemptNoOverlap && !scenes[scene]:
			out = append(out, "писателю "+key+" назначена сцена "+scene+", которой среди проб нет")
		}
	}
	for key := range ledger {
		if _, ok := found[key]; !ok {
			out = append(out, "строка ведомости "+key+" — писателя с этим именем в дереве нет: запись пережила предмет")
		}
	}
	sort.Strings(out)
	return out
}

// sceneTests — имена проб пакета.
func sceneTests(t *testing.T, dir string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	names, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil || len(names) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: пробы пакета не найдены в %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, name := range names {
		f, perr := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && strings.HasPrefix(fn.Name.Name, "Test") {
				out[fn.Name.Name] = true
			}
		}
	}
	return out
}

func TestEverySessionRowWriterHasAnIdentityDeletionScene(t *testing.T) {
	internal := platformtree.RequirePath(t, "internal")
	cmd := platformtree.RequirePath(t, "cmd")
	adapter := filepath.Join(internal, "repo", "kaname", "pg") + string(filepath.Separator)
	found, c, err := sessionRowWriters([]string{internal, cmd}, func(path string) bool {
		return strings.HasPrefix(path, adapter)
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	scenes := sceneTests(t, wd)
	findings := judgeWriterCensus(found, writerSceneLedger, scenes)

	keys := make([]string, 0, len(found))
	for k := range found {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	t.Logf("перепись: файлов %d · функций %d · ссылок на двери %d · писателей %d · строк ведомости %d · проб пакета %d · находок %d",
		c.files, c.funcs, c.refs, len(found), len(writerSceneLedger), len(scenes), len(findings))
	for _, k := range keys {
		t.Logf("  %s → %s (%s)", k, writerSceneLedger[k], found[k])
	}
	if c.refs == 0 || len(found) == 0 {
		t.Fatal("обход пуст: ни одной ссылки на дверь строк сессии — перепись судила бы о непрочитанном")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Инъекции: те же тела (`sessionRowWriters`, `judgeWriterCensus`), вход —
// синтетический пакет в t.TempDir().

func writeProbePackage(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "probe")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "probe.go"), []byte("package probe\n\n"+body), 0o600); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return dir
}

func noSkip(string) bool { return false }

// Каждая законная форма ссылки опознаётся; близнец — ссылка на имя, дверью
// не являющееся, — молчит.
func TestSessionRowWriterCensusKnowsEveryForm(t *testing.T) {
	cases := []struct {
		name, body, key string
	}{
		{"вызов метода", "type U struct{}\nfunc (u *U) Run(w interface{ EndSession() }) { w.EndSession() }\n", "probe.U.Run"},
		{"функция другого пакета", "import hs \"x/humansession\"\nfunc Run() { hs.IssueSession() }\n", "probe.Run"},
		{"функция своего пакета", "func IssueSession() {}\nfunc Run() { IssueSession() }\n", "probe.Run"},
		{"метод значением", "type R struct{ S interface{ SweepUnservableSessions() } }\nfunc With(r R) any { return r.S.SweepUnservableSessions }\n", "probe.With"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			found, _, err := sessionRowWriters([]string{writeProbePackage(t, c.body)}, noSkip)
			if err != nil {
				t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
			}
			if _, ok := found[c.key]; !ok {
				t.Fatalf("форма «%s» не опознана: писатель %s выпал из переписи; найдено %v", c.name, c.key, found)
			}
		})
	}
	found, c, err := sessionRowWriters([]string{writeProbePackage(t,
		"type U struct{}\nfunc (u *U) Run(w interface{ EndSessionLater() }) { w.EndSessionLater() }\n")}, noSkip)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if len(found) != 0 || c.funcs == 0 {
		t.Fatalf("близнец: имя, дверью не являющееся, засчитано писателем (%v), либо обход пуст (функций %d)", found, c.funcs)
	}
}

// Дефект: писатель без строки ведомости — находка, называющая его. Близнец —
// тот же писатель со строкой и сценой — молчание.
func TestSessionRowWriterCensusFindsAWriterWithoutAScene(t *testing.T) {
	found := map[string]string{"probe.U.Run": "probe.go:3:1"}
	scenes := map[string]bool{"TestProbeScene": true}
	got := judgeWriterCensus(found, map[string]string{}, scenes)
	if len(got) != 1 || !strings.Contains(got[0], "probe.U.Run") || !strings.Contains(got[0], "без сцены") {
		t.Fatalf("писатель без сцены не найден: %v", got)
	}
	if got := judgeWriterCensus(found, map[string]string{"probe.U.Run": "TestProbeScene"}, scenes); len(got) != 0 {
		t.Fatalf("близнец: писатель со сценой назван находкой: %v", got)
	}
}

// Дефект с другой стороны: строка ведомости без писателя и сцена, которой нет
// среди проб, — находки; освобождение без сцены сцены не требует.
func TestSessionRowWriterCensusFindsStaleAndDanglingRows(t *testing.T) {
	scenes := map[string]bool{"TestProbeScene": true}
	stale := judgeWriterCensus(map[string]string{}, map[string]string{"probe.Gone": "TestProbeScene"}, scenes)
	if len(stale) != 1 || !strings.Contains(stale[0], "пережила предмет") {
		t.Fatalf("строка ведомости без писателя не найдена: %v", stale)
	}
	found := map[string]string{"probe.U.Run": "probe.go:3:1"}
	dangling := judgeWriterCensus(found, map[string]string{"probe.U.Run": "TestNoSuchScene"}, scenes)
	if len(dangling) != 1 || !strings.Contains(dangling[0], "TestNoSuchScene") {
		t.Fatalf("сцена, которой нет среди проб, не найдена: %v", dangling)
	}
	if got := judgeWriterCensus(found, map[string]string{"probe.U.Run": exemptNoOverlap}, scenes); len(got) != 0 {
		t.Fatalf("освобождение с причиной потребовало сцены: %v", got)
	}
}

// Тело двери писателем не считается; писатель, зовущий дверь, — считается.
func TestSessionRowWriterCensusSkipsTheDoorBody(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "humansession")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	src := "package humansession\n\ntype W interface{ InsertSession() }\n" +
		"func IssueSession(w W) { w.InsertSession() }\nfunc Login(w W) { IssueSession(w) }\n"
	if err := os.WriteFile(filepath.Join(dir, "issue.go"), []byte(src), 0o600); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	found, _, err := sessionRowWriters([]string{dir}, noSkip)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if _, ok := found["humansession.IssueSession"]; ok {
		t.Fatalf("тело двери засчитано писателем: %v", found)
	}
	if _, ok := found["humansession.Login"]; !ok {
		t.Fatalf("писатель, зовущий дверь, выпал из переписи: %v", found)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const callerAdmissionTest = "TestHopAdmits_FollowsTheNarrowingDeclaration"

// callerFullTreeTestBudget ограничивает обход штатным бюджетом unit-пакета CI.
// Общий срок пакета дополнительно ограничивает каждый обход ниже.
const callerFullTreeTestBudget = 45 * time.Minute

const callerReaderControl = "TestInternalFront_CheckExecutesRealHandler"
const callerLookupControl = "TestInternalFront_LookupSubjectKeepsOwnHopDenied"
const callerNarrowingControl = "TestInternalFront_CheckLaneIsNoWiderThanGRPC"
const callerHandlerSource = "internal/apps/kaname/api/internal_iam/handler.go"
const callerDispositionSource = "internal/check/caller_identity_experimental_disposition.json"

// callerFullTreeTestContext оставляет время до общего timeout пакета для
// завершения отменённого обхода и cleanup. Проверки явной отмены независимы.
func callerFullTreeTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	deadline := time.Now().Add(callerFullTreeTestBudget)
	if packageDeadline, ok := t.Deadline(); ok {
		cleanupDeadline := packageDeadline.Add(-30 * time.Second)
		if cleanupDeadline.Before(deadline) {
			deadline = cleanupDeadline
		}
	}
	return context.WithDeadline(context.Background(), deadline)
}

// callerExperimentalDisposition — описание наблюдения конкретного RPC;
// отброшенное чтение не объявляется сужением довода в runtime-таблице.
type callerExperimentalDisposition struct {
	RPC      string
	Producer string
	Site     string
	Kind     string
	Reason   string
}

// TestCallerIdentityAdmissionFindsAnUndeclaredRealReader — проверяет гейт дерева
// настоящим новым потребителем в существующем зарегистрированном RPC.
// Обе копии содержат одинаковое чтение; отличается только запись объявления.
func TestCallerIdentityAdmissionFindsAnUndeclaredRealReader(t *testing.T) {
	root := moduleRoot(t)
	declared := callerActualTree(t, root)
	undeclared := callerActualTree(t, root)
	where := callerInjectReader(t, declared)
	if other := callerInjectReader(t, undeclared); other != where {
		t.Fatalf("фикстура: координаты близнецов различаются: %s / %s", where, other)
	}
	callerDeclareReader(t, declared)
	callerAssertSingleDeclarationDelta(t, declared, undeclared)

	// Оба дерева проходят все контроли до вопроса о гейте. Ошибка отдельного
	// контроля не обрывает перепись; общий барьер не даёт выдать незаконную
	// фикстуру за отрицательный опыт гейта.
	fixturesOK := true
	for _, twin := range []struct{ name, dir string }{{"declared", declared}, {"undeclared", undeclared}} {
		for _, control := range []string{callerReaderControl, callerLookupControl, callerNarrowingControl} {
			if !t.Run(twin.name+"/"+control, func(t *testing.T) {
				callerRunNamed(t, twin.dir, "./internal/restfront", control)
			}) {
				fixturesOK = false
			}
		}
	}
	if !fixturesOK {
		t.Fatal("фикстура настоящего фронта не прошла: вердикта гейта нет")
	}
	var once sync.Once
	var observed check.CallerIdentityReport
	// При отдельном запуске любого близнеца он сам получает полный отчёт.
	judgeLawful := func(t *testing.T) check.CallerIdentityReport {
		t.Helper()
		once.Do(func() { observed = callerJudgeTree(t, declared) })
		return observed
	}
	lawfulOK := t.Run("lawful_twin", func(t *testing.T) {
		callerRunNamed(t, declared, "./internal/authzguard", callerAdmissionTest)
		lawful := judgeLawful(t)
		if len(lawful.Findings) != 0 {
			t.Fatalf("законный близнец: %v", lawful.Findings)
		}
	})
	t.Run("undeclared_reader", func(t *testing.T) {
		callerRunNamed(t, undeclared, "./internal/authzguard", callerAdmissionTest)
		// Копии отличаются только JSON объявления. Подставляем его отсутствие
		// в тот же полный набор чтений, сохраняя проверку всех остальных RPC.
		if _, err := os.Stat(filepath.Join(undeclared, callerDispositionSource)); !os.IsNotExist(err) {
			t.Fatalf("в отрицательном близнеце ожидалось отсутствие описания: %v", err)
		}
		findings, err := judgeLawful(t).DeclarationFindingsForTest(liveCallerDeclarations())
		if err != nil {
			t.Fatal(err)
		}
		want := where + ": чтение личности без объявления " +
			"github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check -> " +
			"github.com/PRO-Robotech/corelib/grpcsrv.CertIdentityFromContext @ " +
			"(*github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam.Handler).Check"
		if len(findings) != 1 || findings[0] != want {
			t.Fatalf("ожидалась единственная находка %q, получены %q", want, findings)
		}
	})
	if !lawfulOK {
		t.Error("законный близнец не прошёл: отрицательный исход не принимается как доказательство")
	}
}

// callerActualTree — копия входного дерева; служебные данные git в опыт не идут.
func callerActualTree(t *testing.T, root string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if rel == "." || (rel == ".git" && !d.IsDir()) {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		if d.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			return os.Symlink(target, filepath.Join(dst, rel))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), data, info.Mode().Perm())
	})
	if err != nil {
		t.Fatalf("фикстура настоящего дерева: %v", err)
	}
	return dst
}

// callerInjectReader вставляет новый producer в настоящий Check по позициям
// разобранного дерева. Roster.FromContext здесь уже покрыт runtime-сужением;
// сертификатный reader — отдельное наблюдение, которому нужно своё описание.
func callerInjectReader(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, callerHandlerSource)
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, callerHandlerSource, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	const importPath = `"github.com/PRO-Robotech/corelib/grpcsrv"`
	for _, spec := range f.Imports {
		if spec.Path.Value == importPath {
			t.Fatal("фикстура изменилась: импорт сертификатного producer уже существует")
		}
	}
	importAt := -1
	for _, d := range f.Decls {
		if decl, ok := d.(*ast.GenDecl); ok && decl.Tok == token.IMPORT && decl.Lparen.IsValid() {
			importAt = fset.Position(decl.Lparen).Offset + 1
			break
		}
	}
	if importAt < 0 {
		t.Fatal("фикстура: группа импортов настоящего обработчика не найдена")
	}
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "Check" {
			continue
		}
		at := fset.Position(fn.Body.Lbrace).Offset + 1
		if importAt >= at {
			t.Fatal("фикстура: импорт не предшествует телу обработчика")
		}
		injected := append([]byte(nil), src[:importAt]...)
		injected = append(injected, []byte("\n\tcallerIdentityExperiment "+importPath)...)
		injected = append(injected, src[importAt:at]...)
		injected = append(injected, []byte("\n\t_, _ = callerIdentityExperiment.CertIdentityFromContext(ctx)")...)
		injected = append(injected, src[at:]...)
		if err := os.WriteFile(path, injected, 0o600); err != nil {
			t.Fatal(err)
		}
		return callerInjectedReaderCoordinate(t, injected)
	}
	t.Fatal("фикстура: настоящий Check не найден")
	return ""
}

// Координату даёт сам вызов в уже изменённом исходнике, независимо от
// позиций исходного обработчика, длины вставки и отчёта проверяемого гейта.
func callerInjectedReaderCoordinate(t *testing.T, src []byte) string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, callerHandlerSource, src, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var pos token.Pos
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "CertIdentityFromContext" {
			return true
		}
		pkg, ok := ast.Unparen(sel.X).(*ast.Ident)
		if ok && pkg.Name == "callerIdentityExperiment" {
			if pos.IsValid() {
				t.Fatal("фикстура: найдено несколько вставленных чтений сертификатной личности")
			}
			pos = call.Pos()
		}
		return true
	})
	if !pos.IsValid() {
		t.Fatal("фикстура: вставленное чтение сертификатной личности не найдено")
	}
	return fset.PositionFor(pos, false).String()
}

// callerDeclareReader — единственная разница близнеца: типизированное
// описание наблюдения; действующее runtime-объявление Check не меняется.
func callerDeclareReader(t *testing.T, root string) {
	t.Helper()
	declaration := callerExperimentalDisposition{
		RPC:      "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1/InternalIAMService/Check",
		Producer: "github.com/PRO-Robotech/corelib/grpcsrv.CertIdentityFromContext",
		Site:     "(*github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam.Handler).Check",
		Kind:     "observation",
		Reason:   "Экспериментальное чтение сертификатной личности в настоящем Check; результат отброшен и не сужает довод или допуск.",
	}
	data, err := json.Marshal(declaration)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, callerDispositionSource), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func callerJudgeTree(t *testing.T, root string) check.CallerIdentityReport {
	t.Helper()
	declared := liveCallerDeclarations()
	data, err := os.ReadFile(filepath.Join(root, callerDispositionSource))
	if err == nil {
		var d check.CallerReadDeclaration
		if err := json.Unmarshal(data, &d); err != nil {
			t.Fatal(err)
		}
		declared = append(declared, d)
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	ctx, cancel := callerFullTreeTestContext(t)
	defer cancel()
	// The ordinary gate uses the closed collector with indexed scope reuse.
	// Phase-by-phase observers belong to the separately selected diagnostics.
	report, err := check.CallerIdentityFindings(ctx, root, declared, nil)
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНЯЛСЯ: %v", err)
	}
	t.Logf("гейт: файлов %d, RPC %d, чтений %d, внешних листьев %d, находок %d", report.Files, report.RPCs, len(report.Reads), report.ExcludedExternalCalls, len(report.Findings))
	t.Logf("WORK %+v", report.Work)
	return report
}

func callerAssertSingleDeclarationDelta(t *testing.T, declared, undeclared string) {
	t.Helper()
	var differences []string
	err := filepath.WalkDir(declared, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(declared, path)
		if err != nil {
			return err
		}
		a, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		b, err := os.ReadFile(filepath.Join(undeclared, rel))
		if os.IsNotExist(err) && filepath.ToSlash(rel) == callerDispositionSource {
			differences = append(differences, callerDispositionSource)
			return nil
		}
		if err != nil {
			return err
		}
		if !bytes.Equal(a, b) {
			differences = append(differences, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	err = filepath.WalkDir(undeclared, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(undeclared, path)
		if err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(declared, rel)); os.IsNotExist(err) {
			differences = append(differences, "только без объявления: "+filepath.ToSlash(rel))
		} else if err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(differences) != 1 || differences[0] != callerDispositionSource {
		t.Fatalf("фикстура: ожидалась только дельта объявления, получено %v", differences)
	}
}

func callerRunNamed(t *testing.T, root, pkg, name string) {
	t.Helper()
	out, err, executed := callerRun(t, root, pkg, name)
	if !executed || err != nil {
		t.Fatalf("фикстура/близнец %s: исполнено=%t, ошибка=%v\n%s", name, executed, err, out)
	}
	t.Logf("контроль: %s, исполнено 1, отказов 0\n%s", name, out)
}

func callerRun(t *testing.T, root, pkg, name string) ([]byte, error, bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-json", "-count=1", "-timeout=4m", pkg, "-run", "^"+name+"$")
	cmd.Dir = root
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: срок %s: %v\n%s", name, ctx.Err(), out)
	}
	executed := false
	started := map[string]int{}
	passed := map[string]int{}
	s := bufio.NewScanner(bytes.NewReader(out))
	for s.Scan() {
		var event struct{ Action, Test, Package string }
		if json.Unmarshal(s.Bytes(), &event) != nil {
			continue
		}
		if event.Action == "run" && strings.HasSuffix(event.Package, strings.TrimPrefix(pkg, ".")) {
			started[event.Test]++
		}
		if event.Action == "pass" && strings.HasSuffix(event.Package, strings.TrimPrefix(pkg, ".")) {
			passed[event.Test]++
			if event.Test == name {
				executed = true
			}
		}
		if event.Action == "fail" && event.Test == name {
			executed = true
		}
	}
	if s.Err() != nil {
		t.Fatalf("чтение исхода: %v", s.Err())
	}
	// Успех родителя сам по себе не доказывает, что все подслучаи были
	// запущены: ранний return мог бы оставить зелёный неполный контроль.
	var children []string
	switch name {
	case callerReaderControl:
		children = []string{"https_front_verified_hop", "direct_grpc_verified_edge_twin", "outsider_http_forbidden_without_downstream"}
	case callerLookupControl:
		children = []string{"https_front_forbidden_without_downstream", "direct_grpc_verified_edge_twin", "outsider_http_forbidden_without_downstream"}
	case callerNarrowingControl:
		children = []string{
			"плоскость_данных_registry_о_чужом_типе",
			"лист_вне_перечня",
			"плоскость_данных_registry_о_своём_типе",
			"близнец:_край_о_том_же_чужом_объекте",
		}
	}
	completed := 0
	for _, child := range children {
		path := name + "/" + child
		if passed[path] != 1 || name == callerNarrowingControl && started[path] != 1 {
			err = fmt.Errorf("контроль %s: подслучай %s, запусков %d, успехов %d, ожидалось по одному. Исход процесса: %v",
				name, child, started[path], passed[path], err)
		} else {
			completed++
		}
	}
	if len(children) > 0 {
		t.Logf("контроль %s: успешных обязательных подслучаев %d из %d", name, completed, len(children))
	}
	return out, err, executed
}

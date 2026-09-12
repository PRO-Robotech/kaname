// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_reseed_wiring_test.go — КАК досев дотягивается до единственного
// писателя проекции роли, и откуда его самого зовут.
//
// Порт с монорепо (`internal/repohygiene/roleverbreseedwiring_test.go`, снят
// вынесением службы — `kacho#2597`). Дословно: весь предикат обеих осей.
// Изменилось: пакет (`repohygiene` → `check_test`), путь каталога досева
// (`services/iam/internal/apps/kaname/seed` → `internal/apps/kaname/seed` —
// в kaname код службы лежит от корня), обход (`repoRoot(t)` →
// `platformtree.RequireCorpus(t)`). Писатель проекции (`RoleVerbTable`,
// `RoleVerbWritesIn`) переиспользован из уже перенесённого соседнего
// семейства `roleverbsolewriter` (`role_verb_projection_sole_writer.go`) — не
// копия, тот же предикат. `bootCompositionRoot`/`roleVerbReseedMarker` —
// из `role_verb_reseed_boot_lane_test.go` (то же семейство приёмки,
// тот же пакет `check_test`) — второе объявление здесь заводить нельзя.
//
// # Почему этого не хватало (дословно из монорепо)
//
// Приёмка `role-verb-projection-sole-writer.md` (§6) объявляет требование
// «досев зовёт писателя через порт, а не своим SQL» СЛЕДСТВИЕМ двух других:
// писатель один и лежит в `repo/`. Следствие неполно: писателя можно свести
// в ОДИН, положить в `repo/` — и всё равно дотянуться до него из use-case
// ПРЯМЫМ ИМПОРТОМ пакета-адаптера. Гейт единственности при этом зелен.
//
// Здесь закрываются ровно две оси:
//
//  1. слой use-case не импортирует пакет, в котором стоит единственный писатель;
//  2. ссылка на пересчёт проекции в ДЕРЕВЕ ровно одна, и стоит она в
//     композиционном корне.
package check_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// useCaseLayerMarker — признак слоя use-case в пути файла.
const useCaseLayerMarker = "/internal/apps/"

// roleVerbSeedPackageDir — каталог досева, чьи вызовы считает ось 2.
const roleVerbSeedPackageDir = "internal/apps/kaname/seed"

// skipPath — пути вне области обхода: VCS, синканная AI-оснастка, документация,
// вендоренное и build-артефакты.
func skipPath(rel string) bool {
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".git", ".claude", "docs", "node_modules", "vendor", "bin":
			return true
		}
	}
	return false
}

// kanameModulePath — путь импорта модуля kaname. Один модуль — одна константа,
// в отличие от монорепо, где `importOfTreeRel` различала iam-префикс и
// платформенный.
const kanameModulePath = "github.com/PRO-Robotech/kaname"

// importOfTreeRel — путь импорта пакета по его пути в дереве.
func importOfTreeRel(rel string) string {
	return kanameModulePath + "/" + rel
}

// treeGoFiles — непроверочные файлы Go по ИНДЕКСУ git.
func treeGoFiles(t *testing.T, root string) []string {
	t.Helper()
	out, err := gitenv.Command(root, "ls-files", "-z", "--", "*.go").Output()
	if err != nil {
		t.Fatalf("git ls-files: %v — состав дерева не установлен, и «ноль находок» "+
			"здесь означало бы «ноль прочитанного»", err)
	}
	var files []string
	for _, rel := range strings.Split(strings.TrimRight(string(out), "\x00"), "\x00") {
		if rel == "" || skipPath(rel) || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		files = append(files, rel)
	}
	return files
}

// importedPaths отдаёт пути импорта файла Go.
func importedPaths(filename, src string) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(file.Imports))
	for _, imp := range file.Imports {
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// useCaseFileImports — файл слоя use-case и его пути импорта.
type useCaseFileImports struct {
	Rel     string
	Imports []string
}

// roleVerbWriterPackageOf — путь импорта пакета, если файл ПИШЕТ проекцию.
func roleVerbWriterPackageOf(rel, src string) (string, bool, error) {
	if !strings.Contains(src, check.RoleVerbTable) {
		return "", false, nil
	}
	writes, _, err := check.RoleVerbWritesIn(rel, src)
	if err != nil {
		return "", false, err
	}
	if len(writes) == 0 {
		return "", false, nil
	}
	return importOfTreeRel(filepath.ToSlash(filepath.Dir(rel))), true, nil
}

// isUseCaseLayer — лежит ли файл в слое use-case.
func isUseCaseLayer(rel string) bool {
	return strings.Contains("/"+rel, useCaseLayerMarker)
}

// useCaseWriterImportFindings — файлы use-case, импортирующие пакет писателя.
func useCaseWriterImportFindings(apps []useCaseFileImports, writerPkgs map[string]string) []string {
	var findings []string
	for _, a := range apps {
		for _, imp := range a.Imports {
			if src, isWriter := writerPkgs[imp]; isWriter {
				findings = append(findings, a.Rel+" импортирует "+imp+" (писатель — "+src+")")
			}
		}
	}
	sort.Strings(findings)
	return findings
}

// TestRoleVerbWriterIsReachedFromUseCaseThroughThePort — слой use-case не
// импортирует пакет единственного писателя проекции роли.
func TestRoleVerbWriterIsReachedFromUseCaseThroughThePort(t *testing.T) {
	root, _ := platformtree.RequireCorpus(t)
	files := treeGoFiles(t, root)

	var (
		filesRead    int
		writerPkgs   = map[string]string{}
		useCaseFiles int
		apps         []useCaseFileImports
	)

	for _, rel := range files {
		b, readErr := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- путь из индекса своего дерева
		if readErr != nil {
			t.Fatalf("чтение %s: %v", rel, readErr)
		}
		filesRead++
		body := string(b)
		pkg, isWriter, perr := roleVerbWriterPackageOf(rel, body)
		if perr != nil {
			t.Fatalf("разбор %s: %v — файл индекса не разобран, и его молчание "+
				"ничего не значит", rel, perr)
		}
		if isWriter {
			writerPkgs[pkg] = rel
		}
		if isUseCaseLayer(rel) {
			imps, ierr := importedPaths(rel, body)
			if ierr != nil {
				t.Fatalf("разбор импортов %s: %v", rel, ierr)
			}
			useCaseFiles++
			apps = append(apps, useCaseFileImports{Rel: rel, Imports: imps})
		}
	}

	pkgList := make([]string, 0, len(writerPkgs))
	for p := range writerPkgs {
		pkgList = append(pkgList, p)
	}
	sort.Strings(pkgList)

	t.Logf("осмотрено непроверочных файлов Go: %d; из них в слое use-case (%s): %d; "+
		"пакетов-писателей проекции роли: %d %v",
		filesRead, useCaseLayerMarker, useCaseFiles, len(pkgList), pkgList)

	if filesRead == 0 {
		t.Fatal("осмотрено ноль файлов — гейт не читал дерева, и его молчание ничего не значит")
	}
	if useCaseFiles == 0 {
		t.Fatalf("в дереве нет ни одного непроверочного файла слоя %s — предпосылка "+
			"гейта неверна: либо слой переименован, либо обход его не видит",
			useCaseLayerMarker)
	}
	if len(pkgList) == 0 {
		t.Fatalf("ни один непроверочный файл не пишет %s — предмета у гейта нет: "+
			"либо таблица переименована, либо писателя не осталось вовсе", check.RoleVerbTable)
	}

	for _, f := range useCaseWriterImportFindings(apps, writerPkgs) {
		t.Errorf("%s\n"+
			"Слой use-case дотягивается до писателя проекции роли ПРЯМЫМ ИМПОРТОМ "+
			"пакета-адаптера. Писателя зовут через порт: `kanamerepo.Writer` + "+
			"`shared.DoWithWriteTxVoid`, метод `RolesW().ReplaceRoleVerbs`. Иначе "+
			"use-case решает не только КОГДА и ДЛЯ КАКИХ ролей пересчитывать, но и "+
			"КАК писать, — а форму строки, отображение отказов и транзакционность "+
			"держит слой repo/. Гейт единственности этого не видит: писатель при "+
			"таком импорте по-прежнему один и по-прежнему в repo/.", f)
	}
}

// exportedRoleVerbSeedEntryPoints — экспортированные функции пакета досева,
// чьё имя несёт `RoleVerb`.
func exportedRoleVerbSeedEntryPoints(t *testing.T, root string, files []string) (map[string]bool, int) {
	t.Helper()
	entries := map[string]bool{}
	read := 0
	for _, rel := range files {
		if filepath.ToSlash(filepath.Dir(rel)) != roleVerbSeedPackageDir {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- путь из индекса своего дерева
		if err != nil {
			t.Fatalf("чтение %s: %v", rel, err)
		}
		read++
		names, perr := exportedRoleVerbEntryPointsIn(rel, string(b))
		if perr != nil {
			t.Fatalf("разбор %s: %v", rel, perr)
		}
		for _, n := range names {
			entries[n] = true
		}
	}
	return entries, read
}

// exportedRoleVerbEntryPointsIn — экспортированные функции файла, чьё имя
// несёт `RoleVerb`.
func exportedRoleVerbEntryPointsIn(filename, src string) ([]string, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil {
			continue
		}
		if fn.Name.IsExported() && strings.Contains(fn.Name.Name, roleVerbReseedMarker) {
			out = append(out, fn.Name.Name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// isBootCompositionRoot — ЕДИНСТВЕННОЕ место дерева, где ссылка на пересчёт
// законна. Определение «корня» берётся у соседнего гейта (`bootCompositionRoot`,
// объявлен в `role_verb_reseed_boot_lane_test.go`), а не выписывается второй раз.
func isBootCompositionRoot(rel string) bool {
	return filepath.ToSlash(rel) == bootCompositionRoot
}

// roleVerbReseedRefsIn отдаёт ССЫЛКИ на точки входа пересчёта — в ЛЮБОЙ
// законной форме записи.
func roleVerbReseedRefsIn(filename, src string, entries map[string]bool) ([]string, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filename, src, 0)
	if err != nil {
		return nil, err
	}
	type span struct {
		from, to token.Pos
		name     string
	}
	var spans []span
	declNames := make(map[*ast.Ident]bool)
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		declNames[fn.Name] = true
		if fn.Body != nil {
			spans = append(spans, span{from: fn.Body.Pos(), to: fn.Body.End(), name: fn.Name.Name})
		}
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		ident, ok := n.(*ast.Ident)
		if !ok || !entries[ident.Name] || declNames[ident] {
			return true
		}
		owner := "<пакетный уровень>"
		for _, s := range spans {
			if ident.Pos() >= s.from && ident.End() <= s.to {
				owner = s.name
				break
			}
		}
		out = append(out, filename+"::"+owner+" → "+ident.Name)
		return true
	})
	return out, nil
}

// TestRoleVerbReseedHasOneReferenceInTheTreeAndItIsTheBootRoot — пересчёт
// проекции роли за старт происходит РОВНО ОДИН раз, и зовут его ИЗ
// КОМПОЗИЦИОННОГО КОРНЯ, где у его отказа есть собственная полоса.
func TestRoleVerbReseedHasOneReferenceInTheTreeAndItIsTheBootRoot(t *testing.T) {
	root, _ := platformtree.RequireCorpus(t)
	files := treeGoFiles(t, root)

	entries, seedFilesRead := exportedRoleVerbSeedEntryPoints(t, root, files)
	names := make([]string, 0, len(entries))
	for n := range entries {
		names = append(names, n)
	}
	sort.Strings(names)

	var atRoot, elsewhere []string
	filesRead, filesParsed := 0, 0
	for _, rel := range files {
		b, err := os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- путь из индекса своего дерева
		if err != nil {
			t.Fatalf("чтение %s: %v", rel, err)
		}
		filesRead++
		src := string(b)
		if !strings.Contains(src, roleVerbReseedMarker) {
			continue
		}
		filesParsed++
		refs, rerr := roleVerbReseedRefsIn(rel, src, entries)
		if rerr != nil {
			t.Fatalf("разбор %s: %v", rel, rerr)
		}
		if isBootCompositionRoot(rel) {
			atRoot = append(atRoot, refs...)
		} else {
			elsewhere = append(elsewhere, refs...)
		}
	}
	sort.Strings(atRoot)
	sort.Strings(elsewhere)

	t.Logf("осмотрено непроверочных файлов Go дерева: %d; из них разобрано (несут `%s`): %d; "+
		"файлов пакета досева (%s) прочитано: %d; точек входа пересчёта: %d %v; "+
		"ссылок в композиционном корне (%s): %d; ссылок вне корня: %d",
		filesRead, roleVerbReseedMarker, filesParsed, roleVerbSeedPackageDir, seedFilesRead,
		len(names), names, bootCompositionRoot, len(atRoot), len(elsewhere))

	if filesRead == 0 {
		t.Fatalf("обход дерева не прочитал ни одного непроверочного файла Go — " +
			"предпосылка гейта неверна, и «ноль находок» здесь означало бы «ноль прочитанного»")
	}
	if seedFilesRead == 0 {
		t.Fatalf("в каталоге %s не прочитано ни одного непроверочного файла — "+
			"предпосылка гейта неверна: каталог переехал либо обход его не видит",
			roleVerbSeedPackageDir)
	}
	if len(names) == 0 {
		t.Fatalf("в пакете досева нет ни одной экспортированной функции с `%s` в имени — "+
			"предмета у гейта нет: пересчёт переименован либо снят", roleVerbReseedMarker)
	}
	if filesParsed == 0 {
		t.Fatalf("ни один файл дерева не несёт `%s` — предмет исчез из дерева, "+
			"и молчание гейта о нём ничего не говорит", roleVerbReseedMarker)
	}

	for _, f := range elsewhere {
		t.Errorf("%s\n"+
			"Пересчёт проекции роли зовётся ВНЕ композиционного корня. Своя полоса "+
			"отказа у него есть только там (%s) — значит здесь его отказ приезжает "+
			"вызывающему обёрнутым в ЧУЖУЮ ошибку и печатается уровнем чужой полосы, "+
			"а на старте пересчёт идёт БОЛЬШЕ ОДНОГО РАЗА: вдвое больше транзакций и "+
			"перепись, затирающая первую.", f, bootCompositionRoot)
	}
	switch len(atRoot) {
	case 1:
	case 0:
		t.Errorf("в композиционном корне (%s) ссылок на пересчёт проекции роли НЕТ.\n"+
			"Тогда на старте проекция не пересеивается вовсе: роль с одними селекторами "+
			"адресует объект и не разрешает на нём ничего, а вердикт по её выдаче "+
			"отказывает МОЛЧА.", bootCompositionRoot)
	default:
		t.Errorf("в композиционном корне (%s) ссылок на пересчёт проекции роли %d, "+
			"а обязана быть одна: %v\n"+
			"Пересчёт за старт идёт больше одного раза; перепись второго прогона "+
			"затирает первую, и оба прогона по отдельности выглядят исправно.",
			bootCompositionRoot, len(atRoot), atRoot)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_module_test.go — служба несёт СВОЙ модуль Go, и он самодостаточен.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Служба выносится отдельным репозиторием. Пока у неё нет собственного go.mod,
// «отдельный репозиторий» невыразим по построению: единственный модуль дерева
// объявлен в корне монорепо, поэтому собрать службу можно ТОЛЬКО имея это дерево
// на диске. Отсутствие модуля — не неудобство, а отсутствие предмета: продукта,
// который можно склонировать и собрать, не существует.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — три условия, и все три вместе
//
//  1. go.mod у службы ЕСТЬ и объявляет путь модуля;
//  2. в нём НЕТ директивы замены на модуль PRO-Robotech. Замена вида `=> ../..`
//     резолвится только там, где дерево монорепо лежит рядом, — то есть ровно в
//     том окружении, независимость от которого и есть предмет. Запрет выведен из
//     реального инцидента (`.claude/rules/polyrepo.md`, §«replace ЗАПРЕЩЁН»):
//     единичный клон не собирался, и образ ствола не выпускался;
//  3. КАЖДЫЙ импорт `github.com/PRO-Robotech/...`, найденный в коде службы,
//     принадлежит либо её собственному модулю, либо модулю, ОБЪЯВЛЕННОМУ в
//     require. Импорт вне обоих множеств означает: сборка вне дерева монорепо
//     отказывает, а внутри — проходит, и расхождение видно только на чужой
//     машине.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОИСК ПО ОБРАЗЦУ
//
// Путь `github.com/PRO-Robotech/kacho/...` встречается в этом дереве не только
// импортом: он стоит внутри СТРОКОВЫХ ЛИТЕРАЛОВ синтетических фикстур соседних
// гейтов и в комментариях. Замер по стволу: файлов вне службы, где такой путь
// найден поиском по тексту, — шесть, и НИ ОДИН из них импортом не является.
// Проверка по подстроке считала бы объяснение предметом. Здесь судится узел
// импорта, полученный разбором (`parser.ImportsOnly`), а не текст.
package supplyhygiene

import (
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"
)

// serviceRoot — корень службы относительно каталога этого пакета
// (internal/supplyhygiene → internal → корень службы).
const serviceRoot = "../.."

// foreignImportPrefix — общий префикс модулей платформы, чьё присутствие в
// импортах и есть предмет проверки.
const foreignImportPrefix = "github.com/PRO-Robotech/"

// skippedDirs — каталоги, которые обходу не принадлежат: произведённое чужими
// инструментами, а не исходники службы.
var skippedDirs = map[string]struct{}{
	".git":         {},
	"node_modules": {},
	"build":        {},
	".docusaurus":  {},
}

// uncoveredImport — одно попадание: где стоит импорт и какой именно.
type uncoveredImport struct {
	file   string
	line   int
	path   string
	reason string
}

// moduleCensus — объём осмотренного одним обходом. Печатается всегда: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
type moduleCensus struct {
	modulePath      string
	declared        []string
	filesParsed     int
	importsSeen     int
	platformImports int
	ownImports      int
	externalModules []string
}

// scanServiceModule — весь разбор одним местом, над ПРОИЗВОЛЬНЫМ составом. Обход
// вынесен из теста именно затем, чтобы способность гейта упасть проверялась
// подачей настоящего входа, а не чтением.
//
// СОСТАВ ПРИНОСИТ ВЫЗЫВАЮЩИЙ, и в этом весь смысл параметра. У настоящего дерева
// службы авторитет — ИНДЕКС git (`treecorpus.NewTree`): под корнем лежат
// каталоги, которых в репозитории нет (рабочие копии агентов, отчёты прогонов,
// сборочные и распакованные каталоги), и обход диска сделал бы вердикт свойством
// чужого рабочего каталога, а не коммита — в обе стороны: красное на файле,
// которого в репозитории нет, и молчание в свежем клоне там, где сказать обязан.
// У синтетического корня инъекции индекса нет by construction, и обход диска там
// не откат, а единственный возможный авторитет (`treecorpus.SyntheticTree`).
// Поставщики РАЗВЕДЕНЫ по назначению и выбираются явно: молчаливый откат
// «нет git — иду по диску» вернул бы ровно тот дефект, ради которого разведение
// и сделано, и вернул бы его невидимо.
func scanServiceModule(tree *treecorpus.Tree) (moduleCensus, []uncoveredImport, error) {
	var census moduleCensus

	root := tree.Root()
	modPath := filepath.Join(root, "go.mod")
	raw, err := os.ReadFile(modPath)
	if err != nil {
		return census, nil, err
	}
	mod, err := modfile.Parse(modPath, raw, nil)
	if err != nil {
		return census, nil, err
	}
	if mod.Module == nil || mod.Module.Mod.Path == "" {
		return census, nil, errNoModulePath
	}
	census.modulePath = mod.Module.Mod.Path

	var findings []uncoveredImport

	for _, rep := range mod.Replace {
		if strings.HasPrefix(rep.Old.Path, foreignImportPrefix) {
			findings = append(findings, uncoveredImport{
				file:   filepath.ToSlash(modPath),
				line:   rep.Syntax.Start.Line,
				path:   rep.Old.Path,
				reason: "заменён директивой replace на " + rep.New.Path + ": сборка снова требует дерево монорепо на диске",
			})
		}
	}

	for _, req := range mod.Require {
		if strings.HasPrefix(req.Mod.Path, foreignImportPrefix) {
			census.declared = append(census.declared, req.Mod.Path)
		}
	}
	sort.Strings(census.declared)

	covers := func(importPath string) bool {
		if importPath == census.modulePath || strings.HasPrefix(importPath, census.modulePath+"/") {
			return true
		}
		for _, m := range census.declared {
			if importPath == m || strings.HasPrefix(importPath, m+"/") {
				return true
			}
		}
		return false
	}

	externals := map[string]struct{}{}
	fset := token.NewFileSet()

	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") || inSkippedDir(rel) {
			continue
		}
		path := filepath.Join(root, rel)

		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return census, findings, parseErr
		}
		census.filesParsed++

		for _, spec := range file.Imports {
			census.importsSeen++

			value, unquoteErr := strconv.Unquote(spec.Path.Value)
			if unquoteErr != nil || !strings.HasPrefix(value, foreignImportPrefix) {
				continue
			}
			census.platformImports++

			if value == census.modulePath || strings.HasPrefix(value, census.modulePath+"/") {
				census.ownImports++
				continue
			}

			if segments := strings.SplitN(value, "/", 4); len(segments) >= 3 {
				externals[strings.Join(segments[:3], "/")] = struct{}{}
			}
			if covers(value) {
				continue
			}

			findings = append(findings, uncoveredImport{
				file:   filepath.ToSlash(path),
				line:   fset.Position(spec.Pos()).Line,
				path:   value,
				reason: "не принадлежит собственному модулю и не покрыт ни одним require",
			})
		}
	}

	for m := range externals {
		census.externalModules = append(census.externalModules, m)
	}
	sort.Strings(census.externalModules)

	return census, findings, nil
}

// inSkippedDir — лежит ли файл под каталогом, обходу не принадлежащим. Состав
// отдаёт ПУТИ, а не записи каталога, поэтому отсечение идёт по сегментам пути, а
// не пропуском поддерева; последний сегмент — имя файла и каталогом не является.
func inSkippedDir(rel string) bool {
	segments := strings.Split(filepath.ToSlash(rel), "/")
	for _, seg := range segments[:len(segments)-1] {
		if _, skip := skippedDirs[seg]; skip {
			return true
		}
	}
	return false
}

// errNoModulePath — go.mod есть, но пути модуля не объявляет.
var errNoModulePath = errors.New("go.mod не объявляет путь модуля")

func TestServiceCarriesItsOwnSelfSufficientModule(t *testing.T) {
	tree, treeErr := treecorpus.NewTree(serviceRoot)
	require.NoErrorf(t, treeErr,
		"состав дерева службы (%s) не прочитан у индекса — вердикт беспредметен: "+
			"обход диска вместо индекса читал бы каталоги, которых в репозитории нет",
		serviceRoot)

	census, findings, err := scanServiceModule(tree)
	require.NoErrorf(t, err,
		"у службы нет пригодного собственного go.mod (%s): собрать её вне дерева монорепо невозможно by construction",
		filepath.Join(serviceRoot, "go.mod"))

	t.Logf(
		"перепись: модуль службы %q · файлов Go разобрано %d · импортов осмотрено %d · из них платформенных %d "+
			"(своих %d, внешних %d) · внешних модулей по путям импорта %v · объявлено require платформы %v · находок %d",
		census.modulePath, census.filesParsed, census.importsSeen, census.platformImports,
		census.ownImports, census.platformImports-census.ownImports,
		census.externalModules, census.declared, len(findings),
	)

	// Пустой обход — находка, а не идеал.
	require.NotZero(t, census.filesParsed, "обход пуст: файлов Go не разобрано ни одного — вердикт беспредметен")
	require.NotZero(t, census.importsSeen, "обход пуст: импортов не осмотрено ни одного — вердикт беспредметен")
	require.NotZero(t, census.platformImports, "обход пуст: платформенных импортов не найдено ни одного — вердикт беспредметен")

	for _, f := range findings {
		t.Errorf(
			"%s:%d — %q %s: сборка службы вне дерева монорепо отказывает, внутри проходит. "+
				"Законная форма — require по версии; см. .claude/rules/polyrepo.md §«replace ЗАПРЕЩЁН»",
			f.file, f.line, f.path, f.reason,
		)
	}
}

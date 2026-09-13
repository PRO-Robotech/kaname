// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mirror_divergence_wiring.go — у ЧТЕНИЯ РАЗНОСТИ зеркала и каталога обязан
// быть ВЫЗЫВАЮЩИЙ в композиционном корне (kacho#1828).
//
// # Предмет
//
// Разность зеркала и живого каталога — величина, от которой зависит решение
// владельца об отзыве, а отзыв ОТНИМАЕТ доступ. Читатель этой разности в дереве
// есть и хорошо построен; до этого гейта его не спрашивал НИ ОДИН путь
// исполнения — только интеграционные пробы. Механизм без вызывающего от
// отсутствующего неотличим: на поднятом стенде величина не производится, и
// «разности нет» читается ровно так же, как «никто не мерил».
//
// # Почему гейт судит УЗЕЛ ВЫЗОВА, а не слово
//
// Имя читателя встречается в этом дереве и прозой — в объяснениях, включая
// объяснение самого гейта. Проверка по подстроке краснела бы на собственном
// комментарии, а зеленела бы на закомментированном вызове.
//
// # Какие формы записи вызова гейт знает
//
// Обе законные: `resource_mirror.Divergence(…)` и вызов через АЛИАС импорта
// (`mirror "…/resource_mirror"` → `mirror.Divergence(…)`). Локальное имя пакета
// берётся из блока импортов каждого файла, а не предполагается равным
// последнему сегменту пути. Форма, о которой распознаватель не знает, — не
// редкость, а слепая зона: всё, записанное в ней, оказывается вне наблюдения.
//
// # Чем этот гейт НЕ является
//
// Он не утверждает, что разность ПУСТА, и не вправе: непустая разность на
// стенде арендатора — предмет решения владельца, а не находка проверки. Предмет
// здесь один — ВЫЗЫВАЮЩИЙ существует.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// MirrorDivergencePkgSuffix — хвост пути пакета-читателя разности.
const MirrorDivergencePkgSuffix = "/repo/kaname/pg/resource_mirror"

// MirrorDivergenceFunc — имя читателя, чей вызывающий здесь стережётся.
const MirrorDivergenceFunc = "Divergence"

// MirrorWiringScan — что увидел обход композиционного корня.
type MirrorWiringScan struct {
	// Files — не-тестовых файлов Go разобрано.
	Files int
	// Calls — узлов вызова читателя найдено.
	Calls int
	// CallSites — файлы с вызовом, по возрастанию.
	CallSites []string
}

// ScanMirrorDivergenceWiring обходит названный каталог и считает вызовы
// читателя разности.
//
// Вынесен отдельно от гейта затем, чтобы инъекция гоняла ТУ ЖЕ функцию на
// синтетическом дереве: проверка, доказанная на своей копии разбора, доказывает
// свойство копии.
func ScanMirrorDivergenceWiring(root string) (MirrorWiringScan, error) {
	var out MirrorWiringScan
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || strings.HasPrefix(name, ".") {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// Неразбираемый файл — не «нет вызова»: он вне наблюдения, и
			// молчание о нём сказано ни о чём. Обход продолжается, но файл в
			// перепись не идёт, поэтому падение переписи его и поймает.
			return nil
		}
		out.Files++

		local, imported := mirrorLocalName(file)
		if !imported {
			return nil
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		seen := false
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != MirrorDivergenceFunc {
				return true
			}
			ident, ok := sel.X.(*ast.Ident)
			if !ok || ident.Name != local {
				return true
			}
			out.Calls++
			seen = true
			return true
		})
		if seen {
			out.CallSites = append(out.CallSites, filepath.ToSlash(rel))
		}
		return nil
	})
	return out, err
}

// mirrorLocalName — под каким именем файл знает пакет-читатель.
//
// Алиас имеет приоритет над последним сегментом пути: предположить второе
// значило бы ослепнуть на форме, которая в Go законна ровно так же.
func mirrorLocalName(file *ast.File) (string, bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || !strings.HasSuffix(path, MirrorDivergencePkgSuffix) {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				// Пустой импорт вызова не даёт, точечный — даёт БЕЗ
				// квалификатора, и узел у него другой. Ни одна форма в дереве
				// не наблюдалась; объявляем их вне охвата вслух, а не молча.
				return "", false
			}
			return imp.Name.Name, true
		}
		return path[strings.LastIndex(path, "/")+1:], true
	}
	return "", false
}

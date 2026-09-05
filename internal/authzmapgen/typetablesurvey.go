// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmapgen

// typetablesurvey.go — ПЕРЕПИСЬ таблиц типов пакета продукта: сколько их и
// сколько из них порождается (задача #1092).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТО ИЗМЕРЯЕТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ
//
// «Порождена одна таблица из двух» — утверждение о ДЕРЕВЕ в настоящем времени.
// Стоя прозой в шапке продукта, оно переживёт свой предмет молча: вторая
// таблица будет выведена (#1930), а шапка останется говорить, что не будет.
// Перепись даёт число производителем, и объявленный остаток самоистекает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ТАБЛИЦЕЙ ТИПОВ — СОСТАВ, А НЕ ИМЯ
//
// Package-level карта, у которой ВСЕ ключи либо ВСЕ значения суть типы модели,
// объявленные манифестами. Опознание по составу, а не по имени, потому что имя
// `objectTypes` стоит и в комментариях, объясняющих сам остаток: гейт, судящий
// подстроку, краснел бы на собственном объяснении и продолжал бы находить имя
// после того, как таблица уедет в порождённый файл.
//
// Соседние карты пакета этим отсекаются by construction, а не перечнем
// исключений: их ключи и значения — дотированные `модуль.ресурс` и проза, а
// имя типа модели точки не содержит НИКОГДА.
//
// ─────────────────────────────────────────────────────────────────────────────
// СЛЕПАЯ ЗОНА НАЗВАНА
//
// Карта над ЧАСТЬЮ типов (подмножеством) таблицей типов здесь не считается:
// предикат требует, чтобы типами были ВСЕ элементы одной из сторон, и множество
// при этом непусто. Требовать равенства ПОЛНОМУ набору было бы строже, но тогда
// перепись теряла бы таблицу в тот же миг, когда манифест объявляет новый тип, —
// то есть краснела бы на верном коде. Выбран предикат «все элементы — типы»:
// он не пропускает таблицу, отставшую на один тип, и не требует полноты.
//
// Тестовые файлы не читаются: синтетика проб держит собственные карты типов, и
// их счёт сделал бы перепись функцией числа проб.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// TypeTableSurvey — объём осмотренного и вердикт.
//
// Печатается ВСЕГДА: «рукописных одна» неотличимо от «прочитано ноль файлов»,
// если объём не назван.
type TypeTableSurvey struct {
	// FilesRead — не-тестовых файлов Go прочитано.
	FilesRead int
	// MapsRead — package-level карт прочитано, включая не-типовые.
	MapsRead int
	// Generated — таблиц типов в ПОРОЖДЁННОМ файле.
	Generated int
	// HandWritten — таблиц типов вне порождённого файла.
	HandWritten int
	// HandWrittenNames — их имена, отсортированно: находка обязана называть
	// предмет, иначе читатель идёт искать его сам.
	HandWrittenNames []string
}

// ObjectTypeSet — множество типов модели, которые производитель эмитит.
//
// Отдаётся ОТСЮДА, а не собирается вызывающим: второй обход тех же записей
// разошёлся бы с первым на первом же новом виде записи.
func (t Tables) ObjectTypeSet() map[string]struct{} {
	set := make(map[string]struct{}, len(t.Entries))
	for _, e := range t.Entries {
		if e.ObjectType != "" {
			set[e.ObjectType] = struct{}{}
		}
	}
	return set
}

// SurveyTypeTables обходит каталог пакета продукта и считает таблицы типов.
//
// Каталог подаётся ПУТЁМ, а не содержимым: инъекция подаёт синтетический тем же
// путём, каким гейт подаёт настоящий, поэтому доказательство способности упасть
// относится к ЭТОЙ функции, а не к её копии.
//
// Пустой набор типов — ОТКАЗ, а не «таблиц ноль»: предикат «все элементы суть
// типы» на пустом наборе не выполняется никогда, и перепись молча объявила бы
// пакет свободным от таблиц.
func SurveyTypeTables(dir string, types map[string]struct{}) (TypeTableSurvey, error) {
	if len(types) == 0 {
		return TypeTableSurvey{}, fmt.Errorf(
			"набор типов пуст: предикат «все элементы стороны суть типы» на нём не " +
				"выполняется ни для одной карты, и перепись объявила бы пакет свободным " +
				"от таблиц типов, ничего не прочитав")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return TypeTableSurvey{}, fmt.Errorf("читаю каталог продукта %s: %w", dir, err)
	}

	generatedBase := filepath.Base(GeneratedRelPath)
	var survey TypeTableSurvey
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- имя пришло из обхода ЭТОГО дерева, подставить посторонний файл извне нечем
		if err != nil {
			return TypeTableSurvey{}, fmt.Errorf("читаю %s: %w", name, err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			return TypeTableSurvey{}, fmt.Errorf("разбираю %s: %w", name, err)
		}
		survey.FilesRead++

		for _, decl := range f.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, val := range vs.Values {
					lit, ok := val.(*ast.CompositeLit)
					if !ok {
						continue
					}
					if _, isMap := lit.Type.(*ast.MapType); !isMap {
						continue
					}
					survey.MapsRead++
					if !mapSideIsAllTypes(lit, types) {
						continue
					}
					if name == generatedBase {
						survey.Generated++
						continue
					}
					survey.HandWritten++
					if i < len(vs.Names) {
						survey.HandWrittenNames = append(survey.HandWrittenNames, vs.Names[i].Name)
					}
				}
			}
		}
	}
	sort.Strings(survey.HandWrittenNames)
	return survey, nil
}

// mapSideIsAllTypes — правда, когда ВСЕ ключи либо ВСЕ значения карты суть типы
// модели, и сторона при этом непуста.
//
// Стороны разные, потому что таблицы разные: одна держит тип КЛЮЧОМ (набор
// отношений типа), другая — ЗНАЧЕНИЕМ (точечное имя → тип). Спрашивать только
// одну сторону значило бы не увидеть половину предмета.
func mapSideIsAllTypes(lit *ast.CompositeLit, types map[string]struct{}) bool {
	keysAll, valsAll := true, true
	keys, vals := 0, 0
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			return false
		}
		if s, ok := stringLit(kv.Key); ok {
			keys++
			if _, isType := types[s]; !isType {
				keysAll = false
			}
		} else {
			keysAll = false
		}
		if s, ok := stringLit(kv.Value); ok {
			vals++
			if _, isType := types[s]; !isType {
				valsAll = false
			}
		} else {
			valsAll = false
		}
	}
	return (keysAll && keys > 0) || (valsAll && vals > 0)
}

// stringLit — содержимое строкового литерала. Не литерал — вторым значением
// ложь: сторона, где стоит не строка, типами быть не может.
func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

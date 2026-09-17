// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// process_knob_names.go — судья ИМЁН РУЧЕК ПРОЦЕССА: ни один двоичный файл
// службы не читает переменной окружения, названной именем платформы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДИТСЯ ТО, ЧТО ЛИНКУЕТСЯ, А НЕ ТЕКСТ ДЕРЕВА
//
// Ось «ручки» переписи осей (`platform_name_axes_test.go`) держалась ТОЧНЫМ
// ЧИСЛОМ токенов вида `KACHO_…` в не-тестовых файлах, и к нулю это число не
// шло НИКОГДА: в нём стояли имена ручек СОСЕДЕЙ в тексте отказа и объяснениях
// (реестр, край), ручки ФУНДАМЕНТА (накатчик — их имя выбирает corelib), ручки
// собственных проб в ЗАХВАЧЕННЫХ отчётах (правка сфальсифицировала бы замер),
// объяснение применённого свода (ban #5) и конвенция оснастки воркспейса
// (`KACHO_HOME_<ИМЯ>` читает её же гейт). Ни одно из них не есть ручка службы.
//
// Ручка службы — то, что ЧИТАЕТ ЕЁ ПРОЦЕСС. Поэтому корпус судьи — пакеты этого
// модуля, которые линкуются в двоичные файлы (`go list -deps ./cmd/...`), а
// предмет — строковый литерал формы имени переменной окружения. Комментарий и
// проза литералом не являются и не судятся: поиск по подстроке краснел бы на
// собственном объяснении. Предложение, в котором имя чужой ручки стоит внутри
// текста отказа, формы имени не имеет — и потому близнец законный.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО СУДЬЯ НЕ СУДИТ — названо, чтобы «зелёный» не читался шире сделанного
//
//  1. ручки, которые читает ФУНДАМЕНТ внутри слинкованного пакета corelib
//     (`KACHO_MIGRATOR_DSN` у накатчика): их имя выбирает фундамент —
//     PRO-Robotech/corelib#11. Корпус — пакеты ЭТОГО модуля;
//  2. имя, собранное из частей во время исполнения (`prefix + name`): судится
//     каждая часть-литерал формы имени, а не результат склейки. Часть без
//     подчёркивания в конце формы имени не имеет и не судится — это граница,
//     а не свойство;
//  3. пакеты вне двоичных файлов: инструменты проверок и гейты читают ручки
//     оснастки, и их имя выбирает оснастка.
package supplyhygiene

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// envNameShape — форма имени переменной окружения: заглавные латинские буквы,
// цифры и подчёркивания, первой — буква; хвостовое подчёркивание допускается,
// потому что так записывают ПРИСТАВКУ, из которой имя собирается при
// исполнении.
var envNameShape = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]*)*_?$`)

// ProcessKnobCensus — объём осмотренного.
type ProcessKnobCensus struct {
	// Files — файлов Go разобрано (не-тестовых, из пакетов двоичных файлов).
	Files int
	// Literals — строковых литералов осмотрено.
	Literals int
	// EnvShaped — из них формы имени переменной окружения.
	EnvShaped int
	// Unparsed — файлы, которых разбор не прочёл; о них судит сборка, но
	// пропуск обязан быть виден.
	Unparsed []string
}

// ProcessKnobFinding — одна ручка процесса, названная именем платформы.
type ProcessKnobFinding struct {
	File string
	Line int
	Name string
}

func (f ProcessKnobFinding) String() string {
	return fmt.Sprintf("%s:%d: процесс службы читает ручку %q, названную именем платформы: "+
		"оператор, поставивший службу одну, задаёт её настройку под именем продукта, которого "+
		"не ставил; ручки службы выводятся приставкой `config.EnvPrefix`", f.File, f.Line, f.Name)
}

// JudgeProcessKnobNames судит литералы формы имени переменной окружения в
// поданных исходниках. sources — путь → текст файла Go; пробы (`_test.go`)
// не судятся: они называют имя как предмет своей проверки.
func JudgeProcessKnobNames(sources map[string][]byte) (ProcessKnobCensus, []ProcessKnobFinding) {
	var (
		census   ProcessKnobCensus
		findings []ProcessKnobFinding
	)
	paths := make([]string, 0, len(sources))
	for p := range sources {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	fset := token.NewFileSet()
	for _, path := range paths {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, sources[path], 0)
		if err != nil {
			census.Unparsed = append(census.Unparsed, path)
			continue
		}
		census.Files++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.Literals++
			val, uqErr := strconv.Unquote(lit.Value)
			if uqErr != nil || !envNameShape.MatchString(val) {
				return true
			}
			census.EnvShaped++
			if len(PlatformNameHits(val)) == 0 {
				return true
			}
			findings = append(findings, ProcessKnobFinding{
				File: path,
				Line: fset.Position(lit.Pos()).Line,
				Name: val,
			})
			return true
		})
	}
	return census, findings
}

// ─────────────────────────────────────────────────────────────────────────────
// ДОМЕН ДОВЕРИЯ — тот же корпус, другой предмет
//
// Приёмка WIRE-1 (WIRE-4-03) требует, чтобы домен доверия, который служба
// принимает, не был объявлен ни одним литералом кода: перепись литералов вида
// `spiffe://` в непробном дереве даёт ноль, а домен приходит настройкой
// (`KANAME_AUTHN__TRUST_DOMAIN`). Ось «SPIFFE» переписи осей держалась числом
// вхождений имени платформы в профилях чарта — а они называют СОСЕДА (учётку
// края платформы в круге отправителей) и стенд, то есть не имя службы. Имя
// службы в SPIFFE — то, что произносит её процесс; судится он.

// trustDomainLiteralMarker — признак литерала, объявляющего SPIFFE-имя.
const trustDomainLiteralMarker = "spiffe://"

// JudgeProcessTrustDomainLiterals судит строковые литералы поданных исходников:
// ни один не объявляет SPIFFE-имени. Пробы (`_test.go`) не судятся.
func JudgeProcessTrustDomainLiterals(sources map[string][]byte) (ProcessKnobCensus, []ProcessKnobFinding) {
	var (
		census   ProcessKnobCensus
		findings []ProcessKnobFinding
	)
	paths := make([]string, 0, len(sources))
	for p := range sources {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	fset := token.NewFileSet()
	for _, path := range paths {
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, sources[path], 0)
		if err != nil {
			census.Unparsed = append(census.Unparsed, path)
			continue
		}
		census.Files++
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			census.Literals++
			val, uqErr := strconv.Unquote(lit.Value)
			if uqErr != nil || !strings.Contains(val, trustDomainLiteralMarker) {
				return true
			}
			findings = append(findings, ProcessKnobFinding{
				File: path,
				Line: fset.Position(lit.Pos()).Line,
				Name: val,
			})
			return true
		})
	}
	return census, findings
}

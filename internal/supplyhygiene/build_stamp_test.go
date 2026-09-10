// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_stamp_test.go — сборка ПРОСТАВЛЯЕТ версию, а не обещает её.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Двоичный файл службы объявляет `buildVersion`/`buildRevision` и кормит ими
// ряд витрины `kaname_build_info`. Само по себе это ничего не гарантирует:
// компоновщик подставляет значение по ПОЛНОМУ ИМЕНИ символа и молчит, когда
// такого символа нет, а сборка, не назвавшая `-ldflags` вовсе, оставляет
// умолчание. В обоих случаях витрина отвечает — и отвечает неправду.
//
// Класс не выдуман: в этом же дереве соседние процессы платформы объявляли такие
// же переменные, а подстановка до них не доходила — величина есть, производителя
// нет. Сегодня доходит до всех (#2527), и ведомость остатка ПУСТА. СКОЛЬКО их,
// здесь не пишется и не писалось: прежде тут стояло «четыре сервиса … ни одна
// сборка дерева этого не делает», и первая половина устарела бы с каждым новым
// образом, а вторая устарела в тот день, когда штамп проставил ЭТОТ образ.
// Перепись «объявляют N · ставят M» принадлежит держателю платформы
// `internal/repohygiene` `TestBuildStampReachesEveryBinaryThatDeclaresIt` (#2521),
// он же ведёт ведомость остатка. Держать число здесь значило бы завести второе
// место об одном предмете — а разошлось бы оно молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — ДВЕ ПОЛОСЫ, И ОБЕ ОБЯЗАТЕЛЬНЫ
//
//  1. ИСПОЛНЯЕМАЯ строка сборки службы несёт `-ldflags` с `-X` на ОБА символа, и
//     значения берутся из тех же аргументов, из которых делается клеймо образа;
//     сами аргументы объявлены в ТОЙ ЖЕ ступени, где идёт сборка (аргумент,
//     объявленный в другой ступени, в этой не виден, и подстановка молча даёт
//     пустую строку). Ось видимости ступени здесь БОЛЬШЕ НЕ ЕДИНСТВЕННАЯ в
//     дереве: держатель платформы завёл её у себя вместе с #2527. Осталась
//     здешней только сверка «значение взято ИМЕННО из аргумента клейма» — она
//     называет имена аргументов, а держатель платформы их намеренно не знает.
//  2. У каждого `-X` есть ЦЕЛЬ: символ объявлен переменной уровня пакета в
//     композиционном корне. Без этой полосы переименование переменной в Go
//     молча отвязало бы штамп — компоновщик о промахе не сообщает.
//
// Одной первой полосы мало: она зеленела бы при несуществующем символе. Одной
// второй мало: она зеленела бы при сборке без штампа вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБИРАЕТСЯ ИСПОЛНЯЕМАЯ ЧАСТЬ, А НЕ ТЕКСТ
//
// Слово `-ldflags` стоит в комментариях — и в шапке композиционного корня, и в
// этой самой шапке. Проверка по подстроке над сырым файлом нашла бы СВОЁ
// СОБСТВЕННОЕ объяснение и осталась бы зелёной при снятой подстановке. Поэтому
// строки комментариев отбрасываются до разбора, а склейки продолжения строки
// сшиваются: `RUN` службы разнесён по нескольким физическим строкам, и
// построчный разбор увидел бы половину команды.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// stampedSymbols — символы, которые сборка обязана проставить, и аргумент, из
// которого берётся значение каждого. Пара, а не два перечня: разъехавшись, они
// дали бы штамп, взятый не из объявления провенанса, — то есть вторую величину
// об одном предмете.
var stampedSymbols = []struct {
	symbol string // полное имя, как его видит компоновщик
	arg    string // аргумент сборки, из которого берётся значение
}{
	{symbol: "main.buildVersion", arg: "KACHO_IMAGE_VERSION"},
	{symbol: "main.buildRevision", arg: "KACHO_IMAGE_REVISION"},
}

// serviceBinaryFlag — по чему опознаётся строка сборки ИМЕННО служебного
// двоичного файла. Пробел на конце обязателен: без него образец совпал бы и с
// накатчиком миграций, который витрины не держит и штампа не требует.
const serviceBinaryFlag = "-o /kaname "

// builderStageMarker — начало ступени сборки. Аргументы, объявленные в другой
// ступени, здесь не видны.
const builderStageMarker = "AS builder"

// buildStampCensus — объём осмотренного одним обходом.
type buildStampCensus struct {
	linesScanned    int // физических строк файла сборки
	executableLines int // из них исполняемых (не комментарий, не пусто)
	instructions    int // склеенных инструкций
	buildCommands   int // из них — сборок служебного двоичного файла
	argsDeclared    int // объявлений аргументов в ступени сборки
	goVarsDeclared  int // символов, объявленных переменной уровня пакета
}

// dockerfileInstructions — исполняемая часть файла сборки, сшитая по
// продолжениям строки. Комментарии отбрасываются ЦЕЛИКОМ и до сшивки: иначе
// продолжение, начинающееся с решётки, унесло бы с собой хвост команды.
func dockerfileInstructions(raw string) ([]string, buildStampCensus) {
	var census buildStampCensus
	var out []string
	var cur strings.Builder
	cont := false

	for _, line := range strings.Split(raw, "\n") {
		census.linesScanned++
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		census.executableLines++
		body := strings.TrimSuffix(trimmed, "\\")
		if cont {
			cur.WriteString(" ")
		}
		cur.WriteString(strings.TrimSpace(body))
		cont = strings.HasSuffix(trimmed, "\\")
		if cont {
			continue
		}
		out = append(out, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	census.instructions = len(out)
	return out, census
}

// scanBuildStamp — разбор над ПРОИЗВОЛЬНЫМ корнем службы: и файл сборки, и
// объявления Go берутся оттуда же. Вынесено из пробы затем, чтобы способность
// упасть доказывалась подачей входа, а не чтением.
func scanBuildStamp(root string) (buildStampCensus, []string, error) {
	raw, err := os.ReadFile(filepath.Join(root, dockerfileName))
	if err != nil {
		return buildStampCensus{}, nil, err
	}

	instructions, census := dockerfileInstructions(string(raw))

	// Аргументы, объявленные ПОСЛЕ начала ступени сборки и ДО следующей ступени.
	declaredInBuilder := map[string]bool{}
	inBuilder := false
	for _, ins := range instructions {
		if strings.HasPrefix(ins, "FROM ") {
			inBuilder = strings.Contains(ins, builderStageMarker)
			continue
		}
		if !inBuilder || !strings.HasPrefix(ins, "ARG ") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(ins, "ARG "))
		name, _, _ = strings.Cut(name, "=")
		declaredInBuilder[strings.TrimSpace(name)] = true
		census.argsDeclared++
	}

	// Символы, объявленные переменной уровня пакета в композиционном корне.
	declaredInGo, err := packageLevelVars(filepath.Join(root, "cmd", "kaname"))
	if err != nil {
		return census, nil, err
	}

	var findings []string
	for _, ins := range instructions {
		if !strings.Contains(ins, serviceBinaryFlag) {
			continue
		}
		census.buildCommands++
		for _, s := range stampedSymbols {
			pkg, name, _ := strings.Cut(s.symbol, ".")
			if pkg == "main" && declaredInGo[name] {
				census.goVarsDeclared++
			} else {
				findings = append(findings, "символ "+s.symbol+" НЕ ОБЪЯВЛЕН переменной "+
					"уровня пакета в cmd/kaname: компоновщик о промахе `-X` молчит, "+
					"поэтому штамп не доедет и это ничем не проявится")
			}
			if !strings.Contains(ins, "-X "+s.symbol+"=") {
				findings = append(findings, "строка сборки не проставляет "+s.symbol+
					": витрина ответит умолчанием, а не тем, что исполняется")
				continue
			}
			if !strings.Contains(ins, "-X "+s.symbol+"=$"+s.arg) &&
				!strings.Contains(ins, "-X "+s.symbol+"=${"+s.arg+"}") {
				findings = append(findings, "значение "+s.symbol+" берётся не из аргумента "+
					s.arg+", которым клеймится образ, — значит витрина и клеймо суть "+
					"две величины об одном предмете и разойдутся молча")
			}
			if !declaredInBuilder[s.arg] {
				findings = append(findings, "аргумент "+s.arg+" не объявлен в ступени "+
					"сборки: в другой ступени он не виден, и подстановка даст ПУСТУЮ строку")
			}
		}
	}
	if census.buildCommands == 0 {
		findings = append(findings, "в файле сборки нет ни одной строки, собирающей "+
			"служебный двоичный файл (образец "+serviceBinaryFlag+") — разбор беспредметен")
	}
	return census, findings, nil
}

// packageLevelVars — имена переменных уровня пакета в каталоге.
//
// Разбор синтаксического дерева, а не поиск по образцу: имя переменной
// встречается и в строках, и в комментариях этого же дерева, и поиск словом
// зеленел бы на упоминании.
func packageLevelVars(dir string) (map[string]bool, error) {
	out := map[string]bool{}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, err
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, n := range vs.Names {
						out[n.Name] = true
					}
				}
			}
		}
	}
	return out, nil
}

// TestBuildStampReachesTheBinaryItLabels — сборка службы проставляет обе
// величины версии, и у каждой подстановки есть цель.
func TestBuildStampReachesTheBinaryItLabels(t *testing.T) {
	census, findings, err := scanBuildStamp(serviceRoot)
	require.NoErrorf(t, err, "разбор сборки службы: %s", filepath.Join(serviceRoot, dockerfileName))

	t.Logf("перепись: строк файла сборки %d · из них исполняемых %d · инструкций %d · "+
		"сборок служебного двоичного файла %d · аргументов ступени сборки %d · "+
		"символов с объявлением %d · находок %d",
		census.linesScanned, census.executableLines, census.instructions,
		census.buildCommands, census.argsDeclared, census.goVarsDeclared, len(findings))

	// Пустой обход — находка: «ноль непроставленных величин» обязано быть
	// отличимо от «ноль прочитанного».
	require.NotZero(t, census.linesScanned, "обход пуст: файл сборки не прочитан — вердикт беспредметен")
	require.NotZero(t, census.executableLines,
		"обход пуст: исполняемых строк не осталось ни одной — разбор отбросил всё, вердикт беспредметен")
	require.NotZero(t, census.instructions, "обход пуст: инструкций не распознано ни одной — распознаватель ослеп")

	for _, f := range findings {
		t.Errorf("%s: %s", filepath.ToSlash(filepath.Join(serviceRoot, dockerfileName)), f)
	}
}

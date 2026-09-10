// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// bootedge_env_reach_test.go — ГЕЙТ КЛАССА: переменная окружения, НАЗВАННАЯ
// таблицей рёбер подъёма, обязана доезжать до поля (#2469).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ТРЕТЬЯ СТУПЕНЬ, КОТОРУЮ НЕ СУДИЛ НИ ОДИН ИЗ ДВУХ СОСЕДЕЙ
//
// Ступеней до старта четыре, и две накрыты гейтами досягаемости:
//
//	СТРАЖ НАСТРОЙКИ   — `config.TestRefusalNamedEnvVarReachesItsField`;
//	САМООТЧЁТ ПОСАДКИ — `TestPostureSelfReportNamesAReachableEnvVar`.
//
// Оба прямо говорят в своих шапках, что отказов ПУТИ ПОДЪЁМА не судят. А имена
// ручек в этих отказах есть: страж транспорта HTTP-рёбер печатает оператору
// «поставьте <ручка>=true с её сертификатом и ключом» и «объявлено <ручка>».
//
// Цена неверного имени здесь та же, что у соседей, и в самой дорогой форме:
// отказ ВЫГЛЯДИТ исчерпывающим — называет координату и объясняет, что едет по
// проводу, — а оператор задаёт названное и не меняет НИЧЕГО. Служба
// по-прежнему отказывается стартовать по той же причине, и разорвать этот цикл
// у отдельно поставленной службы некому: подсказать некому, а исходников у
// оператора может не быть вовсе.
//
// Риск не теоретический потому, что ступень читает ВТОРОЙ механизм настройки:
// имена этих ручек выводит `envconfig` (`config.LoadMTLS`), а не `viper`, и
// правило вывода имени у него своё. Гейт соседа, спрашивающий `config.Load`, о
// них не высказывается вовсе — он их не находит.
//
// Замер на ревизии заведения: имён 6 · доезжает 6 · инертных 0. Живого дефекта
// нет — предмет гейта в том, что свойство держалось ВНИМАНИЕМ, а страж,
// потерявший верное имя, на исправной посадке выглядит РОВНО ТАК ЖЕ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ РАЗБОР, А НЕ ПОДСТРОКА
//
// Имена этих ручек стоят в дереве и комментариями, и в текстах отказов, и в
// профилях. Предикат по подстроке краснел бы на собственном объяснении
// проверяемого. Поэтому судятся ПОЛЯ составного литерала `httpEdgeTLS`,
// прочитанные из синтаксического дерева: `knob` и `plaintextKnob`. Поле `why`
// намеренно не судится — это проза, а не координата.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОПЫТ, А НЕ ЧТЕНИЕ ТЕГОВ
//
// «Есть ли у имени тег» — вопрос о тексте объявления, и он не равен вопросу
// оператора. Предикат один и он про ИСХОД: задать переменную и посмотреть,
// изменилась ли загруженная посадка транспорта.
//
// Способность упасть доказана инъекцией — bootedge_env_reach_injection_test.go.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// bootEdgeKnobFields — поля составного литерала, несущие КООРДИНАТУ. Всё
// остальное в этом литерале — проза и величины.
var bootEdgeKnobFields = map[string]bool{"knob": true, "plaintextKnob": true}

// bootEdgeLiteralType — тип, чьи литералы объявляют рёбра подъёма.
const bootEdgeLiteralType = "httpEdgeTLS"

// bootEdgeKnob — одна названная ручка с координатой её объявления.
type bootEdgeKnob struct {
	Name string
	File string
	Line int
}

func (k bootEdgeKnob) String() string { return fmt.Sprintf("%s (%s:%d)", k.Name, k.File, k.Line) }

// bootEdgeKnobsIn читает объявленные ручки рёбер подъёма из ОДНОГО исходника.
//
// Источник принимается доводом (имя и байты): тем же вызовом инъекция подаёт
// синтетический вход, меняя ровно один факт.
//
// Литерал узнаётся ДВУМЯ формами, и обе законны в этом дереве: с явным типом
// (`httpEdgeTLS{…}`) и без него — внутри среза, где тип задан элементом
// (`[]httpEdgeTLS{{…}}`). Форма, о которой распознаватель не знает, даёт не
// красное и не зелёное, а МОЛЧАНИЕ: сегодня таблица написана второй формой, и
// разбор, знающий только первую, прочитал бы НОЛЬ ручек.
func bootEdgeKnobsIn(name string, src []byte) ([]bootEdgeKnob, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var out []bootEdgeKnob
	// declared — тип, объявленный внешним литералом среза: элементы внутри него
	// свой тип не повторяют.
	var read func(lit *ast.CompositeLit, declared string)
	read = func(lit *ast.CompositeLit, declared string) {
		typeName := declared
		switch t := lit.Type.(type) {
		case *ast.Ident:
			typeName = t.Name
		case *ast.ArrayType:
			if id, ok := t.Elt.(*ast.Ident); ok {
				typeName = id.Name
			}
		}
		for _, elt := range lit.Elts {
			if inner, ok := elt.(*ast.CompositeLit); ok {
				read(inner, typeName)
				continue
			}
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok || typeName != bootEdgeLiteralType {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || !bootEdgeKnobFields[key.Name] {
				continue
			}
			value, ok := bootEdgeConstantString(kv.Value)
			if !ok || strings.TrimSpace(value) == "" {
				// Пустая ручка означает «исключения у ребра не бывает» — это
				// объявленная величина, а не координата.
				continue
			}
			pos := fset.Position(kv.Pos())
			out = append(out, bootEdgeKnob{Name: value, File: filepath.Base(pos.Filename), Line: pos.Line})
		}
	}

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		read(lit, "")
		return false // вложенные литералы уже прочитаны рекурсией
	})
	return out, nil
}

// bootEdgeConstantString — строковая константа, включая склейку литералов.
func bootEdgeConstantString(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		l, okL := bootEdgeConstantString(e.X)
		r, okR := bootEdgeConstantString(e.Y)
		if !okL || !okR {
			return "", false
		}
		return l + r, true
	}
	return "", false
}

// bootEdgeCensus — объём осмотренного. Печатается ВСЕГДА.
type bootEdgeCensus struct {
	Files   int
	Named   int
	Reached int
	Names   []string
}

func (c bootEdgeCensus) String() string {
	return fmt.Sprintf("файлов корня прочитано %d · имён названо таблицей рёбер %d · доезжает %d · инертных %d",
		c.Files, c.Named, c.Reached, c.Named-c.Reached)
}

// auditBootEdgeKnobs — разбор. Находки и перепись; `*testing.T` не трогает, иначе
// инъекции не поддался бы.
func auditBootEdgeKnobs(files int, knobs []bootEdgeKnob,
	reaches func(env string) (bool, string)) ([]string, bootEdgeCensus) {

	census := bootEdgeCensus{Files: files}
	at := map[string]bootEdgeKnob{}
	for _, k := range knobs {
		if _, seen := at[k.Name]; !seen {
			at[k.Name] = k
			census.Names = append(census.Names, k.Name)
		}
	}
	sort.Strings(census.Names)
	census.Named = len(census.Names)

	var findings []string
	// ПУСТОЙ ОБХОД — находка, а не тишина.
	if census.Files == 0 {
		return []string{"обход пуст: исходников композиционного корня прочитано 0"}, census
	}
	if census.Named == 0 {
		return []string{"обход пуст: таблица рёбер подъёма не назвала ни одной ручки — " +
			"либо рёбра перестали их называть, либо распознаватель не знает формы литерала; " +
			"и то и другое читается этой строкой одинаково, поэтому вердикт беспредметен"}, census
	}

	for _, env := range census.Names {
		reached, how := reaches(env)
		if reached {
			census.Reached++
			continue
		}
		findings = append(findings, fmt.Sprintf(
			"%s названа таблицей рёбер подъёма (%s) и ДО ПОЛЯ НЕ ДОЕЗЖАЕТ: %s. "+
				"Оператор задаёт названное, получает ТОТ ЖЕ отказ и разорвать этот цикл ему нечем — "+
				"назовите ту ручку, которая работает, либо объявите этой привязку",
			env, at[env], how))
	}
	return findings, census
}

// ─────────────────────────────────────────────────────────────────────────────
// ЖИВОЙ МИР.

// bootEdgeProbeValues — значения, которыми пробуют досягаемость. Формы разные:
// признак включения не меняется от пути, а путь — от «true». Досягаемость
// доказывает ЛЮБОЕ: вопрос не «годно ли значение», а «увидел ли его процесс».
var bootEdgeProbeValues = []string{"true", "/etc/kaname/tls/server/tls.crt", "mutual"}

// bootEdgeReaches — ОПЫТ: задать переменную и посмотреть, изменилась ли
// загруженная посадка транспорта.
//
// Спрашивается `LoadMTLS`, а не `Load`: ступень читает ВТОРОЙ механизм
// настройки, и вопрос, заданный первому, о ней не высказывается вовсе.
func bootEdgeReaches(t *testing.T) func(string) (bool, string) {
	t.Helper()
	return func(env string) (bool, string) {
		clearIAMEnv()
		base, err := config.LoadMTLS()
		if err != nil {
			return true, "посадка транспорта не загружается, досягаемость не спрашивалась"
		}
		for _, value := range bootEdgeProbeValues {
			clearIAMEnv()
			t.Setenv(env, value)
			got, err := config.LoadMTLS()
			if err != nil {
				return true, fmt.Sprintf("значение %q отвергнуто разбором — то есть прочитано", value)
			}
			if !reflect.DeepEqual(base, got) {
				return true, fmt.Sprintf("значение %q изменило загруженную посадку транспорта", value)
			}
		}
		return false, fmt.Sprintf("ни одно из %d пробных значений не изменило загруженную посадку",
			len(bootEdgeProbeValues))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ.

func TestBootEdgeRefusalNamesAReachableEnvVar(t *testing.T) {
	saved := os.Environ()
	t.Cleanup(func() {
		clearIAMEnv()
		for _, kv := range saved {
			if key, value, ok := strings.Cut(kv, "="); ok && strings.HasPrefix(key, "KANAME_") {
				_ = os.Setenv(key, value)
			}
		}
	})

	files := postureRootFiles(t)
	var knobs []bootEdgeKnob
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s не прочитан: %v", name, err)
		}
		found, err := bootEdgeKnobsIn(name, src)
		if err != nil {
			t.Fatalf("%s не разобран: %v", name, err)
		}
		knobs = append(knobs, found...)
	}

	findings, census := auditBootEdgeKnobs(len(files), knobs, bootEdgeReaches(t))

	t.Logf("объём осмотренного: %s", census)
	t.Logf("названы таблицей рёбер: %s", strings.Join(census.Names, ", "))

	if len(findings) > 0 {
		t.Fatalf("находок %d:\n  • %s", len(findings), strings.Join(findings, "\n  • "))
	}
}

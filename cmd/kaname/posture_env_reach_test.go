// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// posture_env_reach_test.go — ГЕЙТ КЛАССА: переменная окружения, НАЗВАННАЯ
// текстом САМООТЧЁТА О ПОСАДКЕ, обязана доезжать до поля.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Композиционный корень объявляет не-gRPC поверхности осями с тремя
// состояниями: величина · неприменимо с причиной · не объявлено. Причина
// неприменимости печатается оператору при старте и называет ручку, которой ось
// включают. Текст пишется прозой и не компилируется; привязка ключа к окружению
// живёт в разборе настройки и не знает, что о ней написано, — два места об одном
// предмете, расходящиеся МОЛЧА.
//
// Цена та же, что у отказа стража, и в самой дорогой форме: самоотчёт ВЫГЛЯДИТ
// исчерпывающим — называет координату и объясняет следствие («верификация всей
// плоскости данных реестра останется закрытой»), — а координата неверна.
// Оператор чужого облака задаёт названную переменную и не меняет НИЧЕГО.
//
// Замер на этом дереве до правки (#2042): осей с текстом 6 · имён названо 4 ·
// доезжало 0. Все четыре имени встречались в дереве РОВНО ОДИН раз — в самом
// тексте, — то есть производителя у них не было вовсе: величина берётся из
// настройки, а её ручка называется иначе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОПЫТ, А НЕ ЧТЕНИЕ ИСХОДНИКА
//
// «Есть ли у ключа привязка» — вопрос о тексте разбора настройки, и он не равен
// вопросу оператора. Ключ бывает известен виперу тремя способами (умолчание,
// явная привязка, легаси-псевдоним). Поэтому предикат один и он про ИСХОД:
// задать переменную и посмотреть, изменилась ли загруженная настройка.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЛАСТЬ НАЗВАНА ЧЕСТНО
//
// Судятся ТЕКСТЫ ОСЕЙ самоотчёта — аргумент `addrAxis` и объяснение
// `servicecontract.NotApplicable`. Отказы стража настройки сюда НЕ приходят: у
// них свой гейт (`config.TestRefusalNamedEnvVarReachesItsField`), и второго
// места об одном предмете здесь не заводится — производители текста разные.
// Отказы пути подъёма (`serve`, посадка mTLS) не судит НИ ОДИН из двух, и это
// названо, чтобы отсутствие не приняли за покрытие.
//
// Судится ровно то, что НАЗВАНО ОСЬЮ. Имя переменной, встреченное в комментарии
// рядом или в тексте отказа, предметом этого гейта не является: по дереву iam
// имён вида `KANAME_*` больше сотни, и разбор, судящий исходный текст, дал бы
// десятки находок, из которых верны единицы, — такой отключают первым.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// postureEnvPattern — имя переменной ЭТОЙ службы в тексте оси.
var postureEnvPattern = regexp.MustCompile(`KANAME_[A-Z0-9_]*[A-Z0-9]`)

// axisText — один текст самоотчёта об оси с его координатой.
type axisText struct {
	File string
	Line int
	Text string
}

func (a axisText) String() string { return fmt.Sprintf("%s:%d", a.File, a.Line) }

// postureAxisTexts — тексты осей, объявленные ЭТИМ исходником.
//
// Читается разбором, а не поиском подстроки: тот же текст встречается в
// комментариях, в отказах и в шапках функций, и счёт по тексту судил бы прозу.
//
// Аргумент, не являющийся строковой константой, осью с ТЕКСТОМ не считается:
// сама `addrAxis` передаёт свой параметр дальше, и это не место самоотчёта, а
// его механизм.
func postureAxisTexts(name string, src []byte) ([]axisText, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, src, parser.ParseComments)
	if err != nil {
		return nil, err
	}

	var out []axisText
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		idx, ok := axisTextArgument(call)
		if !ok || idx >= len(call.Args) {
			return true
		}
		text, ok := constantString(call.Args[idx])
		if !ok {
			return true
		}
		out = append(out, axisText{
			File: name,
			Line: fset.Position(call.Lparen).Line,
			Text: text,
		})
		return true
	})
	return out, nil
}

// axisTextArgument — номер аргумента, несущего текст самоотчёта, если этот вызов
// объявляет ось.
func axisTextArgument(call *ast.CallExpr) (int, bool) {
	fun := call.Fun
	// `servicecontract.NotApplicable[T](…)` — вызов инстанцированной формы:
	// снимаем указание типа, иначе селектор под ним не виден.
	switch idx := fun.(type) {
	case *ast.IndexExpr:
		fun = idx.X
	case *ast.IndexListExpr:
		fun = idx.X
	}
	switch f := fun.(type) {
	case *ast.Ident:
		if f.Name == "addrAxis" {
			return 1, true
		}
	case *ast.SelectorExpr:
		if f.Sel.Name == "NotApplicable" {
			return 0, true
		}
	}
	return 0, false
}

// constantString — строковая константа выражения, включая склейку литералов.
func constantString(expr ast.Expr) (string, bool) {
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
		left, okL := constantString(e.X)
		right, okR := constantString(e.Y)
		if !okL || !okR {
			return "", false
		}
		return left + right, true
	}
	return "", false
}

// postureEnvCensus — объём осмотренного. Печатается ВСЕГДА: без него «находок 0»
// неотличимо от «прочитано 0».
type postureEnvCensus struct {
	Files     int
	Axes      int
	Named     int
	Reached   int
	NamedList []string
}

func (c postureEnvCensus) String() string {
	return fmt.Sprintf(
		"файлов корня прочитано %d · осей с текстом объявлено %d · имён названо %d · доезжает %d · инертных %d",
		c.Files, c.Axes, c.Named, c.Reached, c.Named-c.Reached)
}

// auditPostureNamedEnv — разбор. Возвращает находки и объём осмотренного.
//
// Обращения к `*testing.T` здесь нет намеренно: разбор, роняющий пробу изнутри,
// инъекции не поддаётся.
func auditPostureNamedEnv(files int, axes []axisText,
	reaches func(env string) (bool, string)) ([]string, postureEnvCensus) {

	var findings []string
	census := postureEnvCensus{Files: files, Axes: len(axes)}

	namedAt := map[string]axisText{}
	for _, axis := range axes {
		for _, env := range postureEnvPattern.FindAllString(axis.Text, -1) {
			if _, seen := namedAt[env]; !seen {
				namedAt[env] = axis
			}
		}
	}
	for env := range namedAt {
		census.NamedList = append(census.NamedList, env)
	}
	sort.Strings(census.NamedList)
	census.Named = len(census.NamedList)

	// ПУСТОЙ ОБХОД — находка, а не тишина.
	if census.Files == 0 {
		findings = append(findings, "обход пуст: исходников композиционного корня прочитано 0")
	}
	if census.Files > 0 && census.Axes == 0 {
		findings = append(findings,
			"обход пуст: ни одна ось самоотчёта не объявлена текстом — предмета у разбора нет")
	}
	if census.Axes > 0 && census.Named == 0 {
		findings = append(findings,
			"обход пуст: ни одна ось не назвала переменной окружения — разбору нечего сверять")
	}
	if len(findings) > 0 {
		return findings, census
	}

	for _, env := range census.NamedList {
		reached, how := reaches(env)
		if reached {
			census.Reached++
			continue
		}
		axis := namedAt[env]
		findings = append(findings, fmt.Sprintf(
			"%s названа текстом самоотчёта об оси (%s) и ДО ПОЛЯ НЕ ДОЕЗЖАЕТ: %s. "+
				"Оператор задаёт названное и не меняет ничего — самоотчёт выглядит исчерпывающим, "+
				"а координата неверна. Назовите ту ручку, которая работает, либо объявите этой привязку",
			env, axis, how))
	}
	return findings, census
}

// ─────────────────────────────────────────────────────────────────────────────
// ЖИВОЙ МИР.

// postureRootFiles — не-тестовые исходники композиционного корня.
func postureRootFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("каталог композиционного корня не прочитан: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// postureProbeValues — значения, которыми пробуют досягаемость. Форм несколько:
// адрес не меняется от «true», а булев опт-ин — от адреса. Досягаемость
// доказывает ЛЮБОЕ: вопрос не «годно ли значение», а «увидел ли его процесс».
var postureProbeValues = []string{"tcp://127.0.0.1:19999", "true", "7m", "7"}

// postureReaches — ОПЫТ: задать переменную и посмотреть, изменилась ли
// загруженная настройка.
func postureReaches(t *testing.T) func(string) (bool, string) {
	t.Helper()
	return func(env string) (bool, string) {
		clearIAMEnv()
		base, err := config.Load("")
		if err != nil {
			return true, "профиль не загружается, досягаемость не спрашивалась"
		}
		for _, value := range postureProbeValues {
			clearIAMEnv()
			t.Setenv(env, value)
			got, err := config.Load("")
			if err != nil {
				return true, fmt.Sprintf("значение %q отвергнуто разбором настройки — то есть прочитано", value)
			}
			if !reflect.DeepEqual(base, got) {
				return true, fmt.Sprintf("значение %q изменило загруженную настройку", value)
			}
		}
		return false, fmt.Sprintf(
			"ни одно из %d пробных значений не изменило загруженную настройку",
			len(postureProbeValues))
	}
}

// clearIAMEnv — снимает переменные ЭТОЙ службы, чтобы окружение прогона не
// подменяло исход опыта.
func clearIAMEnv() {
	for _, kv := range os.Environ() {
		key, _, ok := strings.Cut(kv, "=")
		if ok && strings.HasPrefix(key, "KANAME_") {
			_ = os.Unsetenv(key)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ГЕЙТ.

func TestPostureSelfReportNamesAReachableEnvVar(t *testing.T) {
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
	var axes []axisText
	for _, name := range files {
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s не прочитан: %v", name, err)
		}
		found, err := postureAxisTexts(name, src)
		if err != nil {
			t.Fatalf("%s не разобран: %v", name, err)
		}
		axes = append(axes, found...)
	}

	findings, census := auditPostureNamedEnv(len(files), axes, postureReaches(t))

	t.Logf("объём осмотренного: %s", census)
	t.Logf("названы осями: %s", strings.Join(census.NamedList, ", "))

	if len(findings) > 0 {
		t.Fatalf("находок %d:\n  • %s", len(findings), strings.Join(findings, "\n  • "))
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_gates_test.go — ГЕЙТЫ по дереву для требований полосы своего входа:
// сценарии F4d-10 и F4d-11 приёмки Ф4д (F4d-03, гейт словаря посадки, снят
// вместе со словарём, kaname#363).
//
// Оба судят РАЗОБРАННЫЙ исходник, а не текст: имена стоят и в комментариях, и в
// текстах отказов, поэтому проверка по подстроке краснела бы на собственном
// объяснении. Каждый печатает объём осмотренного и
// падает на пустом обходе — «ноль находок» обязано быть отличимо от «ноль
// прочитанного». Способность падать и молчать доказана инъекцией в обе стороны
// (lane_gates_injection_test.go).
//
// ПОЧЕМУ ГЕЙТЫ ЖИВУТ ЗДЕСЬ, А НЕ В ОБЩЕЙ ГИГИЕНЕ ДЕРЕВА. Их предмет — ОДИН
// пакет: таблица требований и ручки разговора с поставщиком объявлены здесь и
// нигде больше. Гейт, стоящий рядом со своим
// предметом, читает его без обхода всего дерева и не может разойтись с ним
// каталогом.
package config_test

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
)

// packageDir — каталог пакета настройки. Гейты читают исходник с диска, а не
// свою копию его содержимого.
const packageDir = "."

// parsePackageFiles возвращает разобранные непроверочные файлы пакета.
func parsePackageFiles(t *testing.T) (*token.FileSet, map[string]*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatalf("каталог пакета не прочитан: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(packageDir, name), nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("%s не разобран: %v", name, err)
		}
		out[name] = f
	}
	if len(out) == 0 {
		t.Fatal("обход пуст: непроверочных файлов Go в пакете не найдено — гейт судил бы о непрочитанном")
	}
	return fset, out
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-10 — проба отказа старта ТАБЛИЧНАЯ по объявлению, а не по своему перечню.

// Гейт утверждает три вещи сразу: таблица объявлена ровно одна; проба обходит
// ИМЕННО её; ни одна стадия старта не пуста.
//
// Прежде третье утверждение звучало «ни при одном значении поля посадки
// множество обязательных элементов не пусто», и перепись шла по полосам.
// Посадка у службы одна (kaname#363); вырожденный исход снятия оси — таблица,
// у которой строки есть, но ни одна не исполняется на какой-то стадии, — и
// судится теперь переписью по стадиям.
func TestF4d10_BootRefusalProbeWalksTheDeclaredTable(t *testing.T) {
	fset, files := parsePackageFiles(t)

	// (1) таблица объявлена ровно одна
	census := inspectLaneTable(files)
	decls, rows, perStage := census.Declarations, census.Rows, census.PerStage
	if decls != 1 {
		t.Fatalf("объявлений таблицы требований — %d, обязано быть ровно 1: второе разошлось бы с первым молча", decls)
	}
	if rows == 0 {
		t.Fatal("таблица пуста — обходить нечего, и гейт судил бы о непрочитанном")
	}

	// (2) НИ ОДНА стадия не пуста: стадия без требований означала бы старт,
	//     поднимающийся без проверки того, чем служба удостоверяет человека.
	stages := []string{"LaneStageConfig", "LaneStageWiring"}
	for _, stage := range stages {
		if perStage[stage] == 0 {
			t.Errorf("стадия %s не несёт НИ ОДНОГО требования — старт поднимался бы без неё", stage)
		}
	}
	if sum := perStage["LaneStageConfig"] + perStage["LaneStageWiring"]; sum != rows {
		t.Errorf("строк таблицы %d, а по стадиям насчитано %d — у строки стадия, которой перепись не знает", rows, sum)
	}

	// (3) проба обходит именно это объявление
	probeFile := "lane_requirements_test.go"
	src, err := os.ReadFile(probeFile)
	if err != nil {
		t.Fatalf("проба отказа старта не прочитана: %v", err)
	}
	pf, err := parser.ParseFile(fset, probeFile, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s не разобран: %v", probeFile, err)
	}
	if !rangesOverLaneRequirements(pf) {
		t.Errorf("проба отказа старта не обходит config.LaneRequirements — она перестала быть табличной, "+
			"и строка может остаться непокрытой (%s)", probeFile)
	}

	t.Logf("перепись: строк в таблице %d (настройка %d · сборка %d) · порождено случаев %d · объявлений таблицы %d",
		rows, perStage["LaneStageConfig"], perStage["LaneStageWiring"], rows, decls)
}

// rowStage возвращает имя стадии, названной строкой таблицы; пусто — стадии нет.
func rowStage(row *ast.CompositeLit) string {
	for _, el := range row.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Stage" {
			continue
		}
		switch v := kv.Value.(type) {
		case *ast.Ident:
			return v.Name
		case *ast.SelectorExpr:
			return v.Sel.Name
		}
	}
	return ""
}

// rangesOverLaneRequirements — есть ли в пробе обход именно объявленной
// таблицы.
func rangesOverLaneRequirements(f *ast.File) bool {
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		rs, ok := n.(*ast.RangeStmt)
		if !ok {
			return true
		}
		switch x := rs.X.(type) {
		case *ast.Ident:
			if x.Name == "LaneRequirements" {
				found = true
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == "LaneRequirements" {
				found = true
			}
		}
		return true
	})
	return found
}

// ─────────────────────────────────────────────────────────────────────────────
// F4d-11 — ручка, от которой зависит разговор с поставщиком, обязана быть видна
// проверке настройки при старте.

// Видна проверке — значит ЧИТАЕТСЯ ПАКЕТОМ НАСТРОЙКИ. Config.Validate() —
// метод этого пакета, и дотянуться он способен ровно до того, что пакет читает
// сам. Ручка, читаемая прямым обращением к окружению из корня сборки, проверке
// невидима by construction, и полосность посадки окажется неполной ровно на
// неё.
//
// ПРЕДИКАТ — МЕСТО ЧТЕНИЯ, А НЕ ИМЯ. Соответствия «имя переменной ↔ имя поля»
// не существует: секрет в YAML не пишется никогда, поэтому полем объявляется
// ИМЯ переменной (`hydra-admin-token-env`), а не её значение. Сверка по именам
// объявила бы такую ручку невидимой при исправной проводке.
//
// ГРАНИЦА НАЗВАНА ВСЛУХ: гейт утверждает «пакет настройки эту ручку читает», а
// не «Validate до неё дотягивается». Второго предиката по разбору не построить
// — путь до значения идёт через резолв, который зовут и проверка, и сборка.
// Чего гейт даёт — невозможность завести разговор с поставщиком мимо настройки
// обычным способом, каким его заводят.
func TestF4d11_EveryProviderKnobIsVisibleToConfigValidation(t *testing.T) {
	_, files := parsePackageFiles(t)

	// Ручки, читаемые САМИМ пакетом настройки.
	inConfig := map[string]bool{}
	for name := range providerEnvKnobsIn(t, packageDir, files).where {
		inConfig[name] = true
	}

	// Ручки окружения, читаемые НЕПРОВЕРОЧНЫМ кодом службы, — переписью по
	// дереву службы, а не по одному пакету: восьмая ручка жила в композиционном
	// корне, и именно поэтому её никто не видел.
	env := providerEnvKnobs(t, "../../../..")

	var invisible []string
	for _, knob := range env.names {
		if inConfig[knob] {
			continue
		}
		invisible = append(invisible, knob+" ("+env.where[knob]+")")
	}
	sort.Strings(invisible)

	t.Logf("перепись: файлов пакета настройки осмотрено %d; файлов Go дерева службы прочитано %d; "+
		"ручек разговора с поставщиком в дереве службы %d; видимых проверке %d",
		len(files), env.filesRead, len(env.names), len(env.names)-len(invisible))

	// ПРЕДПОСЫЛКА — ПРОЧИТАННОЕ, А НЕ НАЙДЕННОЕ. Ручек разговора с поставщиком в
	// дереве НОЛЬ с тех пор, как снята последняя дорога к нему — обмен у прежнего
	// издателя (kaname#494). Это ЦЕЛЬ снятия, и падать на ней гейт не вправе:
	// прежний отказ «ни одной ручки не найдено» краснел ровно на достигнутом.
	// Отличить «ноль найдено» от «ноль прочитано» обязана перепись файлов, а
	// способность найти ручку, если она вернётся, доказывают инъекции оси 3
	// (lane_gates_injection_test.go) на синтетике.
	if env.filesRead == 0 {
		t.Fatal("обход пуст: ни одного файла Go дерева службы не прочитано — гейт судил бы о непрочитанном")
	}
	if len(env.names) == 0 {
		t.Logf("ручек разговора с поставщиком 0 — предмет гейта снят вместе с последней дорогой к " +
			"поставщику; вернувшаяся ручка будет судиться здесь же")
	}
	if len(invisible) > 0 {
		t.Errorf("ручки разговора с поставщиком, невидимые проверке настройки при старте (%d): %s — "+
			"проверка дотягивается ровно до того, что читает пакет настройки, поэтому ручка мимо него "+
			"не участвует в полосности посадки и не может быть снята значением поля",
			len(invisible), strings.Join(invisible, ", "))
	}
}

// providerEnvKnobsIn — те же ручки, но по уже разобранным файлам одного
// каталога. Отдельная функция, чтобы обход пакета и обход дерева опознавали
// ручку ОДНИМ признаком: два предиката об одном предмете разошлись бы молча.
func providerEnvKnobsIn(t *testing.T, dir string, files map[string]*ast.File) envKnobs {
	t.Helper()
	out := envKnobs{where: map[string]string{}}
	for name, f := range files {
		for _, knob := range getenvNamesMentioningProvider(f) {
			if _, ok := out.where[knob]; !ok {
				out.names = append(out.names, knob)
				out.where[knob] = name
			}
		}
	}
	sort.Strings(out.names)
	return out
}

// getenvNamesMentioningProvider — имена переменных окружения разговора с
// внешним поставщиком, названные файлом.
//
// ПРИЗНАК — ФОРМА ИМЕНИ В ЛИТЕРАЛЕ, А НЕ ДОВОД `os.Getenv`. Довод ловит только
// прямое чтение и слепнет ровно там, где имя переменной вынесено косвенностью
// (`os.Getenv(c.HydraAdminTokenEnvName())`) — то есть на первой же ручке,
// которую починили. Гейт, чей предикат ломается от починки его же предмета,
// перепись занижает и об этом молчит.
//
// Литерал вида `KACHO_..._HYDRA_...` — единственный способ назвать такую
// переменную, будь то довод чтения, умолчание косвенности или имя в тексте
// отказа оператору. Комментарии литералами не являются и в перепись не входят.
func getenvNamesMentioningProvider(f *ast.File) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil || !looksLikeProviderEnvName(name) {
			return true
		}
		out = append(out, name)
		return true
	})
	return out
}

// looksLikeProviderEnvName — имя переменной окружения (заглавные, цифры и
// подчёркивания), называющее внешнего поставщика.
func looksLikeProviderEnvName(s string) bool {
	if len(s) < len("HYDRA") || !strings.Contains(s, "HYDRA") {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
		default:
			return false
		}
	}
	return true
}

// Законный близнец: ручка, к разговору с поставщиком не относящаяся, находкой
// не считается — иначе гейт краснел бы на каждой переменной окружения службы.
func TestF4d11_AKnobUnrelatedToTheProviderIsNotAFinding(t *testing.T) {
	env := providerEnvKnobs(t, "../../../..")
	for _, knob := range env.names {
		if knob == "KANAME_JWKS_ENC_KEY" || knob == "KANAME_SECOND_FACTOR_ENC_KEY" {
			t.Fatalf("ручка %q к разговору с поставщиком не относится и в перепись попадать не должна", knob)
		}
	}
	t.Logf("перепись: ручек разговора с поставщиком %d; посторонних среди них 0", len(env.names))
}

// envKnobs — перепись ручек окружения, читаемых прямым обращением.
type envKnobs struct {
	names []string
	where map[string]string
	// filesRead — сколько непроверочных файлов Go прочитано обходом дерева.
	// Объём осмотренного: «ручек 0» без него неотличимо от «файлов 0».
	filesRead int
}

// providerEnvKnobs собирает имена переменных окружения, читаемых непроверочным
// кодом службы и относящихся к разговору с внешним поставщиком.
//
// Признак — имя переменной, а не место чтения: разговор с поставщиком опознаётся
// по его же имени в ручке, и это единственное, что не зависит от того, в каком
// слое ручку прочитали.
func providerEnvKnobs(t *testing.T, serviceRoot string) envKnobs {
	t.Helper()
	out := envKnobs{where: map[string]string{}}
	seen := map[string]bool{}
	fset := token.NewFileSet()

	err := filepath.Walk(serviceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		out.filesRead++
		for _, name := range getenvNamesMentioningProvider(f) {
			if !seen[name] {
				seen[name] = true
				out.names = append(out.names, name)
				out.where[name] = filepath.Base(path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("обход дерева службы не выполнен: %v", err)
	}
	sort.Strings(out.names)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// Чистые тела гейтов. Вынесены, чтобы инъекция звала ТО ЖЕ, что исполняется на
// дереве: своя копия предиката в пробе инъекции разошлась бы с настоящим гейтом
// молча, и доказательство перестало бы относиться к нему.

// laneTableCensus — перепись таблицы требований.
type laneTableCensus struct {
	Declarations int
	Rows         int
	PerStage     map[string]int
}

// inspectLaneTable читает объявление таблицы требований.
func inspectLaneTable(files map[string]*ast.File) laneTableCensus {
	c := laneTableCensus{PerStage: map[string]int{}}
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			vs, ok := n.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "LaneRequirements" {
				return true
			}
			c.Declarations++
			for _, v := range vs.Values {
				cl, ok := v.(*ast.CompositeLit)
				if !ok {
					continue
				}
				for _, el := range cl.Elts {
					row, ok := el.(*ast.CompositeLit)
					if !ok {
						continue
					}
					c.Rows++
					if stage := rowStage(row); stage != "" {
						c.PerStage[stage]++
					}
				}
			}
			return false
		})
	}
	return c
}

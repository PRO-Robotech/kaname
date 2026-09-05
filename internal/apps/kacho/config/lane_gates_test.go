// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// lane_gates_test.go — ГЕЙТЫ по дереву для полосности посадки личности:
// сценарии F4d-03, F4d-10 и F4d-11 приёмки Ф4д.
//
// Все три судят РАЗОБРАННЫЙ исходник, а не текст: канонические имена значений
// стоят и в комментариях, и в текстах отказов, поэтому проверка по подстроке
// краснела бы на собственном объяснении. Каждый печатает объём осмотренного и
// падает на пустом обходе — «ноль находок» обязано быть отличимо от «ноль
// прочитанного». Способность падать и молчать доказана инъекцией в обе стороны
// (lane_gates_injection_test.go).
//
// ПОЧЕМУ ГЕЙТЫ ЖИВУТ ЗДЕСЬ, А НЕ В ОБЩЕЙ ГИГИЕНЕ ДЕРЕВА. Их предмет — ОДИН
// пакет: словарь значений поля, таблица требований полос и ручки разговора с
// поставщиком объявлены здесь и нигде больше. Гейт, стоящий рядом со своим
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
// ИМЕННО её; ни при одном значении поля множество обязательных элементов не
// пусто.
func TestF4d10_BootRefusalProbeWalksTheDeclaredTable(t *testing.T) {
	fset, files := parsePackageFiles(t)

	// (1) таблица объявлена ровно одна
	census := inspectLaneTable(files)
	decls, rows, perLane := census.Declarations, census.Rows, census.PerLane
	if decls != 1 {
		t.Fatalf("объявлений таблицы требований полос — %d, обязано быть ровно 1: второе разошлось бы с первым молча", decls)
	}
	if rows == 0 {
		t.Fatal("таблица пуста — обходить нечего, и гейт судил бы о непрочитанном")
	}

	// (2) НЕ СУЩЕСТВУЕТ значения поля, при котором множество обязательных
	//     элементов пусто. Самое сильное утверждение сценария.
	lanes := []string{"laneExternal", "laneOwn"}
	for _, lane := range lanes {
		if perLane[lane] == 0 {
			t.Errorf("полоса %s не несёт НИ ОДНОГО обязательного элемента — посадка поднималась бы без всякой проверки личности", lane)
		}
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
			"и клетка произведения может остаться непокрытой (%s)", probeFile)
	}

	t.Logf("перепись: клеток в таблице %d (external %d · own %d) · порождено случаев %d · объявлений таблицы %d",
		rows, perLane["laneExternal"], perLane["laneOwn"], rows*len(lanes), decls)
}

// rowLanes возвращает имена перечней полос, названные строкой таблицы.
func rowLanes(row *ast.CompositeLit) []string {
	var out []string
	for _, el := range row.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok || key.Name != "Lanes" {
			continue
		}
		switch v := kv.Value.(type) {
		case *ast.Ident:
			out = append(out, v.Name)
		case *ast.CompositeLit:
			for _, e := range v.Elts {
				if id, ok := e.(*ast.Ident); ok {
					out = append(out, id.Name)
				} else if sel, ok := e.(*ast.SelectorExpr); ok {
					out = append(out, sel.Sel.Name)
				}
			}
		}
	}
	return out
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

	t.Logf("перепись: файлов пакета настройки осмотрено %d; ручек разговора с поставщиком в дереве службы %d; видимых проверке %d",
		len(files), len(env.names), len(env.names)-len(invisible))

	if len(env.names) == 0 {
		t.Fatal("обход пуст: ни одной ручки разговора с поставщиком не найдено — гейт судил бы о непрочитанном")
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
		if knob == "KACHO_IAM_HOOK_TOKEN" || knob == "KACHO_IAM_JWKS_ENC_KEY" {
			t.Fatalf("ручка %q к разговору с поставщиком не относится и в перепись попадать не должна", knob)
		}
	}
	t.Logf("перепись: ручек разговора с поставщиком %d; посторонних среди них 0", len(env.names))
}

// envKnobs — перепись ручек окружения, читаемых прямым обращением.
type envKnobs struct {
	names []string
	where map[string]string
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

// mapstructureName вынимает имя настройки из тега структуры.
func mapstructureName(tag string) string {
	const key = `mapstructure:"`
	i := strings.Index(tag, key)
	if i < 0 {
		return ""
	}
	rest := tag[i+len(key):]
	j := strings.Index(rest, `"`)
	if j < 0 {
		return ""
	}
	name := rest[:j]
	if c := strings.Index(name, ","); c >= 0 {
		name = name[:c]
	}
	return name
}

// ─────────────────────────────────────────────────────────────────────────────
// Чистые тела гейтов. Вынесены, чтобы инъекция звала ТО ЖЕ, что исполняется на
// дереве: своя копия предиката в пробе инъекции разошлась бы с настоящим гейтом
// молча, и доказательство перестало бы относиться к нему.

// laneTableCensus — перепись таблицы требований полос.
type laneTableCensus struct {
	Declarations int
	Rows         int
	PerLane      map[string]int
}

// inspectLaneTable читает объявление таблицы требований полос.
func inspectLaneTable(files map[string]*ast.File) laneTableCensus {
	c := laneTableCensus{PerLane: map[string]int{}}
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
					for _, lane := range rowLanes(row) {
						c.PerLane[lane]++
					}
				}
			}
			return false
		})
	}
	return c
}

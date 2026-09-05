// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keys_internal_test.go — ключ-нестрока: ШЕСТЬ форм, а не десять (MOD-MF-08 · 09 ·
// 10 · 11, приёмка §5.3).
//
// # Почему проба внутренняя, а не через Load
//
// Три сценария из четырёх утверждают МОЛЧАНИЕ ступени разбора на входе, который
// до типизированной цели заведомо не доходит: ключи `on`, `off`, `yes`… законны
// как строки, но полями манифеста не являются, поэтому Load отверг бы их формой —
// и «молчит» стало бы неотличимо от «краснеет по другой причине». Проба ступени
// спрашивает ровно то, о чём сценарий: судит ли разбор ТИП ключа.
//
// Наблюдаемое следствие для вызывающего утверждается отдельно и через Load —
// MOD-MF-12 в manifest_test.go.
//
// # Почему по ТЕГУ узла, а не по разобранной карте
//
// Типизированная цель ловушку ПРЯЧЕТ: `map[string]map[string]string` приводит
// ключ `true` к строке `"true"` с `err == nil`. И даже нетипизированная карта
// теряет предмет — `null:` и `~:` схлопываются в один ключ, одно значение
// исчезает без единого признака. Тег узла несёт и тип, и номер строки.
package manifest

import (
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// nonStringKeyForms — шесть написаний, дающих ключ-НЕ-строку на gopkg.in/yaml.v3
// (ядро YAML 1.2). Перечень — предмет сценария MOD-MF-08, поэтому он выписан, а
// не выведен: выведенный из реализации совпал бы с ней при любой её ошибке.
var nonStringKeyForms = []struct {
	literal string // как ключ написан в документе
	tag     string // тег, который обязан увидеть разбор
}{
	{"true", "!!bool"},
	{"false", "!!bool"},
	{"null", "!!null"},
	{"~", "!!null"},
	{"123", "!!int"},
	{"0x1f", "!!int"},
}

// yaml11BooleanLooking — десять написаний, которые тело задачи называет ловушкой.
// На gopkg.in/yaml.v3 они СТРОКИ: булевость `on/off/yes/no/y/n` — свойство YAML 1.1,
// а ядро v3 читает YAML 1.2. Проверка, написанная по тексту задачи, была бы зелена
// всегда и не видела бы шести настоящих форм выше.
var yaml11BooleanLooking = []string{"on", "off", "yes", "no", "y", "n", "On", "OFF", "Yes", "NO"}

// parseDoc — корневой узел документа. Проба берёт узел тем же способом, что и
// загрузчик: иначе она утверждала бы о своём разборе, а не о его.
func parseDoc(t *testing.T, doc string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("разбор документа пробы: %v", err)
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 {
		t.Fatalf("документ пробы не дал одного корня")
	}
	return root.Content[0]
}

// ── MOD-MF-08 ───────────────────────────────────────────────────────────────

// TestMODMF08NonStringKeysAreRefusedByNodeTag — шесть форм, КАЖДАЯ отдельным
// утверждением, и каждый отказ называет номер строки.
func TestMODMF08NonStringKeysAreRefusedByNodeTag(t *testing.T) {
	for _, form := range nonStringKeyForms {
		t.Run(form.literal, func(t *testing.T) {
			// Ключ ставится на ГЛУБИНЕ и с законными соседями вокруг: испорчено
			// ровно одно свойство, форма остального годна.
			doc := "outer:\n  before: a\n  " + form.literal + ": b\n  after: c\n"
			faults := checkStringKeys(parseDoc(t, doc))
			if len(faults) != 1 {
				t.Fatalf("ключ %q: находок %d, ожидалась 1: %v", form.literal, len(faults), faults)
			}
			f := faults[0]
			if f.Line != 3 {
				t.Errorf("ключ %q: названа строка %d, написан на 3-й", form.literal, f.Line)
			}
			if f.Tag != form.tag {
				t.Errorf("ключ %q: тег %q, ожидался %q", form.literal, f.Tag, form.tag)
			}
			if !strings.Contains(f.Error(), "line "+strconv.Itoa(f.Line)) {
				t.Errorf("текст отказа не называет строку: %s", f.Error())
			}
		})
	}
}

// ── MOD-MF-09 ───────────────────────────────────────────────────────────────

// TestMODMF09QuotedTwinsAreSilent — законный близнец: те же шесть написаний В
// КАВЫЧКАХ молчат, и значения доступны под своими строковыми именами.
//
// Без этой пробы MOD-MF-08 зеленела бы на разборе, отвергающем ВСЯКИЙ ключ.
func TestMODMF09QuotedTwinsAreSilent(t *testing.T) {
	var b strings.Builder
	b.WriteString("outer:\n")
	for _, form := range nonStringKeyForms {
		b.WriteString("  \"" + form.literal + "\": v\n")
	}
	doc := b.String()

	if faults := checkStringKeys(parseDoc(t, doc)); len(faults) != 0 {
		t.Fatalf("ключи в кавычках объявлены нестроками: %v", faults)
	}
	t.Logf("перепись: написаний %d · находок 0", len(nonStringKeyForms))

	var got map[string]map[string]string
	if err := yaml.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	for _, form := range nonStringKeyForms {
		if _, ok := got["outer"][form.literal]; !ok {
			t.Errorf("значение под ключом %q недоступно: %v", form.literal, got["outer"])
		}
	}
	if len(got["outer"]) != len(nonStringKeyForms) {
		t.Errorf("ключей в карте %d, написано %d", len(got["outer"]), len(nonStringKeyForms))
	}
}

// ── MOD-MF-10 ───────────────────────────────────────────────────────────────

// TestMODMF10Yaml11BooleanLookingKeysStayStrings — `on`/`off`/`yes`/`no`/`y`/`n`
// НЕ отвергаются: на ядре YAML 1.2 они строки.
//
// Сценарий существует, чтобы неверная посылка не вернулась: проверка, написанная
// по тексту задачи, искала бы именно их — и была бы зелена всегда.
func TestMODMF10Yaml11BooleanLookingKeysStayStrings(t *testing.T) {
	var b strings.Builder
	b.WriteString("outer:\n")
	for _, k := range yaml11BooleanLooking {
		b.WriteString("  " + k + ": v\n")
	}
	doc := b.String()

	if faults := checkStringKeys(parseDoc(t, doc)); len(faults) != 0 {
		t.Fatalf("написания YAML 1.1 объявлены нестроками: %v", faults)
	}

	var got map[string]map[string]string
	if err := yaml.Unmarshal([]byte(doc), &got); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	for _, k := range yaml11BooleanLooking {
		if _, ok := got["outer"][k]; !ok {
			t.Errorf("ключ %q не доступен как строка: %v", k, got["outer"])
		}
	}
	if n := len(got["outer"]); n != len(yaml11BooleanLooking) {
		t.Fatalf("ключей в карте %d, написано %d — какие-то схлопнулись", n, len(yaml11BooleanLooking))
	}
	t.Logf("перепись: написаний %d · остались строками %d · находок 0",
		len(yaml11BooleanLooking), len(got["outer"]))
}

// ── MOD-MF-11 ───────────────────────────────────────────────────────────────

// TestMODMF11TwoWritingsOfOneKeyAreNamedBothNotCollapsed — `null:` и `~:` в одном
// отображении: названы ОБЕ строки, ни одно значение не потеряно молча.
//
// Замер, ради которого сценарий: разобранная карта схлопывает их в один ключ
// `nil`, и одно значение исчезает без единого признака. Проверка по тегу узла
// ловит это ДО схлопывания — по карте оно уже ненаблюдаемо, и проба утверждает
// обе половины сразу.
func TestMODMF11TwoWritingsOfOneKeyAreNamedBothNotCollapsed(t *testing.T) {
	doc := "outer:\n  null: first\n  ~: second\n"

	faults := checkStringKeys(parseDoc(t, doc))
	if len(faults) != 2 {
		t.Fatalf("находок %d, написано два ключа-нестроки: %v", len(faults), faults)
	}
	lines := map[int]bool{}
	for _, f := range faults {
		lines[f.Line] = true
	}
	if !lines[2] || !lines[3] {
		t.Errorf("названы не обе строки: %v", faults)
	}

	// Вторая половина: по карте предмета уже нет — доказательство того, что
	// проверка обязана стоять ДО приведения к типу, а не после.
	var collapsed map[string]map[any]any
	if err := yaml.Unmarshal([]byte(doc), &collapsed); err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if n := len(collapsed["outer"]); n != 1 {
		t.Fatalf("ожидалось схлопывание двух написаний в один ключ карты, получено %d", n)
	}
	t.Logf("перепись: написано ключей 2 · ключей карты %d · находок по тегу %d",
		len(collapsed["outer"]), len(faults))
}

// ── граница правила ─────────────────────────────────────────────────────────

// TestCheckStringKeysIsSilentOnTheRealManifest — контроль на настоящем документе.
//
// «Ноль находок» обязано быть отличимо от «ноль прочитанного», поэтому проба
// печатает объём осмотренного и падает, если отображений в документе не оказалось
// вовсе: молчание на пустом обходе доказывало бы лишь пустоту обхода.
func TestCheckStringKeysIsSilentOnTheRealManifest(t *testing.T) {
	data := mustReadFixture(t)
	root := parseDoc(t, string(data))

	seen := countMappingKeys(root)
	if seen == 0 {
		t.Fatalf("обход не прочитал ни одного ключа — молчание было бы беспредметным")
	}
	if faults := checkStringKeys(root); len(faults) != 0 {
		t.Fatalf("настоящий манифест объявлен несущим ключи-нестроки: %v", faults)
	}
	t.Logf("перепись: ключей отображений осмотрено %d · находок 0", seen)
}

// countMappingKeys — сколько ключей отображений обошла проверка. Считается
// НЕЗАВИСИМО от неё: счётчик внутри проверяемого кода сказал бы ровно то, что тот
// про себя думает.
func countMappingKeys(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	total := 0
	if n.Kind == yaml.MappingNode {
		total += len(n.Content) / 2
	}
	for _, c := range n.Content {
		total += countMappingKeys(c)
	}
	return total
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schemaconst_internal_test.go — `const` опубликованной схемы есть утверждение о
// ЗНАЧЕНИИ, и у каждого такого утверждения обязан быть исполнитель (задачи
// продукта #1953 и #1954).
//
// # Слепая зона, в которую попадали оба дефекта
//
// Согласие схемы и структур держит проба равенства КЛЮЧЕЙ
// (`schemaagreement_internal_test.go`, MOD-MF-21) — и это её объявленная
// граница, а не дефект. `const` же говорит не о ключе, а о значении, поэтому
// лежит ровно вне её наблюдения. Схема при этом судьёй не является и судьёй не
// станет (шапка пакета): значит `const` без исполнителя есть обещание, за
// которое никто не отвечает.
//
// Замер на ревизии заведения задач, обе стороны:
//
//	`const` в схеме                                     7
//	из них ТРЕБОВАНИЙ (не под `if`/`not`)               6
//	из них дискриминаторов условия                      1
//	вхождений в манифестах дерева, схеме ОТВЕЧАЮЩИХ     0  ← у трёх ключей дома посева
//	вхождений, схеме ПРОТИВОРЕЧАЩИХ                    15
//
// То есть схема объявляла невалидным КАЖДЫЙ существующий манифест: автор нового
// модуля, подключивший её в редакторе — а ровно для этого она и опубликована, —
// правил бы рабочий манифест в нерабочий по её указанию.
//
// # Почему свести схему и код к ОДНОМУ объявлению нельзя, и это замерено
//
// Оба пути закрыты, и закрыты не вкусом:
//
//   - загрузчик читает схему — библиотеки JSON Schema в дереве нет ни одной
//     (`grep -ci jsonschema go.mod` → 0), и заводить её значит сделать схему
//     ВТОРЫМ судьёй, что решением #1088 отвергнуто прямо;
//   - схема порождается из Go — она несёт 67 КБ рукописной прозы для человека,
//     и её порождение есть отдельный предмет, а не побочный эффект этой работы.
//
// Поэтому объявления остаются ДВА, а расхождение между ними держит ГЕЙТ — то,
// что и предписано, когда сведение к одному невозможно. Гейтов два, потому что
// исполнители у `const` бывают двух родов, и спрашиваются они по-разному:
// значение либо описывает ДЕРЕВО (и тогда его подтверждают манифесты), либо
// пиннуто ЗАГРУЗЧИКОМ (и тогда его подтверждает константа домена).
package manifest

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// treeManifestGlob — популяция гейта: манифесты модулей ДЕРЕВА.
//
// Фикстуры проб в популяцию НЕ входят, и это граница по существу, а не по
// удобству: часть из них заведомо невалидна by construction — инъекция обязана
// нарушать то, что проверяется, — и вердикт по ним был бы ложной находкой в
// каждом прогоне. Схема же описывает поставляемый артефакт, и именно его автор
// нового модуля берёт образцом.
const treeManifestGlob = "../../../../services/*/manifest.yaml"

// schemaConst — одно объявление `const` вместе с тем, как до него дошли.
type schemaConst struct {
	path        string // путь в нотации стороны структур: `seed.groups[].account`
	value       string
	conditional bool // достигнут через `if`/`not`
}

// walkSchemaConsts — все `const` схемы, ВЫВЕДЕННЫЕ обходом.
//
// Словарь ключевых слов берётся тот же, что у пробы равенства ключей: вторая
// копия разошлась бы с первой, и разошлась бы молча — `const`, спрятанный под
// словом, о котором знает лишь один из двух обходов, не дал бы ни красного, ни
// зелёного. Незнакомое слово ПАДАЕТ, а не пропускается.
//
// Условность отслеживается отдельно: `const` под `if` есть ДИСКРИМИНАТОР —
// условие, при котором применяется `then`, — а не требование к документу.
// Считать его требованием значило бы потребовать от каждой выдачи `target:
// resources`, тогда как выдачи дерева законно пишут `allInScope`; находка была
// бы ложной, а прибор, у которого находки ложные, перестают читать.
func walkSchemaConsts(node any, prefix, at string, cond bool, out *[]schemaConst, unknown *[]string) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	for _, keyword := range sortedKeys(obj) {
		value := obj[keyword]
		switch {
		case keyword == "const":
			s, isString := value.(string)
			if !isString {
				// Не находка и не молчание: `const` нестрокового типа этот
				// гейт судить не умеет, и он обязан сказать это вслух.
				*unknown = append(*unknown, at+": const не строка — сверять нечем")
				continue
			}
			*out = append(*out, schemaConst{path: prefix, value: s, conditional: cond})
		case keyword == "properties":
			props, ok := value.(map[string]any)
			if !ok {
				*unknown = append(*unknown, at+": properties не отображение")
				continue
			}
			for _, name := range sortedKeys(props) {
				walkSchemaConsts(props[name], joinPath(prefix, name), at+".properties."+name, cond, out, unknown)
			}
		case keyword == "additionalProperties":
			if _, isBool := value.(bool); isBool {
				continue
			}
			if _, isSchema := value.(map[string]any); !isSchema {
				*unknown = append(*unknown, at+": additionalProperties не false и не подсхема")
				continue
			}
			walkSchemaConsts(value, prefix+"{}", at+".additionalProperties", cond, out, unknown)
		case inSet(itemApplicators, keyword):
			walkSchemaConsts(value, prefix+"[]", at+"."+keyword, cond, out, unknown)
		case inSet(pathNeutralApplicators, keyword):
			// `if` и `not` переводят всё вложенное в УСЛОВИЕ; `then`/`else`
			// условность не наследуют — они требования своей ветви.
			walkSchemaConsts(value, prefix, at+"."+keyword, cond || keyword == "if" || keyword == "not", out, unknown)
		case inSet(pathNeutralLists, keyword):
			list, ok := value.([]any)
			if !ok {
				*unknown = append(*unknown, at+": "+keyword+" не список")
				continue
			}
			for i, sub := range list {
				walkSchemaConsts(sub, prefix, at+"."+keyword+"["+itoaLocal(i)+"]", cond, out, unknown)
			}
		case inSet(annotationKeywords, keyword):
			// Значение ограничивают, вглубь документа не ведут.
		default:
			*unknown = append(*unknown, at+": ключевое слово "+keyword+
				" распознавателю неизвестно — const в нём был бы вне наблюдения")
		}
	}
}

// resolveSchemaPath — все конкретные значения документа, стоящие по пути схемы.
//
// Нотация та же, что у стороны структур: `[]` — элемент списка, `{}` — значение
// карты. Отсутствие пути даёт пустой перечень, и это НЕ находка: подраздел
// манифеста не обязателен, а `const` описывает лишь то, что написано.
func resolveSchemaPath(node any, segments []string) []any {
	if len(segments) == 0 {
		return []any{node}
	}
	head, rest := segments[0], segments[1:]

	name := head
	var iterate string
	for _, suffix := range []string{"[]", "{}"} {
		if strings.HasSuffix(name, suffix) {
			name, iterate = strings.TrimSuffix(name, suffix), suffix
			break
		}
	}

	var at any
	if name == "" {
		at = node
	} else {
		obj, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		at, ok = obj[name]
		if !ok {
			return nil
		}
	}

	switch iterate {
	case "[]":
		list, ok := at.([]any)
		if !ok {
			return nil
		}
		var out []any
		for _, item := range list {
			out = append(out, resolveSchemaPath(item, rest)...)
		}
		return out
	case "{}":
		obj, ok := at.(map[string]any)
		if !ok {
			return nil
		}
		var out []any
		for _, key := range sortedKeys(obj) {
			out = append(out, resolveSchemaPath(obj[key], rest)...)
		}
		return out
	default:
		return resolveSchemaPath(at, rest)
	}
}

// splitSchemaPath — путь в сегменты. Суффиксы `[]`/`{}` остаются при сегменте,
// к которому относятся.
func splitSchemaPath(path string) []string {
	if path == "" {
		return nil
	}
	return strings.Split(path, ".")
}

// readTreeManifests — манифесты дерева, разобранные как YAML.
func readTreeManifests(t *testing.T) map[string]any {
	t.Helper()
	paths, err := filepath.Glob(treeManifestGlob)
	if err != nil {
		t.Fatalf("обход манифестов дерева не состоялся (%s): %v", treeManifestGlob, err)
	}
	out := map[string]any{}
	for _, p := range paths {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("манифест %s не прочитан: %v", p, err)
		}
		var doc any
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("манифест %s не разбирается как YAML: %v", p, err)
		}
		out[p] = normaliseYAML(doc)
	}
	return out
}

// normaliseYAML — приведение разобранного YAML к форме, которую понимает
// [resolveSchemaPath]: ключи карт становятся строками.
func normaliseYAML(node any) any {
	switch v := node.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = normaliseYAML(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[fmt.Sprint(k)] = normaliseYAML(item)
		}
		return out
	case []any:
		out := make([]any, 0, len(v))
		for _, item := range v {
			out = append(out, normaliseYAML(item))
		}
		return out
	default:
		return node
	}
}

// collectSchemaConsts — обход схемы с падением на непознанном.
func collectSchemaConsts(t *testing.T) []schemaConst {
	t.Helper()
	var consts []schemaConst
	var unknown []string
	walkSchemaConsts(readPublishedSchema(t), "", "$", false, &consts, &unknown)
	if len(unknown) > 0 {
		sort.Strings(unknown)
		t.Fatalf("обход схемы встретил непознанные формы (%d) — вердикт по ним не выносится, "+
			"и «ноль расхождений» означало бы «ноль прочитанного»:\n  %s",
			len(unknown), strings.Join(unknown, "\n  "))
	}
	if len(consts) == 0 {
		t.Fatalf("в схеме не прочитано ни одного const — обход пуст, и вердикт беспредметен: "+
			"«ноль находок» неотличимо от «ноль прочитанного» (схема %s)", publishedSchemaPath)
	}
	sort.Slice(consts, func(a, b int) bool { return consts[a].path < consts[b].path })
	return consts
}

// TestSchemaConstIsNotContradictedByTheTreeManifests — ни один `const` схемы не
// объявляет невалидным то, что дерево пишет (#1954).
//
// # Гейт судит КЛАСС, а не перечень имён
//
// Сверяется КАЖДЫЙ `const`, до которого дотягивается обход, а не три ключа,
// названные задачей. Перечень имён пережил бы свой предмет молча: новый `const`
// в схеме не попал бы под наблюдение и ничем бы этого не показал.
//
// # Что означает «ноль находок» — и что оно НЕ означает
//
// Перепись печатает ОБЕ величины: сколько вхождений сверено и сколько
// требований дерево не осуществляет вовсе. Второе — не находка: подраздел
// манифеста не обязателен, и `const` над ненаписанным разделом ничему не
// противоречит. Но и молчать о нём нельзя: он не подтверждён ничем.
func TestSchemaConstIsNotContradictedByTheTreeManifests(t *testing.T) {
	consts := collectSchemaConsts(t)
	manifests := readTreeManifests(t)
	if len(manifests) == 0 {
		t.Fatalf("манифестов дерева не прочитано ни одного (%s) — сверять не с чем, "+
			"и вердикт был бы о пустоте", treeManifestGlob)
	}

	audit := auditSchemaConsts(consts, manifests)

	t.Logf("перепись: манифестов дерева прочитано %d · const объявлено %d "+
		"(требований %d, дискриминаторов условия %d) · вхождений сверено %d · "+
		"схеме отвечает %d · требований, деревом не осуществляемых, %d",
		len(manifests), len(consts), audit.requirements, len(audit.discriminators),
		audit.compared, audit.agreeing, len(audit.unexercised))
	if len(audit.discriminators) > 0 {
		t.Logf("НЕ судятся (const под `if`/`not` — условие, а не требование): %s",
			strings.Join(audit.discriminators, "; "))
	}
	if len(audit.unexercised) > 0 {
		t.Logf("требования, которых дерево не осуществляет (не находка, но и не подтверждено): %s",
			strings.Join(audit.unexercised, "; "))
	}

	if audit.compared == 0 {
		t.Fatalf("сверено ноль вхождений при %d требованиях — гейт ничего не осмотрел, "+
			"и его молчание не является вердиктом", audit.requirements)
	}
	if len(audit.findings) > 0 {
		t.Fatalf("опубликованная схема противоречит дереву в %d вхождениях — автор, подключивший её "+
			"в редакторе, правил бы рабочий манифест в нерабочий:\n  %s",
			len(audit.findings), strings.Join(audit.findings, "\n  "))
	}
}

// schemaConstAudit — исход сверки, вынесенный из пробы.
//
// Вынесен не ради красоты: без него способность гейта УПАСТЬ доказывалась бы
// только порчей дерева, то есть прогоном, который в наборе не живёт и потому
// ничего не держит. Чистая функция позволяет подать инъекцию данными — и
// доказательство едет вместе с гейтом (см. schemaconst_injection_internal_test.go).
type schemaConstAudit struct {
	requirements   int
	discriminators []string
	compared       int
	agreeing       int
	unexercised    []string
	findings       []string
}

// auditSchemaConsts — сверка `const` схемы с тем, что пишут манифесты.
//
// Единственное место, где решается, что есть находка: и гейт, и его инъекция
// зовут ЭТУ функцию. Второй экземпляр сверки разошёлся бы с первым молча — и
// разошёлся бы там, где это не видно: оба отвечают «сходится» на сходящемся
// входе.
func auditSchemaConsts(consts []schemaConst, manifests map[string]any) schemaConstAudit {
	var out schemaConstAudit
	for _, c := range consts {
		if c.conditional {
			out.discriminators = append(out.discriminators, fmt.Sprintf("%s = %q", c.path, c.value))
			continue
		}
		out.requirements++
		segments := splitSchemaPath(c.path)
		hits := 0
		for _, file := range sortedKeys(manifests) {
			for _, got := range resolveSchemaPath(manifests[file], segments) {
				out.compared++
				hits++
				if fmt.Sprint(got) == c.value {
					out.agreeing++
					continue
				}
				out.findings = append(out.findings, fmt.Sprintf(
					"%s: %s = %v, а схема пинит const %q", file, c.path, got, c.value))
			}
		}
		if hits == 0 {
			out.unexercised = append(out.unexercised, fmt.Sprintf("%s = %q", c.path, c.value))
		}
	}
	sort.Strings(out.findings)
	return out
}

// TestSchemaAnchorConstAgreesWithTheLoaderConstants — `const` якоря выдачи равен
// тому, что пинит загрузчик (#1953).
//
// Второй род исполнителя: значение, которое дерево подтвердить не может, потому
// что подтверждает его ОТКАЗ. Свести два объявления к одному нельзя (см. шапку
// файла), поэтому расхождение держит этот гейт — и держит в обе стороны: правка
// константы домена без правки схемы краснеет ровно так же, как обратная.
func TestSchemaAnchorConstAgreesWithTheLoaderConstants(t *testing.T) {
	// Соответствие объявлено ОДИН раз и здесь: путь схемы против константы,
	// которую действительно читает отказ загрузчика.
	pinned := map[string]string{
		"seed.accessBindings[].scopeType": seedGrantAnchorScopeType,
		"seed.accessBindings[].scopeID":   seedGrantAnchorScopeID,
	}
	// Ключ схемы camelCase, константа — та же величина; выравниваем имя пути.
	pinned["seed.accessBindings[].scopeId"] = pinned["seed.accessBindings[].scopeID"]
	delete(pinned, "seed.accessBindings[].scopeID")

	consts := collectSchemaConsts(t)
	seen := map[string]string{}
	for _, c := range consts {
		if c.conditional {
			continue
		}
		if _, pinnedHere := pinned[c.path]; pinnedHere {
			seen[c.path] = c.value
		}
	}

	t.Logf("перепись: const объявлено %d · из них пиннутых загрузчиком ожидается %d · найдено %d",
		len(consts), len(pinned), len(seen))

	if len(seen) != len(pinned) {
		var missing []string
		for path := range pinned {
			if _, ok := seen[path]; !ok {
				missing = append(missing, path)
			}
		}
		sort.Strings(missing)
		t.Fatalf("схема больше не пинит якорь по путям %s — либо решение о якоре изменилось "+
			"(тогда правится и загрузчик), либо путь переехал и гейт ослеп; молча снять const нельзя",
			strings.Join(missing, ", "))
	}

	for path, want := range pinned {
		if seen[path] != want {
			t.Errorf("%s: схема пинит %q, загрузчик отвергает всё, кроме %q — "+
				"два объявления об одном предмете разошлись", path, seen[path], want)
		}
	}
}

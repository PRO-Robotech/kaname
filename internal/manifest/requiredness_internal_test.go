// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// requiredness_internal_test.go — согласие схемы и загрузчика по ТРЕБОВАТЕЛЬНОСТИ
// (задача PRO-Robotech/kacho#1840).
//
// # Чем этот гейт отличается от соседнего, и почему их два
//
// `schemaagreement_internal_test.go` сверяет СОСТАВ КЛЮЧЕЙ: что схема и
// структуры называют одно и то же множество полей. Это его объявленный предмет,
// и он верен — слова `required` и `minItems` стоят у его обходчика в перечне
// «не ведут вглубь» намеренно.
//
// Здесь судится другое: по каждому ключу, который схема объявила ОБЯЗАТЕЛЬНЫМ,
// проверяется, отвергает ли его отсутствие ЗАГРУЗЧИК. Состав совпасть может, а
// строгость разойтись — и тогда автор манифеста получает «манифест годен» от
// инструмента и отказ от продукта. Это класс «два правила об одном поле»
// (`api-conventions.md` §«Неисполнимая возможность»), только стороны расходятся
// не в наличии проверки, а в её строгости.
//
// # Перепись идёт ПРОД-ПУТЁМ, а не чтением кода загрузчика
//
// Вход портится в фикстуре РОВНО ДО ОБЪЯВЛЕННОЙ ГРАНИЦЫ — строка в `minLength`\n// минус один знак, список в `minItems` минус один элемент, — и приговор выносит\n// `Load`, тот самый исполнитель,
// которым судит `make -C services/iam module-manifest-check`. Проба, читающая
// исходник загрузчика на предмет «есть ли там проверка», утверждала бы о ТЕКСТЕ,
// а не об исходе: проверка, стоящая в недостижимой ветке, прошла бы её молча.
//
// # Три исхода по каждой оси, а не два
//
// «Вход не произведён» (в фикстуре нет места, которое надо испортить) НЕ
// зачитывается ни в согласие, ни в расхождение: это третья категория, и она
// печатается своим числом. Иначе «ноль расхождений» стало бы неотличимо от
// «ноль осмотренного» — ровно та беда, ради которой перепись и заводится.
//
// # Положительный контроль обязателен
//
// Без него отрицание зеленело бы на загрузчике, отвергающем ВСЁ: каждая порча
// давала бы отказ, и перепись рапортовала бы полное согласие. Поэтому нетронутая
// фикстура обязана грузиться, и это утверждается первым.
package manifest

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// requirement — одно объявление обязательности, снятое со схемы.
type requirement struct {
	// Path — путь ключа в документе: `roles[].tier.tierId`, `deprecatedVerbs.{}.class`.
	Path string
	// Kind — чем именно схема требует: наличием ключа либо величиной значения.
	Kind string
	// Bound — объявленный предел (`minItems`, `minLength`); для наличия — ноль.
	Bound int
	// At — координата объявления в схеме; попадает в текст находки.
	At string
}

const (
	// kindPresence — ключ обязан присутствовать (`required`).
	kindPresence = "required"
	// kindNonEmptyList — список обязан нести не менее `minItems` элементов.
	kindNonEmptyList = "minItems"
	// kindNonEmptyText — строка обязана нести не менее `minLength` знаков.
	kindNonEmptyText = "minLength"
)

// walkSchemaRequirements — сторона схемы, ВЫВЕДЕННАЯ обходом.
//
// Полярность и условность разведены намеренно, и обе разницы содержательны:
//
//   - под `not` слово `required` означает ОБРАТНОЕ — «ключа быть не должно».
//     Так схема отвергает снятые ключи (`seed.serviceAccount`, `seed.bindings`).
//     Прочитать это как требование значило бы потребовать от загрузчика
//     отвергать то, что он обязан принимать;
//   - под `if`/`then`/`else` требование УСЛОВНО: `resources` у выдачи обязателен
//     ровно при `target: resources`. Безусловная порча такой оси проверяла бы не
//     ту ветку, поэтому условные оси считаются отдельным числом, а не молча
//     отбрасываются.
func walkSchemaRequirements(node any, prefix, at string, negated, conditional bool,
	out *[]requirement, cond *[]requirement, unknown *[]string) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
	}
	emit := func(r requirement) {
		switch {
		case negated:
			// Отрицание: это отказ, а не требование.
		case conditional:
			*cond = append(*cond, r)
		default:
			*out = append(*out, r)
		}
	}
	for _, keyword := range sortedKeys(obj) {
		value := obj[keyword]
		switch {
		case keyword == "properties":
			props, ok := value.(map[string]any)
			if !ok {
				*unknown = append(*unknown, at+": properties не отображение")
				continue
			}
			for _, name := range sortedKeys(props) {
				path := joinPath(prefix, name)
				walkSchemaRequirements(props[name], path, at+".properties."+name,
					negated, conditional, out, cond, unknown)
			}
		case keyword == "required":
			list, ok := value.([]any)
			if !ok {
				*unknown = append(*unknown, at+": required не список")
				continue
			}
			for _, item := range list {
				name, ok := item.(string)
				if !ok {
					*unknown = append(*unknown, at+": элемент required не строка")
					continue
				}
				emit(requirement{Path: joinPath(prefix, name), Kind: kindPresence, At: at})
			}
		case keyword == "minItems":
			if n, ok := value.(float64); ok && n >= 1 {
				emit(requirement{Path: prefix, Kind: kindNonEmptyList, Bound: int(n), At: at})
			}
		case keyword == "minLength":
			if n, ok := value.(float64); ok && n >= 1 {
				emit(requirement{Path: prefix, Kind: kindNonEmptyText, Bound: int(n), At: at})
			}
		case keyword == "additionalProperties":
			if _, isSchema := value.(map[string]any); !isSchema {
				continue
			}
			walkSchemaRequirements(value, prefix+".{}", at+".additionalProperties",
				negated, conditional, out, cond, unknown)
		case inSet(itemApplicators, keyword):
			walkSchemaRequirements(value, prefix+"[]", at+"."+keyword,
				negated, conditional, out, cond, unknown)
		case keyword == "not":
			walkSchemaRequirements(value, prefix, at+".not", !negated, conditional, out, cond, unknown)
		case keyword == "if" || keyword == "then" || keyword == "else":
			walkSchemaRequirements(value, prefix, at+"."+keyword, negated, true, out, cond, unknown)
		case inSet(pathNeutralApplicators, keyword):
			walkSchemaRequirements(value, prefix, at+"."+keyword, negated, conditional, out, cond, unknown)
		case inSet(pathNeutralLists, keyword):
			list, ok := value.([]any)
			if !ok {
				*unknown = append(*unknown, at+": "+keyword+" не список")
				continue
			}
			for i, sub := range list {
				walkSchemaRequirements(sub, prefix, at+"."+keyword+"["+itoaLocal(i)+"]",
					negated, conditional, out, cond, unknown)
			}
		case inSet(annotationKeywords, keyword):
			// Значение ограничивают, обязательности не объявляют.
		default:
			*unknown = append(*unknown, at+": ключевое слово "+keyword+
				" распознавателю неизвестно — записанное в нём вне наблюдения")
		}
	}
}

// pathStep — один шаг пути ключа.
type pathStep struct {
	name     string
	intoSeq  bool
	anyValue bool
}

// boundText — объявленный предел в тексте находки. Без него «minLength» не
// говорит, ГДЕ проходит граница, и починка целится наугад.
func boundText(r requirement) string {
	if r.Bound == 0 {
		return ""
	}
	return " " + itoaLocal(r.Bound)
}

func parsePath(path string) []pathStep {
	steps := make([]pathStep, 0, 4)
	for _, seg := range strings.Split(path, ".") {
		switch {
		case seg == "":
			continue
		case seg == "{}":
			steps = append(steps, pathStep{anyValue: true})
		case strings.HasSuffix(seg, "[]"):
			steps = append(steps, pathStep{name: strings.TrimSuffix(seg, "[]"), intoSeq: true})
		default:
			steps = append(steps, pathStep{name: seg})
		}
	}
	return steps
}

// mapEntry — индекс ключа в содержимом узла-отображения; -1, если ключа нет.
func mapEntry(n *yaml.Node, key string) int {
	if n == nil || n.Kind != yaml.MappingNode {
		return -1
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return i
		}
	}
	return -1
}

// containersFor — узлы-отображения, в которых лежит ПОСЛЕДНИЙ шаг пути.
//
// Их может быть много (каждый элемент списка), и это не деталь: ось, чьё место
// в фикстуре встречается дважды, обязана портиться в одном месте — иначе отказ
// назвал бы два предмета там, где проверяется один.
func containersFor(doc *yaml.Node, steps []pathStep) []*yaml.Node {
	nodes := []*yaml.Node{doc}
	for _, st := range steps {
		next := make([]*yaml.Node, 0, len(nodes))
		for _, n := range nodes {
			switch {
			case st.anyValue:
				if n.Kind != yaml.MappingNode {
					continue
				}
				for i := 1; i < len(n.Content); i += 2 {
					next = append(next, n.Content[i])
				}
			default:
				idx := mapEntry(n, st.name)
				if idx < 0 {
					continue
				}
				value := n.Content[idx+1]
				if !st.intoSeq {
					next = append(next, value)
					continue
				}
				if value.Kind != yaml.SequenceNode {
					continue
				}
				next = append(next, value.Content...)
			}
		}
		nodes = next
	}
	return nodes
}

// violate портит РОВНО ОДНО место документа по требованию r.
//
// Возвращает false, если места нет: тогда вход не произведён, и вердикта по этой
// оси не выносится ни в одну сторону.
func violate(doc *yaml.Node, r requirement) bool {
	steps := parsePath(r.Path)
	if len(steps) == 0 {
		return false
	}
	last := steps[len(steps)-1]
	if last.anyValue {
		return false
	}
	for _, holder := range containersFor(doc, steps[:len(steps)-1]) {
		idx := mapEntry(holder, last.name)
		if idx < 0 {
			continue
		}
		value := holder.Content[idx+1]
		switch r.Kind {
		case kindPresence:
			holder.Content = append(holder.Content[:idx], holder.Content[idx+2:]...)
			return true
		case kindNonEmptyList:
			if value.Kind != yaml.SequenceNode || len(value.Content) < r.Bound {
				continue
			}
			value.Content = value.Content[:r.Bound-1]
			if len(value.Content) == 0 {
				value.Style = yaml.FlowStyle
			}
			return true
		case kindNonEmptyText:
			if value.Kind != yaml.ScalarNode {
				continue
			}
			value.Value = strings.Repeat("я", r.Bound-1)
			value.Tag = "!!str"
			value.Style = yaml.DoubleQuotedStyle
			return true
		}
	}
	return false
}

// requirednessFixtures — фикстуры, на которых производится вход.
//
// Их четыре, потому что разделы и ветки у них разные: оси раздела `seed.joins` в
// фикстуре ресурсов места не имеют вовсе, а ветка выдачи с перечнем объектов
// (`target: resources`) не встречается ни в одной из первых двух, а указатель,
// ярус и действие записаны там КОРОТКОЙ формой, у которой обязательных ключей
// нет вовсе. Ось считается
// произведённой, если её удалось испортить ХОТЯ БЫ В ОДНОЙ; иначе она попадает
// в третью категорию под своим именем — и это повод завести фикстуру, а не
// повод промолчать.
var requirednessFixtures = []string{
	"testdata/vpc.resources-fixture.yaml",
	"testdata/vpc.seed-fixture.yaml",
	"testdata/vpc.binding-resources-fixture.yaml",
	"testdata/vpc.long-forms-fixture.yaml",
}

func readFixtureDoc(t *testing.T, path string) (*yaml.Node, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("фикстура %s не прочитана: %v — портить нечего, и «ноль расхождений» "+
			"означало бы «ноль осмотренного»", path, err)
	}
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatalf("фикстура %s не разбирается: %v", path, err)
	}
	if len(root.Content) == 0 {
		t.Fatalf("фикстура %s пуста", path)
	}
	return root.Content[0], raw
}

// TestSchemaAndLoaderAgreeOnRequiredness — по каждой оси, объявленной схемой
// обязательной, загрузчик обязан отвергнуть вход, где её нет либо она пуста.
func TestSchemaAndLoaderAgreeOnRequiredness(t *testing.T) {
	var required, conditional []requirement
	var unknown []string
	walkSchemaRequirements(readPublishedSchema(t), "", "$", false, false,
		&required, &conditional, &unknown)
	if len(unknown) > 0 {
		t.Fatalf("распознаватель схемы не знает %d форм — его вердикт был бы свойством "+
			"обхода, а не документа:\n  %s", len(unknown), strings.Join(unknown, "\n  "))
	}

	// Различные оси: один и тот же ключ схема законно называет дважды (в
	// `properties` и в перечне `required` родителя). Считая объявления за оси,
	// перепись назвала бы число, которого в документе нет.
	seen := map[string]requirement{}
	for _, r := range required {
		key := r.Path + "|" + r.Kind + "|" + itoaLocal(r.Bound)
		if _, dup := seen[key]; !dup {
			seen[key] = r
		}
	}
	axes := make([]requirement, 0, len(seen))
	for _, r := range seen {
		axes = append(axes, r)
	}
	sort.Slice(axes, func(i, j int) bool {
		if axes[i].Path != axes[j].Path {
			return axes[i].Path < axes[j].Path
		}
		if axes[i].Kind != axes[j].Kind {
			return axes[i].Kind < axes[j].Kind
		}
		return axes[i].Bound < axes[j].Bound
	})

	if len(axes) == 0 {
		t.Fatal("схема не объявила НИ ОДНОЙ обязательной оси — обход пуст, вердикт беспредметен")
	}

	// Положительный контроль: нетронутая фикстура обязана грузиться. Без него
	// отрицание зеленело бы на загрузчике, отвергающем всё.
	for _, path := range requirednessFixtures {
		_, raw := readFixtureDoc(t, path)
		if _, err := Load(raw); err != nil {
			t.Fatalf("положительный контроль: законная фикстура %s отвергнута загрузчиком: %v — "+
				"отрицания на таком входе ничего не утверждают", path, err)
		}
	}

	var divergences, notProduced []string
	produced := 0
	for _, r := range axes {
		madeInput := false
		// Отказ требуется в КАЖДОЙ фикстуре, где вход произведён, а не в одной.
		// Обязательность безусловна: документ, в котором ключа нет, обязан быть
		// отвергнут ВСЕГДА. Довольствуйся проба одним отказом — и ось, которую
		// загрузчик отвергает лишь по СМЕЖНОЙ причине в одном разделе, читалась
		// бы как проверенная, а в другом разделе проходила бы молча.
		refused := true
		accepted := ""
		for _, path := range requirednessFixtures {
			doc, _ := readFixtureDoc(t, path)
			if !violate(doc, r) {
				continue
			}
			madeInput = true
			broken, err := yaml.Marshal(doc)
			if err != nil {
				t.Fatalf("испорченный документ не сериализуется (%s %s): %v", r.Path, r.Kind, err)
			}
			if _, err := Load(broken); err == nil {
				refused = false
				accepted = path
			}
		}
		switch {
		case !madeInput:
			notProduced = append(notProduced, fmt.Sprintf("%s (%s%s) — места в фикстурах нет; объявлено %s",
				r.Path, r.Kind, boundText(r), r.At))
		case refused:
			produced++
		default:
			produced++
			divergences = append(divergences, fmt.Sprintf(
				"%s (%s%s): схема требует, загрузчик ПРИНИМАЕТ (%s) — объявлено %s",
				r.Path, r.Kind, boundText(r), accepted, r.At))
		}
	}

	t.Logf("перепись требовательности: осей схемы %d · вход произведён %d · расхождений %d · "+
		"вход не произведён %d · условных осей (не судятся) %d",
		len(axes), produced, len(divergences), len(notProduced), len(conditional))
	for _, s := range notProduced {
		t.Logf("вход не произведён: %s", s)
	}

	if len(divergences) > 0 {
		sort.Strings(divergences)
		t.Fatalf("схема и загрузчик расходятся по требовательности на %d осях из %d осмотренных — "+
			"автор получает «манифест годен» от инструмента и отказ от продукта:\n  %s",
			len(divergences), produced, strings.Join(divergences, "\n  "))
	}
}

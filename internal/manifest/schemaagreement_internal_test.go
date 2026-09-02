// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// schemaagreement_internal_test.go — СОГЛАСИЕ опубликованной схемы и Go-структур
// (MOD-MF-21, MOD-MF-22; приёмка §5.6).
//
// # Зачем это вообще нужно
//
// Форму манифеста судит ОДИН исполнитель — разбор в Go-структуры (§2.1). Схема
// вторым судьёй не является и судьёй не станет: она КОНТРАКТ для автора
// манифеста и его редактора. Ровно поэтому её и можно держать рядом со
// структурами — но только вместе с этой пробой.
//
// Без неё два места об одном предмете разойдутся, и разойдутся МОЛЧА: оба
// отвечают «валидно» на валидном входе, а расходятся только на невалидном.
// Автор, у которого редактор молчит, узнаёт о расхождении отказом загрузчика в
// конвейере — то есть позже всех и дороже всех.
//
// # Почему РАВЕНСТВО множеств, а не членство
//
// Членство уже подводило в этом самом дереве: проба закрытого набора модулей
// утверждала членство, не сопротивлялась росту набора, и комментарий рядом
// разошёлся с литералом молча (см. domain/module_set.go). Членство ловит только
// одну сторону расхождения; ключ схемы, которого нет в структурах, — такая же
// ложь контракта, как поле структур, которого нет в схеме.
//
// # Распознаватель схемы обязан знать ВСЕ формы, в которых объявляют ключ
//
// Форма, о которой обход не знает, не даёт ни красного, ни зелёного — она
// МОЛЧИТ, и всё записанное в ней оказывается вне наблюдения (`testing.md`
// §«Гейт на класс», п. 7). Поэтому обход не пропускает незнакомое слово, а
// ПАДАЕТ на нём с именем ключевого слова и координатой: список известных форм
// ведётся явно, и его расширение — осознанная правка, а не умолчание.
package manifest

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

// publishedSchemaPath — опубликованный контракт. Лежит ВНЕ `internal/`
// намеренно: `internal` есть правило видимости Go, а контракт, который читает
// автор манифеста и его редактор, не вправе читаться как внутренний.
const publishedSchemaPath = "../../schema/module-manifest.schema.json"

// schemaShapeKeywords — ключевые слова, ведущие ВГЛУБЬ документа, и то, как они
// меняют путь. Пустая строка — путь не меняется (применители), "[]" — элемент
// списка, ключ "" в значении обозначает особую обработку `properties`.
var (
	// pathNeutralApplicators — подсхемы, применяемые к тому же месту документа.
	pathNeutralApplicators = []string{"if", "then", "else", "not"}
	// pathNeutralLists — списки подсхем, применяемых к тому же месту.
	pathNeutralLists = []string{"allOf", "anyOf", "oneOf"}
	// itemApplicators — подсхемы, применяемые к ЭЛЕМЕНТУ списка.
	itemApplicators = []string{"items", "contains"}
	// annotationKeywords — слова, не ведущие вглубь: они ограничивают значение
	// либо описывают его человеку. Перечень ЯВНЫЙ: незнакомое слово обязано
	// ронять обход, а не молча пропускаться.
	annotationKeywords = []string{
		"$schema", "$id", "$comment", "title", "description",
		"type", "enum", "const", "pattern", "format", "default", "examples",
		"required", "minItems", "maxItems", "uniqueItems", "maxProperties",
		"minLength", "maxLength", "minimum", "maximum",
	}
)

func inSet(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func joinPath(prefix, name string) string {
	if prefix == "" {
		return name
	}
	return prefix + "." + name
}

// walkSchemaKeys — пути ключей, ОБЪЯВЛЕННЫХ схемой. Соглашение о пути то же,
// что у стороны структур: элемент списка обозначается суффиксом `[]`, поэтому
// `seed.groups` (сам список) и `seed.groups[].name` (поле элемента) — разные
// пути. Склейка скрыла бы расхождение по одному из двух.
//
// Второй возвращаемый список — НЕРАСПОЗНАННЫЕ формы: слово, о котором обход не
// знает, есть его слепая зона, и вердикт о ней выносить нельзя.
func walkSchemaKeys(node any, prefix, at string, paths *[]string, unknown *[]string) {
	obj, ok := node.(map[string]any)
	if !ok {
		return
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
				*paths = append(*paths, path)
				walkSchemaKeys(props[name], path, at+".properties."+name, paths, unknown)
			}
		case keyword == "additionalProperties":
			// Форм у этого слова ДВЕ, и обе законны — распознаватель обязан
			// знать обе, иначе записанное во второй окажется вне наблюдения
			// (`testing.md` §«Гейт на класс», п. 7):
			//
			//   false      отображение ЗАКРЫТО: у него именованные ключи, и
			//              безымянный структурам невыразим;
			//   подсхема   отображение есть КАРТА: ключ — данные (имя глагола),
			//              а подсхема описывает ЗНАЧЕНИЕ. Путь получает суффикс
			//              `{}` — тот же, что даёт стороне структур `map[…]T`.
			//
			// Вторая форма заведена вместе с разделом `deprecatedVerbs` (#1778);
			// до него закрытым обязано было быть КАЖДОЕ отображение, и это было
			// верно ровно пока карт в манифесте не было.
			if allowed, isBool := value.(bool); isBool {
				if allowed {
					*unknown = append(*unknown, at+": additionalProperties true — "+
						"схема перестала быть закрытой, и неизвестный ключ проходил бы её молча")
				}
				continue
			}
			if _, isSchema := value.(map[string]any); !isSchema {
				*unknown = append(*unknown, at+": additionalProperties не false и не подсхема")
				continue
			}
			walkSchemaKeys(value, prefix+"{}", at+".additionalProperties", paths, unknown)
		case inSet(itemApplicators, keyword):
			walkSchemaKeys(value, prefix+"[]", at+"."+keyword, paths, unknown)
		case inSet(pathNeutralApplicators, keyword):
			walkSchemaKeys(value, prefix, at+"."+keyword, paths, unknown)
		case inSet(pathNeutralLists, keyword):
			list, ok := value.([]any)
			if !ok {
				*unknown = append(*unknown, at+": "+keyword+" не список")
				continue
			}
			for i, sub := range list {
				walkSchemaKeys(sub, prefix, at+"."+keyword+"["+itoaLocal(i)+"]", paths, unknown)
			}
		case inSet(annotationKeywords, keyword):
			// Значение ограничивают, вглубь документа не ведут.
		default:
			*unknown = append(*unknown, at+": ключевое слово "+keyword+
				" распознавателю неизвестно — записанное в нём вне наблюдения")
		}
	}
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func itoaLocal(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// readPublishedSchema — опубликованная схема, разобранная как JSON.
func readPublishedSchema(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(publishedSchemaPath)
	if err != nil {
		t.Fatalf("опубликованная схема не прочитана (%s): %v — сличать нечего, "+
			"и «ноль расхождений» означало бы «ноль прочитанного»", publishedSchemaPath, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("опубликованная схема не разбирается как JSON: %v", err)
	}
	return doc
}

// schemaKeyPaths — сторона схемы, ВЫВЕДЕННАЯ обходом, а не выписанная.
//
// Возвращает РАЗЛИЧНЫЕ пути и, отдельно, число ОБЪЯВЛЕНИЙ. Две величины, а не
// одна, потому что единицы счёта разные: один и тот же ключ законно называется
// схемой дважды — например `target` в `properties` и он же в условии `if`,
// решающем, обязателен ли перечень объектов. Считая объявления за ключи, проба
// печатала «ключей схемы 33 · полей структур 30 · сошлось 33» при нуле
// расхождений — арифметика, которая сама себя опровергает, и читатель ищет
// расхождение, которого нет.
func schemaKeyPaths(t *testing.T) (paths []string, declarations int) {
	t.Helper()
	var raw, unknown []string
	walkSchemaKeys(readPublishedSchema(t), "", "$", &raw, &unknown)
	if len(unknown) > 0 {
		t.Fatalf("распознаватель схемы не знает %d форм — его вердикт был бы "+
			"свойством обхода, а не документа:\n  %s",
			len(unknown), strings.Join(unknown, "\n  "))
	}
	seen := map[string]bool{}
	for _, p := range raw {
		if seen[p] {
			continue
		}
		seen[p] = true
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return paths, len(raw)
}

// TestMODMF21SchemaAndStructsDeclareTheSameKeys — множества РАВНЫ.
//
// Расхождение называется ПОИМЁННО и с обеих сторон: «не совпало» посылает
// читателя сличать два списка руками, а имя пути ведёт прямо к правке.
func TestMODMF21SchemaAndStructsDeclareTheSameKeys(t *testing.T) {
	schemaPaths, declarations := schemaKeyPaths(t)
	structPaths := fieldPaths()

	if len(schemaPaths) == 0 {
		t.Fatal("обход схемы не дал ни одного ключа — сличать нечего")
	}
	if len(structPaths) == 0 {
		t.Fatal("обход структур не дал ни одного пути — сличать нечего")
	}

	inSchema := map[string]bool{}
	for _, p := range schemaPaths {
		inSchema[p] = true
	}
	inStructs := map[string]bool{}
	for _, p := range structPaths {
		inStructs[p] = true
	}

	var onlySchema, onlyStructs []string
	agreed := 0
	for _, p := range schemaPaths {
		if inStructs[p] {
			agreed++
			continue
		}
		onlySchema = append(onlySchema, p)
	}
	for _, p := range structPaths {
		if !inSchema[p] {
			onlyStructs = append(onlyStructs, p)
		}
	}

	for _, p := range onlySchema {
		t.Errorf("ключ схемы %q не объявлен структурами: автор манифеста напишет "+
			"его по контракту, а загрузчик отвергнет как неизвестное поле", p)
	}
	for _, p := range onlyStructs {
		t.Errorf("поле структур %q не объявлено схемой: загрузчик его примет, а "+
			"редактор автора о нём не знает и подсказать не сможет", p)
	}

	t.Logf("перепись: объявлений ключей в схеме %d · из них различных %d · "+
		"полей структур %d · сошлось %d · только в схеме %d · только в структурах %d",
		declarations, len(schemaPaths), len(structPaths), agreed,
		len(onlySchema), len(onlyStructs))
}

// TestMODMF21PublishedSchemaLivesOutsideInternal — два адреса, а не один.
//
// Загрузчик внутри `services/iam/internal/manifest` (эта проба тем и
// исполняется, что лежит в нём), схема — вне `internal/`. Контракт, который
// читает автор манифеста, не вправе читаться как внутренний.
func TestMODMF21PublishedSchemaLivesOutsideInternal(t *testing.T) {
	if _, err := os.Stat(publishedSchemaPath); err != nil {
		t.Fatalf("схемы нет по объявленному адресу %s: %v", publishedSchemaPath, err)
	}
	for _, segment := range strings.Split(publishedSchemaPath, "/") {
		if segment == "internal" {
			t.Fatalf("опубликованная схема лежит под internal/ (%s) — её потребитель "+
				"вне Go, и правило видимости Go для неё не действует", publishedSchemaPath)
		}
	}
	t.Logf("перепись адресов: загрузчик — services/iam/internal/manifest, "+
		"опубликованная схема — %s", publishedSchemaPath)
}

// TestMODMF22EverySchemaKeyHasAReader — у каждого ключа схемы есть читатель в
// прод-коде загрузчика.
//
// Ключ без читателя — «принято-и-проигнорировано» на уровне контракта: продукт
// обещает возможность, которой нет. Единица счёта — прод-файлов-читателей, шт.
func TestMODMF22EverySchemaKeyHasAReader(t *testing.T) {
	prod := prodSourcesOfThisPackage(t)
	if len(prod) == 0 {
		t.Fatal("прод-файлов пакета ноль — «ноль ключей без читателя» было бы " +
			"свойством обхода, а не дерева")
	}

	schemaPaths, _ := schemaKeyPaths(t)
	leaves := map[string]bool{}
	for _, p := range schemaPaths {
		leaves[p[strings.LastIndexByte(p, '.')+1:]] = true
	}
	if len(leaves) == 0 {
		t.Fatal("ключей схемы ноль — проверять нечего")
	}

	names := make([]string, 0, len(leaves))
	for name := range leaves {
		names = append(names, name)
	}
	sort.Strings(names)

	readers := 0
	for _, name := range names {
		needle := `"` + name + `"`
		found := 0
		for _, body := range prod {
			if strings.Contains(body, needle) {
				found++
			}
		}
		if found == 0 {
			t.Errorf("ключ схемы %q не читает ни один прод-файл загрузчика: контракт "+
				"обещает то, чего разбор не принимает", name)
			continue
		}
		readers++
	}
	t.Logf("перепись: прод-файлов пакета %d · различных ключей схемы %d · "+
		"с читателем %d", len(prod), len(names), readers)
}

// prodSourcesOfThisPackage — не-тестовые исходники пакета загрузчика.
func prodSourcesOfThisPackage(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("каталог пакета не прочитан: %v", err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("%s не прочитан: %v", name, err)
		}
		out = append(out, string(body))
	}
	return out
}

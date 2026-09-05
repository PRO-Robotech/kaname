// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// docexample_internal_test.go — пример, который документ ОБЕЩАЕТ оператору,
// обязан приниматься загрузчиком (задача #2015).
//
// # Предмет — измеренный, а не предположенный
//
// `services/iam/MODEL-MANIFEST.md` — документ, который читает оператор чужого
// облака. До этой работы он приводил ДВА отказа дословно («модуль вне закрытого
// платформенного набора», «типа … нет в закрытой таблице типов iam») и объявлял
// закрытыми оба набора. Оба замка к тому моменту были сняты полосами #1927 и
// #2015, а тексты отказов продукт не производил ни одним путём — предикат по
// коду давал НОЛЬ вхождений. Заметить это было нечем: документ ничем не
// держался, и его обещание пережило свой предмет молча.
//
// # Почему проба судит ВХОД, а не текст документа
//
// Сверять прозу с деревом нельзя ничем — «закрыт ли набор» есть утверждение о
// смысле. Зато пример манифеста есть ВХОД, и у него ровно один исход: загрузчик
// его принимает либо нет. Поэтому документ помечает свои примеры маркером, а
// проба подаёт помеченное загрузчику.
//
// # Почему МАРКЕР, а не перечень блоков
//
// В документе есть и второй вид блока — эскиз формы (§2), где ключи стоят рядом
// с многоточиями и заглушками. Он загрузчику не подаётся и подаваться не должен.
// Отобрать нужные перечнем номеров значило бы завести второе место об одном
// предмете, которое разойдётся с документом при первой же правке; отобрать «по
// виду» — гадать. Маркер объявляет намерение ЯВНО, читается автором документа и
// переезжает вместе с блоком.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// docExampleMarker — маркер, которым документ объявляет: блок ниже обязан
// приниматься загрузчиком.
const docExampleMarker = "<!-- проба-загрузчика:"

// operatorFacingDocs — документы, чьи помеченные примеры судятся этой пробой.
//
// Перечень короткий и выписан намеренно: документов, адресованных оператору
// чужого облака, единицы, и обход всего дерева markdown добавил бы к предмету
// разбор чужих текстов, ничего не дав. Появится третий — его добавят сюда, и
// пустой перечень проба отвергает сама.
var operatorFacingDocs = []string{
	"services/iam/MODEL-MANIFEST.md",
}

// TestDocumentedOperatorManifestsAreAcceptedByTheLoader — каждый помеченный
// пример принимается загрузчиком той же полосой, что читает доставку.
func TestDocumentedOperatorManifestsAreAcceptedByTheLoader(t *testing.T) {
	if len(operatorFacingDocs) == 0 {
		t.Fatal("перечень документов пуст — обход беспредметен, «ноль находок» получено даром")
	}
	root := repoRootForPeek(t)

	docsRead, blocksFound := 0, 0
	for _, rel := range operatorFacingDocs {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatalf("%s: документ не прочитан: %v — непрочитанное есть НАХОДКА, "+
				"а не «проверять нечего»", rel, err)
		}
		docsRead++

		for i, block := range markedYAMLBlocks(string(raw)) {
			blocksFound++
			m, lerr := Load([]byte(block))
			if lerr != nil {
				t.Errorf("%s, помеченный пример %d: документ ОБЕЩАЕТ оператору вход, "+
					"который загрузчик отвергает:\n%v\n\nвход:\n%s", rel, i, lerr, block)
				continue
			}
			if m.Module == "" {
				t.Errorf("%s, помеченный пример %d: разобран без имени модуля — "+
					"пример обещает то, чего не показывает", rel, i)
			}
		}
	}

	if blocksFound == 0 {
		t.Fatalf("документов прочитано %d, помеченных примеров НОЛЬ — обход беспредметен: "+
			"«ноль находок» здесь неотличимо от «маркер переименовали, и проба замолчала»",
			docsRead)
	}
	t.Logf("перепись: документов прочитано %d, помеченных примеров подано загрузчику %d",
		docsRead, blocksFound)
}

// TestDocExampleExtractorSeesBothSides — распознаватель обязан УМЕТЬ отличить
// помеченный блок от непомеченного.
//
// Без этого утверждение выше зеленело бы на выделителе, не находящем ничего:
// «примеров ноль» роняет прогон, но «нашёл не тот блок» — нет.
func TestDocExampleExtractorSeesBothSides(t *testing.T) {
	const doc = "текст\n\n```yaml\nэскиз: не подаётся\n```\n\n" +
		docExampleMarker + " держатель -->\n\n```yaml\napiVersion: iam/v1\nmodule: acme\n```\n\n" +
		"хвост\n"

	got := markedYAMLBlocks(doc)
	if len(got) != 1 {
		t.Fatalf("помеченных блоков найдено %d, ожидался 1 — выделитель либо не видит "+
			"маркера, либо берёт всё подряд: %q", len(got), got)
	}
	if !strings.Contains(got[0], "module: acme") || strings.Contains(got[0], "эскиз") {
		t.Fatalf("взят не тот блок: %q", got[0])
	}

	// Вторая сторона: документ БЕЗ маркера не даёт ни одного блока.
	if got := markedYAMLBlocks("```yaml\nэскиз: не подаётся\n```\n"); len(got) != 0 {
		t.Fatalf("непомеченный блок подан загрузчику: %q", got)
	}
}

// markedYAMLBlocks — тела ограждённых блоков `yaml`, ПЕРЕД которыми стоит
// маркер, до ближайшего блока.
//
// Маркер ищется в строках между блоками, а не «где-то выше»: иначе один маркер
// пометил бы все последующие блоки документа разом.
func markedYAMLBlocks(doc string) []string {
	var out []string
	lines := strings.Split(doc, "\n")
	marked := false
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		switch {
		case strings.HasPrefix(line, docExampleMarker):
			marked = true
		case line == "```yaml":
			var body []string
			i++
			for ; i < len(lines) && strings.TrimSpace(lines[i]) != "```"; i++ {
				body = append(body, lines[i])
			}
			if marked {
				out = append(out, strings.Join(body, "\n")+"\n")
			}
			marked = false
		case strings.HasPrefix(line, "```"):
			marked = false
		}
	}
	return out
}

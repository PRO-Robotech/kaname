// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// read_path_concat_test.go — ГЕЙТ КЛАССА: на пути чтения нет условия,
// сравнивающего склейку колонки (задача #17, порт семейства `readpathconcat`).
//
// Предмет, границы разбора и довод в пользу обхода дерева — в шапке
// `read_path_concat.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// read_path_concat_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestReadPathComparesColumnsNotConcatenations — имя сохранено дословно с
// монорепо.
func TestReadPathComparesColumnsNotConcatenations(t *testing.T) {
	t.Parallel()

	root, _ := platformtree.RequireCorpus(t)
	resolve := func(rel string) (string, error) { return platformtree.PathUnder(root, rel) }

	files, dirs, err := check.ReadPathGoFiles(resolve)
	if err != nil {
		t.Fatalf("объём гейта выведен быть не может: %v — «ноль находок» означало бы "+
			"«ноль прочитанного»", err)
	}
	if len(dirs) == 0 {
		t.Fatalf("в %s не нашлось ни одного объявления каталога предмета замера: объём гейта "+
			"выведен быть не может", check.FingerprintSourceRel)
	}
	if len(files) == 0 {
		t.Fatalf("каталоги предмета замера (%s) не дали НИ ОДНОГО не-тестового .go: судить "+
			"нечего, и молчание гейта означало бы свойство, которого никто не проверял",
			strings.Join(dirs, ", "))
	}

	findings, c, err := check.CollectPredicateConcats(files, os.ReadFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	if c.Files == 0 || c.Literals == 0 || c.Segments == 0 {
		t.Fatalf("предпосылка гейта не выполнена: файлов %d, литералов с SQL %d, условных "+
			"сегментов %d. «Ноль находок» тогда означает «ноль прочитанного»",
			c.Files, c.Literals, c.Segments)
	}
	// ЗАКОННЫЙ БЛИЗНЕЦ ОБЯЗАН ПРИСУТСТВОВАТЬ. Склейка в ПРОЕКЦИИ законна и в
	// этих же файлах живёт. Если гейт её не встретил, значит он либо не дочитал
	// до неё, либо считает её условием — и тогда его молчание о находках ничего
	// не стоит.
	if c.ConcatsElsewhere == 0 {
		t.Fatal("в осмотренном не встретилось НИ ОДНОЙ склейки вне условия, а они там есть " +
			"(проекции обратных вопросов). Гейт либо не дочитал, либо не отличает проекцию от " +
			"условия — и его молчание о находках ничего не стоит")
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: каталогов выведено %d (%s), файлов %d, литералов с SQL %d, "+
		"условных сегментов %d, склеек в условии %d, склеек вне условия (законный близнец) %d, "+
		"находок %d",
		len(dirs), strings.Join(dirs, ", "), c.Files, c.Literals, c.Segments,
		c.ConcatsInPredicate, c.ConcatsElsewhere, len(findings))

	for _, f := range findings {
		t.Errorf("%s:%d: условие сравнивает СКЛЕЙКУ колонки: %s\n"+
			"    Склейка выводит колонку из-под индекса: сравнивается вычисленное значение, а оно "+
			"отбирает строки только ПОСЛЕ чтения. Ответ тот же, стоимость растёт с числом строк в "+
			"системе.\n    Разбери значение ДО сравнения и зайди голыми колонками.",
			f.File, f.Line, f.Operand)
	}
}

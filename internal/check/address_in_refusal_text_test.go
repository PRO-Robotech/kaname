// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// address_in_refusal_text_test.go — гейт ДЕРЕВА: ни один приёмник отказа и
// журнала не получает адрес почты участника (задача kaname#641).
//
// Предмет, перечень приёмников, формы адреса и слепые зоны — в шапке ядра
// (`address_in_refusal_text.go`); здесь они не пересказываются.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestNoRefusalTextOrJournalRecordCarriesAnAddress(t *testing.T) {
	t.Parallel()

	root := moduleRoot(t)
	files, err := treecorpus.UnderWithSuffix(root, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не взят: %v", err)
	}

	census, findings, err := check.ScanAddressInRefusalText(root, files)
	if err != nil {
		t.Fatalf("%v", err)
	}
	t.Log(census.String())

	if census.Files == 0 {
		t.Fatalf("обход не разобрал НИ ОДНОГО файла Go под %s — вердикт беспредметен", root)
	}
	// Предпосылка: приёмники обоих видов в дереве есть. Ноль означает, что
	// распознаватель перестал их узнавать, и его молчание неотличимо от чистоты.
	for _, kind := range []string{"отказ", "журнал", "подсказка"} {
		if census.Sinks[kind] == 0 {
			t.Fatalf("приёмников вида %q НОЛЬ при %d разобранных файлах — распознаватель "+
				"перестал их узнавать", kind, census.Files)
		}
	}

	if len(findings) == 0 {
		return
	}
	var b strings.Builder
	for _, f := range findings {
		fmt.Fprintf(&b, "\n  %s", f)
	}
	t.Errorf("адрес почты уезжает в текст отказа или в журнал (%d):%s\n\n"+
		"Адрес — личные данные и изменяемое значение; текст отказа уезжает вызывающему "+
		"и во все журналы по пути. Корреляцию несёт неизменяемый идентификатор: "+
		"называйте субъекта его id, а адрес оставьте хранилищу.",
		len(findings), b.String())
}

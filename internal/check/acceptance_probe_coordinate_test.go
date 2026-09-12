// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_probe_coordinate_test.go — TestAcceptanceProbeCoordinateResolves:
// гейт класса «утверждение, пережившее свой предмет», в его самой проверяемой
// форме — адрес, названный документом, обязан существовать.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `acceptance_probe_coordinate_injection_test.go`.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestAcceptanceProbeCoordinateResolves(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = corpusRoot + "/" + modulePrefix
	}

	docs, err := check.AcceptanceDocsOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмки не прочитаны: %v", err)
	}
	declared, err := check.DeclaredProbesOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: объявления проб не прочитаны: %v", err)
	}
	c := check.JudgeProbeCoordinates(docs, declared, check.AcceptanceProbeCoordinateExemptions)

	t.Logf("осмотрено: приёмок %d · объявлений проб в дереве %d · координат %d · "+
		"резолвится %d · по ведомости %d · находок %d",
		c.Docs, c.Declared, c.Coordinates, c.Resolved, c.Exempted, len(c.Findings))

	// Пустой обход — ОТКАЗ, а не пустой успех: «ноль находок» на «ноль
	// прочитанного» неотличимо от чистого дерева.
	if c.Docs == 0 {
		t.Fatal("приёмок в каталоге службы не прочитано ни одной — вердикт беспредметен: " +
			"проверь, не переехал ли каталог docs/engineering/acceptance")
	}
	if c.Declared == 0 {
		t.Fatal("объявлений проб в дереве не найдено ни одного — резолвить координаты не с чем, " +
			"и всякая из них была бы объявлена мёртвой")
	}
	if c.Coordinates == 0 {
		t.Fatal("координат проб в приёмках не распознано ни одной при непустом корпусе — " +
			"разборщик не знает формы записи, а не документы её лишились")
	}
	for _, f := range c.Findings {
		t.Error(f)
	}
}

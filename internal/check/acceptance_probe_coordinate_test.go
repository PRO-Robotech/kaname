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
	"strings"
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
	ownHome, err := check.OwnHomeOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дом этого дерева не назван: %v", err)
	}
	c := check.JudgeProbeCoordinates(docs, declared, check.AcceptanceProbeCoordinateExemptions)

	t.Logf("осмотрено: приёмок %d · объявлений проб в дереве %d · координат %d · "+
		"резолвится %d · в чужом доме %d (%s) · по ведомости %d · находок %d · "+
		"дом этого дерева %s",
		c.Docs, c.Declared, c.Coordinates, c.Resolved, c.Foreign,
		strings.Join(c.ForeignHomes, " · "), c.Exempted, len(c.Findings), ownHome)

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

	// ── СТОРОЖ 1. Приставка дома не должна стать способом обезоружить гейт ────
	//
	// Чужой дом снимает координату с суждения. Значит существует правка, от
	// которой гейт молчит, а утверждения остаются непроверенными: приставить дом
	// КАЖДОЙ координате. Такой корпус этот сторож отвергает — судить в нём было
	// бы нечего, и «находок ноль» означало бы «прочитано ноль».
	if c.Coordinates == c.Foreign {
		t.Fatalf("все %d координат объявлены живущими в чужих домах (%s) — гейту нечего "+
			"судить, и его зелёный ничего не утверждает: приставка дома есть запись о "+
			"ЧУЖОМ дереве, а не способ снять координату с проверки",
			c.Coordinates, strings.Join(c.ForeignHomes, " · "))
	}

	// ── СТОРОЖ 2. СВОЙ дом, названный чужим, — обход суждения ─────────────────
	//
	// Ядро судит значения и отличить `PRO-Robotech/kaname:TestFoo` от настоящего
	// чужого дома не может: для него всякий непустой дом чужой. Здесь дерево
	// известно, поэтому проверяется здесь.
	for _, h := range c.ForeignHomes {
		if h == ownHome {
			t.Errorf("приёмка называет домом координаты %s — это ДОМ ЭТОГО ДЕРЕВА. "+
				"Координата в своё дерево судится индексом и приставки дома не несёт: "+
				"иначе всякая мёртвая координата закрывается припиской своего же имени "+
				"репозитория", h)
		}
	}

	for _, f := range c.Findings {
		t.Error(f)
	}
}

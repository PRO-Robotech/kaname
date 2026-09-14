// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_path_coordinate_test.go — TestAcceptancePathCoordinateResolves:
// гейт класса «утверждение, пережившее свой предмет», применённый к ПУТИ, по
// которому приёмка велит идти за доказательством.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `acceptance_path_coordinate_injection_test.go`.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestAcceptancePathCoordinateResolves(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = corpusRoot + "/" + modulePrefix
	}

	docs, err := check.AcceptanceDocsOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: приёмки не прочитаны: %v", err)
	}
	tracked, err := check.TrackedPathsOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: отслеживаемые пути не прочитаны: %v", err)
	}
	ownHome, err := check.OwnHomeOfTree(ownDir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: дом этого дерева не назван: %v", err)
	}
	c := check.JudgePathCoordinates(docs, tracked, check.AcceptancePathCoordinateExemptions)

	// ПЕРЕПИСЬ ПЕЧАТАЕТ ВСЕ ВЕЛИЧИНЫ. Одно число скрывало бы ровно тот случай,
	// ради которого гейт заведён: корпус, где судить оказалось нечего.
	t.Logf("осмотрено: приёмок %d · отслеживаемых путей в дереве %d · координат-путей %d · "+
		"резолвится %d · в чужом доме %d [дома: %s] · из них связаны ревизией %d · "+
		"по ведомости %d · находок %d · дом этого дерева %s",
		c.Docs, c.Tracked, c.Coordinates, c.Resolved, c.Foreign,
		strings.Join(c.ForeignHomes, ", "), c.RevisionBound, c.Exempted,
		len(c.Findings), ownHome)

	// ГРАНИЦА — ОТДЕЛЬНОЙ СТРОКОЙ, а не умолчанием. Слепая зона, которую видно,
	// есть остаток; слепая зона, о которой молчат, есть дыра.
	t.Logf("вне суждения: путей-спецификаций без `--` %d (там путь сплошь и рядом "+
		"САМ ЕСТЬ утверждение об отсутствии) · магических путей-спецификаций %d · "+
		"эллипсисов прозы %d. Путь, названный ПРОЗОЙ, этот гейт не судит вовсе — "+
		"см. шапку `acceptance_path_coordinate.go` §ГРАНИЦА РАЗБОРА",
		c.Borders.BareSpec, c.Borders.Magic, c.Borders.Elided)

	// Пустой обход — ОТКАЗ, а не пустой успех.
	if c.Docs == 0 {
		t.Fatal("приёмок в каталоге службы не прочитано ни одной — вердикт беспредметен: " +
			"проверь, не переехал ли каталог docs/engineering/acceptance")
	}
	if c.Tracked == 0 {
		t.Fatal("отслеживаемых путей в дереве не найдено ни одного — резолвить координаты " +
			"не с чем, и всякая из них была бы объявлена мёртвой")
	}
	if c.Coordinates == 0 {
		t.Fatal("путевых координат в приёмках не распознано ни одной при непустом корпусе — " +
			"разборщик не знает формы записи, а не документы её лишились")
	}

	// ── СТОРОЖ 1. Приставка дома не должна стать способом обезоружить гейт ────
	//
	// Чужой дом снимает путь с суждения. Значит существует правка, от которой
	// гейт молчит, а утверждения остаются непроверенными: приставить дом КАЖДОМУ
	// пути. Такой корпус этот сторож отвергает.
	if c.Coordinates == c.Foreign {
		t.Fatalf("все %d путевых координат объявлены живущими в чужих домах (%s) — гейту "+
			"нечего судить, и его зелёный ничего не утверждает: приставка дома есть запись "+
			"о ЧУЖОМ дереве, а не способ снять путь с проверки",
			c.Coordinates, strings.Join(c.ForeignHomes, " · "))
	}

	// ── СТОРОЖ 2. СВОЙ дом, названный чужим, — обход суждения ─────────────────
	//
	// Ядро судит значения и отличить `PRO-Robotech/kaname:internal/x` от
	// настоящего чужого дома не может: для него всякий непустой дом чужой.
	for _, h := range c.ForeignHomes {
		if h == ownHome {
			t.Errorf("приёмка называет домом путевой координаты %s — это ДОМ ЭТОГО ДЕРЕВА. "+
				"Путь в своё дерево судится индексом и приставки дома не несёт: иначе "+
				"всякая мёртвая координата закрывается припиской своего же имени "+
				"репозитория", h)
		}
	}

	for _, f := range c.Findings {
		t.Error(f)
	}
}

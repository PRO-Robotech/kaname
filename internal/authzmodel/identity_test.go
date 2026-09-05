// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

// identity_test.go — вшитая копия модели равна канонической ПОБАЙТОВО.
//
// Без этого гейта у прав два источника, расходящихся молча: канонический файл
// правят люди и по нему судят гейты каталога, а вердикт внутри iam выводится
// из ВШИТОЙ копии. Разойдясь, они дадут не отказ, а РАЗНЫЕ решения о доступе —
// и заметно это станет по чужому доступу, а не по красному прогону.
//
// Здесь стояло «кластер применяет один текст». Кластер не применяет никакого:
// внешний движок отношений снят целиком (S6, эпик #747), и копий у модели
// осталось ДВЕ — каноническая и вшитая (#1038).

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzplan"
)

func TestEmbeddedModelIsByteIdenticalToCanonical(t *testing.T) {
	path, canonical, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("каноническая модель не найдена: %v", err)
	}
	if len(canonical) == 0 {
		t.Fatal("каноническая модель прочитана как ноль байт — сравнивать не с чем")
	}
	if DSL == "" {
		t.Fatal("вшитая копия пуста — форма вердикта не сможет вывести ни одного отношения")
	}
	if string(canonical) != DSL {
		t.Fatalf("вшитая копия разошлась с %s (канон %d байт, копия %d байт). "+
			"Правится ТОЛЬКО канонический файл; копия порождается "+
			"`make -C deploy fga-model-embed`. Пока они разные, гейты каталога судят "+
			"один текст, а вердикт внутри iam выводится из другого — и это не отказ, "+
			"а разные решения о доступе",
			path, len(canonical), len(DSL))
	}
	t.Logf("осмотрено: %d байт канонической модели, копия совпадает", len(canonical))
}

// Копия обязана лежать РЯДОМ с кодом, который её вшивает: `go:embed` не ходит
// вверх по дереву, и подмена пути на канонический файл собралась бы, только если
// его туда скопировать, — то есть молча вернула бы вторую копию без гейта.
func TestEmbeddedCopyIsWhereTheDirectiveSaysItIs(t *testing.T) {
	const rel = "fga_model.fga"
	st, err := os.Stat(rel)
	if err != nil {
		t.Fatalf("копия %s не найдена рядом с пакетом: %v", rel, err)
	}
	if st.Size() == 0 {
		t.Fatal("копия существует, но пуста")
	}
}

// Все отношения модели выразимы планом.
//
// Это предпосылка формы вердикта: невыразимое отношение означает вердикт по
// неполному набору источников, то есть отказ там, где источник просто не
// разобран. Проверяется на ВСЕЙ модели, а не на тех отношениях, которые
// случилось спросить.
func TestEveryRelationOfTheModelIsExpressible(t *testing.T) {
	p, err := Shared()
	if err != nil {
		t.Fatalf("разбор вшитой модели: %v", err)
	}
	types, relations, bad := 0, 0, 0
	for _, tn := range p.Model().TypeNames() {
		types++
		for _, r := range p.Model().Type(tn).Relations {
			relations++
			if _, err := p.Plan(tn, r.Name); err != nil {
				bad++
				t.Errorf("%s.%s: %v", tn, r.Name, err)
			}
		}
	}
	if types == 0 || relations == 0 {
		t.Fatal("модель разобрана в ноль типов или ноль отношений — «невыразимых нет» " +
			"означало бы «ничего не прочитано»")
	}
	t.Logf("осмотрено: типов %d, отношений %d, невыразимых %d", types, relations, bad)
}

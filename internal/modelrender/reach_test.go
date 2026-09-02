// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/internal/authzplan"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/modelrender"
)

// reach_test.go — ОСТАТОК называется числом, а не умалчивается (приёмка B-07).
//
// Побайтовое равенство достижимо ровно для тех блоков канона, чья форма выразима
// разделом `resources` СЕГОДНЯШНЕЙ схемы. Формы для позиционированной внутриблочной
// прозы в схеме нет (Н-04 приёмки — предмет #1778 и условия 2 #1104), поэтому блок,
// у которого комментарий стоит не в начале, недостижим BY CONSTRUCTION.
//
// Это не «качество рендера», а условие исполнимости сверки, и потому измеряется
// числом: «выражено не всё» обязано быть отличимо от «выражено всё».

// derived — попытка вывести ресурс, порождающий данный блок. ok=false, когда форма
// блока разделом `resources` не выражается.
//
// Это НЕ второй рендер: вывод проверяется прогоном НАСТОЯЩЕГО Render и побайтовой
// сверкой с блоком. Вывод, ошибшийся в любую сторону, даёт неравенство и попадает
// в остаток, а не в достижимое.
func derived(block modelrender.Block) (manifest.Resource, bool) {
	lines := strings.Split(strings.TrimRight(string(block.Body), "\n"), "\n")
	if len(lines) < 2 || !strings.HasPrefix(lines[0], "type ") || lines[1] != "  relations" {
		return manifest.Resource{}, false
	}
	r := manifest.Resource{ObjectType: strings.TrimPrefix(lines[0], "type "), Producer: "authored"}

	var doc []string
	i := 2
	for ; i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "#"); i++ {
		doc = append(doc, strings.TrimPrefix(lines[i], "    "))
	}
	r.Doc = strings.Join(doc, "\n")

	previous := "super_admin"
	for ; i < len(lines); i++ {
		body := strings.TrimPrefix(lines[i], "    ")
		if !strings.HasPrefix(body, "define ") {
			return manifest.Resource{}, false
		}
		name, rhs, ok := strings.Cut(strings.TrimPrefix(body, "define "), ": ")
		if !ok {
			return manifest.Resource{}, false
		}
		switch {
		case r.Parent == "" && rhs == "["+name+"]":
			r.Parent = name
		case name == "super_admin" && rhs == "super_admin from "+r.Parent:
			// указатель каскада — порождается, ресурсом не объявляется
		case strings.HasPrefix(name, "v_"):
			r.Verbs = append(r.Verbs, manifest.Verb{Name: strings.TrimPrefix(name, "v_"), Class: "get"})
		case strings.HasPrefix(rhs, "[") && strings.HasSuffix(rhs, " or "+previous):
			subjects := strings.Split(strings.TrimSuffix(strings.TrimPrefix(
				strings.TrimSuffix(rhs, " or "+previous), "["), "]"), ", ")
			if len(r.Tiers) == 0 {
				r.Subjects = subjects
			}
			r.Tiers = append(r.Tiers, name)
			previous = name
		default:
			r.Relations = append(r.Relations, manifest.Relation{Name: name, Definition: rhs})
		}
	}
	if r.Parent == "" {
		return manifest.Resource{}, false
	}
	return r, true
}

// TestB07TheUnreachableRemainderIsNamedByNumber — сколько блоков канона рендер
// достаёт побайтово, и сколько НЕ достаёт.
//
// Проба утверждает НЕ РЕГРЕСС, а не цель: цель — все 27, и до неё нужна форма для
// позиционированной прозы, которой в схеме нет. Число печатается всегда, поэтому
// «ноль находок» отличимо от «ноль прочитанного».
func TestB07TheUnreachableRemainderIsNamedByNumber(t *testing.T) {
	path, dsl, err := authzplan.ResolveCanonicalModel()
	if err != nil {
		t.Fatalf("канон не резолвится: %v", err)
	}
	owned := map[string]bool{}
	for _, e := range authzmap.Catalog() {
		if typ, ok := authzmap.ObjectType(e.Module, e.Resource); ok {
			owned[typ] = true
		}
	}

	var modular, reached int
	var unexpressible, unreproduced []string
	for _, b := range modelrender.SplitCanon(dsl) {
		if !owned[b.Type] {
			continue
		}
		modular++
		r, ok := derived(b)
		if !ok {
			unexpressible = append(unexpressible, b.Type)
			continue
		}
		got, rerr := modelrender.Render(r)
		if rerr != nil || string(got) != string(b.Body) {
			unreproduced = append(unreproduced, b.Type)
			continue
		}
		reached++
	}

	if modular == 0 {
		t.Fatalf("модульных блоков 0 — обход пуст, вердикт беспредметен (канон %s)", path)
	}
	// Порог ЗАМЕРЕН этой же пробой на ревизии посадки, а не выбран: первая
	// редакция несла придуманное 15 и покраснела на собственном замере — число,
	// поставленное для веса, есть украшение, а не довод.
	//
	// Порог — НЕ РЕГРЕСС, а не цель: он падает, когда рендер теряет уже
	// достигнутое, и не зеленеет молча, когда достигнутое растёт.
	const floor = 12
	if reached < floor {
		t.Errorf("достижимо %d из %d, было не меньше %d — рендер потерял форму", reached, modular, floor)
	}
	t.Logf("перепись: модульных блоков %d · достижимо побайтово %d · остаток %d",
		modular, reached, modular-reached)
	// Остаток РАЗДЕЛЁН по причине: это разные предметы и чинятся они разными
	// правками. Слить их в одно число значило бы скрыть, что вторая половина —
	// предел САМОГО РЕНДЕРА, а не схемы манифеста.
	t.Logf("остаток А — форма не выражается разделом `resources` (позиционированная "+
		"проза, Н-04 приёмки — предмет #1778 и условия 2 #1104): %d · %s",
		len(unexpressible), strings.Join(unexpressible, ", "))
	t.Logf("остаток Б — форма выражается, но рендер её не воспроизводит (иные формы "+
		"указателя каскада и субъектов яруса, #1091): %d · %s",
		len(unreproduced), strings.Join(unreproduced, ", "))
}

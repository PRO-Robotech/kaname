// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
)

// expand_acceptance_test.go — приём и компиляция судят ОДИН набор (#1290).
//
// Перепись печатает ОБЕ величины: сколько пар берёт входной контроль и сколько
// из них модель действительно компилирует. Расхождение обязано быть нулём —
// пара, дошедшая до компиляции необъявленной, падает внутренней ошибкой на
// корректном запросе.
//
// Проверка НЕ тавтологична: одна сторона спрашивает `AcceptExpand` (тот самый
// предикат, которым пользуется RPC), другая — ЗАПУСКАЕТ компиляцию плана. Если
// приём когда-нибудь снова расширят до объединения наборов, числа разойдутся и
// гейт назовёт координаты.
func TestExpandAcceptanceMatchesWhatTheModelCompiles(t *testing.T) {
	plans, err := authzmodel.Shared()
	if err != nil {
		t.Fatalf("разбор вшитой модели: %v", err)
	}
	m := plans.Model()

	types := m.TypeNames()
	sort.Strings(types)
	surface := make([]string, 0, len(expandableRelations))
	for r := range expandableRelations {
		surface = append(surface, r)
	}
	sort.Strings(surface)

	pairs, accepted, compiles, mismatch := 0, 0, 0, 0
	for _, tn := range types {
		for _, r := range surface {
			// Каждая пара этого обхода — то, что брал тип-агностичный приём до
			// фикса: «отношение на поверхности» без вопроса о типе. Отсюда вторая
			// величина переписи ниже.
			pairs++
			verdict, aerr := AcceptExpand(tn, r)
			if aerr != nil {
				t.Fatalf("AcceptExpand(%q,%q): %v", tn, r, aerr)
			}
			_, cerr := m.Compile(tn, r)
			ok := verdict == ExpandAccepted
			if ok {
				accepted++
			}
			if cerr == nil {
				compiles++
			}
			if ok != (cerr == nil) {
				mismatch++
				if mismatch <= 10 {
					t.Errorf("%s.%s: вход %v, компиляция %v — приём и компиляция судят разные наборы",
						tn, r, verdict, cerr)
				}
			}
		}
	}

	t.Logf("перепись: типов модели %d · отношений поверхности %d · пар осмотрено %d",
		len(types), len(surface), pairs)
	t.Logf("перепись: принимает вход %d · компилируется %d · расхождение %d", accepted, compiles, mismatch)
	t.Logf("перепись: без потипового вопроса вход брал бы %d, из них не компилируется %d",
		pairs, pairs-compiles)

	// Обе стороны равенства обязаны встретиться хотя бы раз: равенство, у
	// которого одна ветвь не спрошена ни разу, не проверено — оно просто не
	// задано, и такой гейт разрешил бы вернуть приём по объединению.
	if accepted == 0 {
		t.Errorf("вход не принял НИ ОДНОЙ пары — положительная сторона равенства не спрошена")
	}
	if pairs-accepted == 0 {
		t.Errorf("вход не отверг НИ ОДНОЙ пары — отрицательная сторона равенства не спрошена, " +
			"и гейт перестал отличать потиповый приём от приёма по объединению")
	}
}

// TestExpandAcceptanceNamesTheGuiltyField — у отказа три разных основания, и
// каждое называет СВОЁ поле. Слить их в одно «не принимается» значило бы послать
// вызывающего править не ту координату.
func TestExpandAcceptanceNamesTheGuiltyField(t *testing.T) {
	cases := []struct {
		name       string
		objectType string
		relation   string
		want       ExpandAcceptance
	}{
		{"тип объявлен, отношение его — принимается", "nlb_target_group", "v_addtargets", ExpandAccepted},
		{"тип не объявлен вовсе", "no_such_object_type_1290", "v_get", ExpandTypeNotDeclared},
		{"отношение вне поверхности (машинерия модели)", "account", "system_admin", ExpandRelationOffSurface},
		{"отношение на поверхности, но тип его не объявляет", "vpc_network", "v_addtargets", ExpandRelationNotOnType},
		{"ярусное отношение объявленного типа", "account", "viewer", ExpandAccepted},
		{"членство — только у группы", "iam_group", "member", ExpandAccepted},
		{"членство у не-группы", "vpc_network", "member", ExpandRelationNotOnType},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := AcceptExpand(c.objectType, c.relation)
			if err != nil {
				t.Fatalf("AcceptExpand: %v", err)
			}
			if got != c.want {
				t.Errorf("AcceptExpand(%q,%q) = %v; ожидалось %v", c.objectType, c.relation, got, c.want)
			}
		})
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// nlb_listener_project_test.go — regression lock for #68.
//
// kacho-nlb emits an `nlb_listener:<id> #project @project:<proj>` owner-hierarchy
// tuple (services/nlb/.../fga_intent.go, FGARelationProject) exactly like it does
// for nlb_network_load_balancer and nlb_target_group — but the FGA model's
// `nlb_listener` type defined NO `project` relation (only load_balancer/admin/
// editor/viewer/v_*). OpenFGA therefore REJECTED every listener project-tuple
// ("relation 'nlb_listener#project' not found") → the iam fga_outbox drainer
// dead-lettered it (apply_permanent_poison) → the listener's project-hierarchy
// never materialized → listener authz/access broke (nlb `listener` newman suite
// red on a fresh 0-tuple stand). Same defect class as registry Defect A: an
// emitter↔model mismatch. Fix = add `define project: [project]` (Contract-A
// direct-relation, parity with nlb_network_load_balancer at the same tier).
func TestNlbListenerModel_DefinesProjectRelation(t *testing.T) {
	dsl := modelDSL(t) // canonical model DSL (single source of truth)
	body := typeBody(t, dsl, "nlb_listener")
	re := regexp.MustCompile(`(?m)^\s*define project:\s*\[project\]`)
	require.Truef(t, re.MatchString(body),
		"nlb_listener must define `project: [project]` so the nlb-emitted project "+
			"owner-hierarchy tuple is a valid FGA write (no dead-letter poison), parity "+
			"with nlb_network_load_balancer / nlb_target_group (#68). body:\n%s", body)

	// Parity guard: the two peer nlb types already carry it — if this ever regresses,
	// the listener drifts back out of the project hierarchy.
	for _, peer := range []string{"nlb_network_load_balancer", "nlb_target_group"} {
		pb := typeBody(t, dsl, peer)
		require.Truef(t, re.MatchString(pb), "%s should still define project: [project]", peer)
	}
}

// Здесь стояли `readConfigMapModelJSON` и поведенческая проба
// TestNlbListenerModel_ProjectTuple_OpenFGACheck: первая доставала заготовку
// модели из карты чарта загрузки движка отношений, вторая грузила её в поднятый
// контейнером движок и утверждала три вещи — что указатель на проект есть
// ВАЛИДНАЯ запись, что владелец разрешает глаголы листенера и что субъект
// соседнего аккаунта их не разрешает.
//
// Первое утверждение снято ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ: движка, который мог бы
// отвергнуть запись, в дереве нет, а прямой факт своей базы словаря отношений не
// держит вовсе — отвергать стало нечему и некому. Два оставшихся живы и
// проверяются формой вердикта в super_admin_cascade_test.go: `nlb_listener`
// стоит в переписи объектов её мира, поэтому «достаёт по указателю» и «сосед не
// достаёт» утверждаются там на том же типе и тем же вопросом, каким его задаёт
// продукт. Второго места об одном предмете здесь заводить не за чем.
//
// Структурное утверждение выше при этом стало НЕСУЩИМ, а не декоративным: план
// вывода `nlb_listener.v_*` компилируется из этой самой строки `define project`,
// и сняв её, тип потеряет источники «аккаунт» и «кластер» — то есть каскад
// администратора облака до листенера просто исчезнет.

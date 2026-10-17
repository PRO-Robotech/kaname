// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// nested_early_exit_integration_test.go — СТОИМОСТЬ ВЫДАЧИ С ВЛОЖЕННЫМ ПРАВИЛОМ
// (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// DoD «стоимость — требование к реализации»).
//
// Проба той же формы, что `TestR7_1_13_EarlyExitIsObservable`: стоимость
// РАЗРЕШЁННОГО вердикта не растёт с числом оснований сверх первого. Основание
// здесь — выдача роли, право которой на репозиторий приходит ВЛОЖЕННЫМ правилом
// под правилом над реестрами: ось вложенности стоит внутри предиката ветви
// выдач, и ветвь обязана останавливаться на первой подошедшей строке так же,
// как с правилом верхнего уровня. Чтение рёбер объекта — по ключу, один раз на
// проверенную строку, а не на весь набор.
//
// Селектор вложенного правила кладётся оператором — так же, как селекторы
// соседних приборов этой сетки (`setR`): фикстура одного соединения, где
// продуктовый писатель со своей транзакцией неприменим. Форма строки — та, что
// пишет `ReplaceRuleSelectors` (её держит `TestNested_ND02_…` через продуктовый
// писатель): тип и ветвь контейнера, модельное имя типа контейнера выводит
// страж базы.

import (
	"context"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// setRNested — `target` выдач спрашивающему ролями с вложенным правилом.
func (f *gridFixture) setRNested(t *testing.T, ctx context.Context, from, target int) {
	t.Helper()
	s := scalegrid.NewSeeder(f.tx)
	for i := from; i < target; i++ {
		roleID := fmt.Sprintf("rol-nr%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
			 VALUES ($1, $2, '[]'::jsonb,
			         '[{"module":"registry","resources":["registries"],"verbs":["get"],
			            "children":[{"resources":["repositories"],"verbs":["get"]}]}]'::jsonb,
			         'cluster_root')`, roleID, fmt.Sprintf("probe.nr%05d", i)))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
			roleID, probeCatalogType, probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, match_labels, container_type, container_arm)
			 VALUES ($1, 'fp-n', 'anchor', ARRAY[$2::text], '{}'::jsonb, 'registry.registries', 'anchor')`,
			roleID, probeCatalogType))
		bid := fmt.Sprintf("acb-nr%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', 'usr-1', $2, 'project', 'prj-1', 'ACTIVE')`, bid, roleID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', 'usr-1')`, bid))
	}
	must(t, s.Flush(ctx))
}

// TestNestedEarlyExit_AllowedVerdictDoesNotGrowWithGrounds — строк за
// разрешённый вердикт при трёхстах основаниях с вложенным правилом не больше,
// чем при трёх (с тем же запасом на дребезг, что у R7-1-13).
func TestNestedEarlyExit_AllowedVerdictDoesNotGrowWithGrounds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	const groundsCeiling = 16
	const few, many = 3, 300

	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 200)

	f.setRNested(t, ctx, 0, few)
	f.analyze(t, ctx)
	vFew, mFew := askAndExplain(t, ctx, tx, cap, probeObjectID)

	f.setRNested(t, ctx, few, many)
	f.analyze(t, ctx)
	vMany, mMany := askAndExplain(t, ctx, tx, cap, probeObjectID)

	t.Logf("оснований с вложенным правилом %d → строк %d (%s); %d → строк %d (%s)",
		few, mFew.Rows, vFew, many, mMany.Rows, vMany)
	if vFew != relverdict.Allow || vMany != relverdict.Allow {
		t.Fatalf("раскладки дали %s и %s: вложенное правило не дало права, и сравнивались бы разные вопросы", vFew, vMany)
	}
	if d := mMany.Rows - mFew.Rows; d > groundsCeiling {
		t.Errorf("строк за РАЗРЕШЁННЫЙ вердикт с вложенным правилом: %d при %d основаниях против %d при %d, "+
			"прирост %d при потолке %d — ось вложенности читается на всём наборе, а не на первой строке",
			mMany.Rows, many, mFew.Rows, few, d, groundsCeiling)
	}
}

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
// разрешённый вердикт при трёхстах основаниях с вложенным правилом НЕ БОЛЬШЕ,
// чем при трёх (DoD приёмки: «не больше», без запаса).
func TestNestedEarlyExit_AllowedVerdictDoesNotGrowWithGrounds(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
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
	if mMany.Rows > mFew.Rows {
		t.Errorf("строк за РАЗРЕШЁННЫЙ вердикт с вложенным правилом: %d при %d основаниях против %d при %d — "+
			"стоимость растёт с числом оснований: ось вложенности читается на всём наборе, а не на первой строке",
			mMany.Rows, many, mFew.Rows, few)
	}
}

// replayWithNesting — захваченный у настоящего `Ask` запрос вердикта, повторённый
// с признаком вложенности `nesting`; число строк-оснований. Признак — последний
// параметр формы (catalogtype.go), и проба сперва проверяет, каким значением его
// связал продукт (`bound`): иначе «повтор с ложью» мог бы сравнивать ложь с ложью.
func replayWithNesting(t *testing.T, ctx context.Context, f *gridFixture, cap *verdictCapture, bound, nesting bool) int {
	t.Helper()
	cap.reset()
	if _, _, err := relverdict.Ask(ctx, f.tx, relverdict.Query{Subject: probeSubject, ObjectType: probeModelType,
		ObjectID: probeObjectID, Relation: probeRelation}); err != nil {
		t.Fatalf("вопрос: %v", err)
	}
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	stmts := cap.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("захвачено %d операторов вердикта, ждали один", len(stmts))
	}
	args := append([]any(nil), stmts[0].args...)
	if got, ok := args[len(args)-1].(bool); !ok || got != bound {
		t.Fatalf("продукт связал признак вложенности значением %v, ждали %v", args[len(args)-1], bound)
	}
	return countRows(t, ctx, f, stmts[0].sql, args, nesting)
}

func countRows(t *testing.T, ctx context.Context, f *gridFixture, sql string, args []any, nesting bool) int {
	t.Helper()
	if _, ok := args[len(args)-1].(bool); !ok {
		t.Fatalf("последний параметр вердикта — %T, а не признак вложенности", args[len(args)-1])
	}
	args[len(args)-1] = nesting
	rows, err := f.tx.Query(ctx, sql, args...)
	if err != nil {
		t.Fatalf("повтор вердикта: %v", err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("повтор вердикта: %v", err)
	}
	return n
}

// TestNestedFlag_FalseExcludesNestedSelectorsAndKeepsTopLevel — признак
// вложенности читается отдельным обращением, и между ним и вопросом может
// встать запись вложенного селектора. Ложный признак обязан давать ОТКАЗ по
// вложенной строке, а не читать её строкой верхнего уровня (та дала бы тип
// целиком по всей области). Близнец — правило верхнего уровня: при ложном
// признаке его основание остаётся.
func TestNestedFlag_FalseExcludesNestedSelectorsAndKeepsTopLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	t.Run("вложенное правило", func(t *testing.T) {
		tx, cap := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		f.growN(t, ctx, 20)
		f.setRNested(t, ctx, 0, 1)
		f.analyze(t, ctx)
		if n := replayWithNesting(t, ctx, f, cap, true, true); n == 0 {
			t.Fatalf("при истинном признаке оснований 0: вложенное правило не дало права, сравнивать не с чем")
		}
		if n := replayWithNesting(t, ctx, f, cap, true, false); n != 0 {
			t.Errorf("при ложном признаке оснований %d, ждали 0: вложенный селектор прочитан строкой верхнего уровня", n)
		}
	})
	t.Run("близнец: правило верхнего уровня", func(t *testing.T) {
		tx, cap := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		f.growN(t, ctx, 20)
		f.setR(t, ctx, 1, scalegrid.RecruitDirect)
		f.analyze(t, ctx)
		if n := replayWithNesting(t, ctx, f, cap, false, false); n == 0 {
			t.Errorf("при ложном признаке правило верхнего уровня потеряло основание")
		}
	})
}

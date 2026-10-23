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
//
// Здесь же — проба ПРИЗНАКА ВЛОЖЕННОСТИ (`TestNestedFlag_…`): признак читается
// обращением к каталогу (catalogtype.go) и выбирает форму сборки; форма без
// вложенных правил обязана давать отказ по вложенной строке, а не читать её
// строкой верхнего уровня. Оператор берётся захватом у настоящего `Ask`.

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
			   (role_id, rule_fp, arm, object_types, match_labels, container_type, container_arm, verbs_by_type)
			 VALUES ($1, 'fp-n', 'anchor', ARRAY[$2::text], '{}'::jsonb, 'registry.registries', 'anchor',
			         jsonb_build_object($2::text, jsonb_build_array($3::text)))`,
			roleID, probeCatalogType, probeVerb))
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
	vFew, mFew := askAndExplainAs(t, ctx, tx, cap, probeObjectID, relverdict.VerdictQueryNestedSQLForTest)

	f.setRNested(t, ctx, few, many)
	f.analyze(t, ctx)
	vMany, mMany := askAndExplainAs(t, ctx, tx, cap, probeObjectID, relverdict.VerdictQueryNestedSQLForTest)

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

// capturedVerdict — захваченный у настоящего `Ask` оператор вердикта и то, какую
// форму сборки исполнил продукт (`nested` — с вложенными правилами).
func capturedVerdict(t *testing.T, ctx context.Context, f *gridFixture, cap *verdictCapture) (stmt capturedVerdictStmt, nested bool) {
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
	flat := cap.matching(relverdict.VerdictQuerySQLForTest(axis))
	withNested := cap.matching(relverdict.VerdictQueryNestedSQLForTest(axis))
	switch {
	case len(flat) == 1 && len(withNested) == 0:
		return flat[0], false
	case len(flat) == 0 && len(withNested) == 1:
		return withNested[0], true
	}
	t.Fatalf("захвачено операторов вердикта: без вложенных правил %d, с ними %d — ждали ровно один",
		len(flat), len(withNested))
	return capturedVerdictStmt{}, false
}

// grounds — число строк-оснований оператора `sql` с параметрами `args`.
func grounds(t *testing.T, ctx context.Context, f *gridFixture, sql string, args []any) int {
	t.Helper()
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

// TestNestedFlag_FlatFormExcludesNestedSelectorsAndKeepsTopLevel — форма сборки
// выбирается признаком, прочитанным отдельным обращением, и между ним и вопросом
// может встать запись вложенного селектора. Форма БЕЗ вложенных правил обязана
// давать по вложенной строке ОТКАЗ, а не читать её строкой верхнего уровня (та
// дала бы тип целиком по всей области). Близнец — правило верхнего уровня: в
// форме без вложенных правил его основание остаётся.
func TestNestedFlag_FlatFormExcludesNestedSelectorsAndKeepsTopLevel(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}

	t.Run("вложенное правило", func(t *testing.T) {
		tx, cap := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		f.growN(t, ctx, 20)
		f.setRNested(t, ctx, 0, 1)
		f.analyze(t, ctx)
		stmt, nested := capturedVerdict(t, ctx, f, cap)
		if !nested {
			t.Fatalf("над типом стоит вложенный селектор, а продукт исполнил форму без вложенных правил")
		}
		if n := grounds(t, ctx, f, stmt.sql, stmt.args); n == 0 {
			t.Fatalf("в форме с вложенными правилами оснований 0: вложенное правило не дало права, сравнивать не с чем")
		}
		if n := grounds(t, ctx, f, relverdict.VerdictQuerySQLForTest(axis), stmt.args); n != 0 {
			t.Errorf("в форме без вложенных правил оснований %d, ждали 0: вложенный селектор прочитан строкой верхнего уровня", n)
		}
	})
	t.Run("близнец: правило верхнего уровня", func(t *testing.T) {
		tx, cap := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		f.growN(t, ctx, 20)
		f.setR(t, ctx, 1, scalegrid.RecruitDirect)
		f.analyze(t, ctx)
		stmt, nested := capturedVerdict(t, ctx, f, cap)
		if nested {
			t.Fatalf("вложенных селекторов нет, а продукт исполнил форму с вложенными правилами")
		}
		if n := grounds(t, ctx, f, stmt.sql, stmt.args); n == 0 {
			t.Errorf("в форме без вложенных правил правило верхнего уровня потеряло основание")
		}
	})
}

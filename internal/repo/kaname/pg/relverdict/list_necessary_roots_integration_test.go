// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

type necessaryRootCaptureTx struct {
	pgx.Tx
	sql   string
	first []any
}

func (q *necessaryRootCaptureTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	if sql == q.sql && q.first == nil {
		q.first = append([]any(nil), args...)
	}
	return q.Tx.Query(ctx, sql, args...)
}

// Реальная ACTIVE label-выдача остаётся: ноль корней получается отказом
// собственного селектора, а не отсутствием субъектов, роли или источников.
func TestListNecessaryRoots_ZeroLabelsSkipRecursionAndLatePageSurvives(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, _ := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	f.growN(t, ctx, 100, 0)
	axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
	if err != nil {
		t.Fatal(err)
	}
	capture := &necessaryRootCaptureTx{Tx: tx, sql: relverdict.ListQuerySQLForTest(axis)}
	question := relverdict.ListQuery{Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: 50}
	ids, next, err := relverdict.List(ctx, capture, question)
	if err != nil || len(ids) != 0 || next != "" || len(capture.first) != 12 {
		t.Fatalf("zero List: ids=%v next=%q captured=%d err=%v", ids, next, len(capture.first), err)
	}
	var candidates, needed, judged, allowed int
	err = tx.QueryRow(ctx, relverdict.ListNecessaryRootCountsSQLForTest(axis, false), capture.first...).Scan(&candidates, &needed, &judged, &allowed)
	if err != nil || candidates != 50 || needed != 0 || judged != 0 || allowed != 0 {
		t.Fatalf("candidate=%d needed=%d adjudicated=%d allowed=%d err=%v", candidates, needed, judged, allowed, err)
	}
	var mode string
	if err := tx.QueryRow(ctx, "SHOW plan_cache_mode").Scan(&mode); err != nil || mode != "auto" {
		t.Fatalf("causal oracle requires unchanged auto mode: mode=%q err=%v", mode, err)
	}
	var raw []byte
	if err := tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+capture.sql, capture.first...).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var plans []map[string]any
	if err := json.Unmarshal(raw, &plans); err != nil || len(plans) != 1 {
		t.Fatalf("plan decode: %v", err)
	}
	unions := 0
	loops := float64(0)
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if v["Node Type"] == "Recursive Union" {
				unions++
				if n, ok := v["Actual Loops"].(float64); ok {
					loops += n
				} else {
					t.Fatal("recursive union lacks Actual Loops")
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(plans[0]["Plan"])
	if unions == 0 || loops != 0 {
		t.Fatalf("recursive nodes=%d actual loops=%v; expected present but unexecuted", unions, loops)
	}
	t.Logf("auto diagnostic only, not historical plan: candidate=%d needed=%d recursiveLoops=%v executionMs=%v jit=%v", candidates, needed, loops, plans[0]["Execution Time"], plans[0]["JIT"])

	// Первый заход полностью отказной; второй должен наполнить страницу.
	exec(t, ctx, tx, `UPDATE kaname.resource_mirror SET labels=$1::jsonb
         WHERE object_type=$2 AND object_id >= 'bulk-0000050' AND object_id <= 'bulk-0000099'`,
		strJSON(t, strSelectorLabels(0)), strCatalogType)
	ids, next, err = relverdict.List(ctx, tx, question)
	if err != nil || len(ids) != 50 || next != "bulk-0000099" {
		t.Fatalf("late full page: count=%d next=%q err=%v", len(ids), next, err)
	}
	for i, id := range ids {
		if want := fmt.Sprintf("bulk-%07d", i+50); id != want {
			t.Fatalf("late page[%d]=%q want=%q", i, id, want)
		}
	}
	question.AfterID = next
	ids, next, err = relverdict.List(ctx, tx, question)
	if err != nil || len(ids) != 0 || next != "" {
		t.Fatalf("after late full page: ids=%v next=%q err=%v", ids, next, err)
	}
}

// Оба ограничителя разведки обязаны возвращать полный суд, а не обрезать права.
func TestListNecessaryRoots_OverflowKeepsEveryCandidate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, axisName := range []string{"bindings", "selectors"} {
		t.Run(axisName, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()
			tx, _ := openProbeTx(t, ctx)
			f := newStrFixture(t, ctx, tx)
			f.growN(t, ctx, 6, 0)
			if axisName == "bindings" {
				f.setL(t, ctx, 3)
			} else {
				f.setK(t, ctx, 3)
			}
			axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
			if err != nil {
				t.Fatal(err)
			}
			capture := &necessaryRootCaptureTx{Tx: tx, sql: relverdict.ListQuerySQLForTest(axis)}
			ids, next, err := relverdict.List(ctx, capture, relverdict.ListQuery{
				Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: 2,
			})
			if err != nil || len(ids) != 0 || next != "" || len(capture.first) != 12 {
				t.Fatalf("overflow List ids=%v next=%q err=%v", ids, next, err)
			}
			var candidates, needed, judged, allowed int
			err = tx.QueryRow(ctx, relverdict.ListNecessaryRootCountsSQLForTest(axis, false), capture.first...).Scan(&candidates, &needed, &judged, &allowed)
			if err != nil || candidates != 2 || needed != 2 || judged != 2 || allowed != 0 {
				t.Fatalf("overflow counts=%d/%d/%d/%d err=%v", candidates, needed, judged, allowed, err)
			}

			// Переполнение сохраняет также положительное право полного суда.
			// На оси селекторов разрешает только третье правило при Pg=2.
			ruleFP := "fp-0000"
			if axisName == "selectors" {
				ruleFP = "fp-0002"
			}
			exec(t, ctx, tx, `UPDATE kaname.role_rule_selectors
                 SET arm='names', resource_names=ARRAY['bulk-0000001']::text[], match_labels='{}'::jsonb
                 WHERE role_id=$1 AND rule_fp=$2`, strRoleID, ruleFP)
			ids, next, err = relverdict.List(ctx, tx, relverdict.ListQuery{
				Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: 2,
			})
			if err != nil || !reflect.DeepEqual(ids, []string{"bulk-0000001"}) || next != "" {
				t.Fatalf("overflow positive right: ids=%v next=%q err=%v", ids, next, err)
			}
		})
	}
}

func TestListNecessaryRoots_ND08OwnerLabelsRemainOnContainer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	pool, ctx, _ := ndWorld(t, `{"team":"a"}`, `{"team":"b"}`)
	ndSeedRole(t, ctx, pool, "rol-nr-nested", ndRules(true, nil, map[string]string{"team": "a"}))
	ndBind(t, ctx, pool, "acb-nr-nested", "user", "usr-1", "rol-nr-nested", `{"allInScope":true}`)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	ids, next, err := relverdict.List(ctx, tx, relverdict.ListQuery{
		Subject: ndUsrD, ObjectType: ndRepoType, Relation: "v_get", Limit: 50,
	})
	if err != nil || !reflect.DeepEqual(ids, []string{ndXApp, ndXMoved}) || next != "" {
		t.Fatalf("owner labels must select X child only: ids=%v next=%q err=%v", ids, next, err)
	}
}

func TestListNecessaryRoots_AlternateArmsAndDirectFactAreIndependent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, _ := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	f.growN(t, ctx, 6, 0)
	for i, arm := range []string{"names", "anchor", "anchor"} {
		role, binding := fmt.Sprintf("rol-nr-%d", i), fmt.Sprintf("acb-nr-%d", i)
		strSeedRole(t, ctx, tx, role, fmt.Sprintf("necessary-role-%d", i), 1)
		names := []string{}
		if arm == "names" {
			names = []string{"bulk-0000001"}
		}
		exec(t, ctx, tx, `UPDATE kaname.role_rule_selectors
             SET arm=$2, resource_names=$3, match_labels='{}'::jsonb WHERE role_id=$1`, role, arm, names)
		subjectType, subjectID := "user", strUserID
		if i == 2 {
			subjectType, subjectID = "system_class", "authenticated"
		}
		strSeedBinding(t, ctx, tx, binding, subjectType, subjectID, role, "project", "prj-1", nil)
		exec(t, ctx, tx, `UPDATE kaname.access_bindings SET target=jsonb_build_object(
             'resources', jsonb_build_array(jsonb_build_object('type',$2::text,'id',$3::text)))
             WHERE id=$1`, binding, strCatalogType, fmt.Sprintf("bulk-%07d", i+1))
	}
	question := relverdict.ListQuery{Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: 50}
	check := func(want []string) {
		t.Helper()
		ids, next, err := relverdict.List(ctx, tx, question)
		if err != nil || !reflect.DeepEqual(ids, want) || next != "" {
			t.Fatalf("mixed List ids=%v want=%v next=%q err=%v", ids, want, next, err)
		}
	}
	check([]string{"bulk-0000001", "bulk-0000002", "bulk-0000003"})
	exec(t, ctx, tx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
         VALUES($1,'bulk-0000004',$2,$3)`, strModelType, strRelation, strSubject)
	check([]string{"bulk-0000001", "bulk-0000002", "bulk-0000003", "bulk-0000004"})
	// Проекция роли сама по себе не заменяет глагол именно этого правила.
	exec(t, ctx, tx, `UPDATE kaname.role_rule_selectors SET verbs_by_type='{}'::jsonb WHERE role_id='rol-nr-1'`)
	check([]string{"bulk-0000001", "bulk-0000003", "bulk-0000004"})
}

// Каждая ветвь наблюдается отдельно: якорь или соседняя выдача не маскируют
// необходимость факта, имени объекта и глагола собственного правила.
func TestListNecessaryRoots_IsolatedFactNamesAndRuleVerb(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	tx, _ := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	f.growN(t, ctx, 6, 0)
	axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
	if err != nil {
		t.Fatal(err)
	}
	question := relverdict.ListQuery{Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: 50}
	check := func(want []string, wantNeeded int, allNeeded bool) {
		t.Helper()
		capture := &necessaryRootCaptureTx{Tx: tx, sql: relverdict.ListQuerySQLForTest(axis)}
		ids, next, err := relverdict.List(ctx, capture, question)
		if err != nil || len(ids) != len(want) || (len(want) > 0 && !reflect.DeepEqual(ids, want)) || next != "" || len(capture.first) != 12 {
			t.Fatalf("isolated List ids=%v want=%v next=%q captured=%d err=%v", ids, want, next, len(capture.first), err)
		}
		var candidates, needed, judged, allowed int
		err = tx.QueryRow(ctx, relverdict.ListNecessaryRootCountsSQLForTest(axis, false), capture.first...).Scan(&candidates, &needed, &judged, &allowed)
		if allNeeded {
			wantNeeded = candidates
		}
		if err != nil || candidates < 6 || needed != wantNeeded || judged != wantNeeded || allowed != len(want) {
			t.Fatalf("isolated counts=%d/%d/%d/%d wantNeeded=%d wantAllowed=%d err=%v", candidates, needed, judged, allowed, wantNeeded, len(want), err)
		}
	}
	// Меточная выдача существует и отказывает всем; обход фактом ещё отсутствует.
	check(nil, 0, false)
	exec(t, ctx, tx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject)
         VALUES($1,'bulk-0000004',$2,$3)`, strModelType, strRelation, strSubject)
	check([]string{"bulk-0000004"}, 0, true)
	// Убираем факт до проверки имени и глагола: безусловного обхода больше нет.
	exec(t, ctx, tx, `DELETE FROM kaname.relation_fact WHERE object_type=$1
         AND object_id='bulk-0000004' AND relation=$2 AND subject=$3`, strModelType, strRelation, strSubject)
	exec(t, ctx, tx, `UPDATE kaname.role_rule_selectors SET arm='names',
         resource_names=ARRAY['bulk-0000001']::text[], match_labels='{}'::jsonb WHERE role_id=$1`, strRoleID)
	check([]string{"bulk-0000001"}, 1, false)
	// Проекция role_verb остаётся, но собственный глагол правила удалён.
	exec(t, ctx, tx, `UPDATE kaname.role_rule_selectors SET verbs_by_type='{}'::jsonb WHERE role_id=$1`, strRoleID)
	check(nil, 0, false)
}

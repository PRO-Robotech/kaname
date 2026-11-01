// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type escCapturedSQL struct {
	SQL  string
	Args []any
}
type escSQLCapture struct{ queries []escCapturedSQL }

func (c *escSQLCapture) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.HasPrefix(strings.TrimSpace(d.SQL), "SELECT id, subject_type, subject_id,") && strings.Contains(d.SQL, "FROM access_bindings") {
		c.queries = append(c.queries, escCapturedSQL{d.SQL, append([]any(nil), d.Args...)})
	}
	return ctx
}
func (*escSQLCapture) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// S1.8 captures the actual repository producer, including the subject OR predicate,
// complete projection, LIMIT and subsequent-page cursor. No planner knobs are changed.
func TestRoleRights_S1P8_ActualGrantReadPlans(t *testing.T) {
	w := newGDWorld(t)
	// Repository fixture API, one transaction, distinct grants. There are 1001 group
	// grants so the same pagination loop as activeScopesOfGroup must read a cursor page.
	projects := make([]domain.ProjectID, 1001)
	for i := range projects {
		projects[i] = seedProjectInAccount(t, w.ctx, w.pool, w.accA, fmt.Sprintf("plan-%d", i))
	}
	users := make([]domain.UserID, 11000)
	for i := range users {
		users[i] = mustSeedUser(t, w.ctx, w.pool, fmt.Sprintf("plan-%d", i))
	}
	wr, err := w.repo.Writer(w.ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(w.ctx) }()
	for i := 0; i < 12001; i++ {
		st, sid, role := domain.SubjectTypeUser, domain.SubjectID(w.usrA), w.rolPusher
		scopeID := string(w.prjA)
		if i >= 1001 {
			sid = domain.SubjectID(users[i-1001])
		}
		if i < 1001 {
			st, sid, role = domain.SubjectTypeGroup, domain.SubjectID(w.grpB), w.rolPuller
			scopeID = string(projects[i])
		}
		_, err = bindingset.Insert(w.ctx, wr.AccessBindingsW(), domain.AccessBinding{
			ID: domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)), SubjectType: st, SubjectID: sid,
			RoleID: role, ResourceType: "project", ResourceID: scopeID,
			Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
		})
		require.NoError(t, err, "fixture row %d", i)
	}
	require.NoError(t, wr.Commit(w.ctx))
	_, err = w.pool.Exec(w.ctx, "ANALYZE kaname.access_bindings; ANALYZE kaname.access_binding_subjects")
	require.NoError(t, err)
	capture := &escSQLCapture{}
	cfg := w.pool.Config()
	cfg.ConnConfig.Tracer = capture
	pool, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	defer pool.Close()
	rd, err := kanamepg.New(pool, nil).Reader(w.ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	roleRows, err := rd.AccessBindings().ListActiveByRole(w.ctx, w.rolPuller)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(roleRows), 1001)
	token, total, pages := "", 0, 0
	for {
		page, next, err := rd.AccessBindings().ListBySubject(w.ctx, domain.SubjectTypeGroup, domain.SubjectID(w.grpB), abrepo.PageFilter{PageSize: 1000, PageToken: token})
		require.NoError(t, err)
		total += len(page)
		pages++
		if next == "" {
			break
		}
		token = next
	}
	require.GreaterOrEqual(t, total, 1001)
	require.GreaterOrEqual(t, pages, 2)
	require.Len(t, capture.queries, pages+1)
	var nBindings, nSubjects int
	require.NoError(t, w.pool.QueryRow(w.ctx, "SELECT count(*) FROM kaname.access_bindings").Scan(&nBindings))
	require.NoError(t, w.pool.QueryRow(w.ctx, "SELECT count(*) FROM kaname.access_binding_subjects").Scan(&nSubjects))
	t.Logf("S1.8 census: bindings=%d subjects=%d role_rows=%d group_rows=%d group_pages=%d captured_queries=%d", nBindings, nSubjects, len(roleRows), total, pages, len(capture.queries))
	for i, q := range capture.queries {
		name := fmt.Sprintf("group_page_%d", i)
		if i == 0 {
			name = "role"
		}
		t.Run(name, func(t *testing.T) {
			conn, err := w.pool.Acquire(w.ctx)
			require.NoError(t, err)
			defer conn.Release()
			tx, err := conn.Begin(w.ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(w.ctx) }()
			positive := escActualPlan(t, w.ctx, tx, q, "positive")
			// A data-identical no-index twin changes only access-path availability. pg_temp
			// shadows unqualified producer tables; explicit kaname schema remains untouched.
			_, err = tx.Exec(w.ctx, `CREATE TEMP TABLE access_bindings AS TABLE kaname.access_bindings;
CREATE TEMP TABLE access_binding_subjects AS TABLE kaname.access_binding_subjects;
SET LOCAL search_path = pg_temp, kaname, public;
ANALYZE pg_temp.access_bindings; ANALYZE pg_temp.access_binding_subjects`)
			require.NoError(t, err)
			negative := escActualPlan(t, w.ctx, tx, q, "no_index_twin")
			require.False(t, escGrantPlanIndexed(negative), "negative control must reject the data-identical no-index twin")
			_, err = tx.Exec(w.ctx, `DROP TABLE pg_temp.access_bindings; DROP TABLE pg_temp.access_binding_subjects`)
			require.NoError(t, err)
			restored := escActualPlan(t, w.ctx, tx, q, "restored")
			require.Equal(t, escGrantPlanIndexed(positive), escGrantPlanIndexed(restored), "restoration changed the result")
			require.True(t, escGrantPlanIndexed(positive), "S1.8 actual producer must read access_bindings by index; see SQL, args and JSON plans above")
		})
	}
}

func escActualPlan(t *testing.T, ctx context.Context, tx pgx.Tx, q escCapturedSQL, phase string) map[string]any {
	t.Helper()
	var raw []byte
	require.NoError(t, tx.QueryRow(ctx, "EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) "+q.SQL, q.Args...).Scan(&raw))
	t.Logf("S1.8 %s SQL=%s ARGS=%v PLAN=%s", phase, q.SQL, q.Args, raw)
	var docs []map[string]any
	require.NoError(t, json.Unmarshal(raw, &docs))
	require.Len(t, docs, 1)
	return docs[0]["Plan"].(map[string]any)
}

// Judge only the acceptance's indexed grant read; no index-name or timing budget
// is invented. A scan of the full grant table fails even if another subtree indexes.
func escGrantPlanIndexed(plan map[string]any) bool {
	indexed, sequential := false, false
	var visit func(map[string]any)
	visit = func(n map[string]any) {
		if n["Relation Name"] == "access_bindings" {
			kind, _ := n["Node Type"].(string)
			if kind == "Seq Scan" {
				sequential = true
			}
			if kind == "Index Scan" || kind == "Index Only Scan" || kind == "Bitmap Heap Scan" {
				indexed = true
			}
		}
		children, _ := n["Plans"].([]any)
		for _, child := range children {
			if p, ok := child.(map[string]any); ok {
				visit(p)
			}
		}
	}
	visit(plan)
	return indexed && !sequential
}

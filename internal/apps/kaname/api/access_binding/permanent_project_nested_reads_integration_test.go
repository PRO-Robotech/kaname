// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// The counter observes nested production SQL from the complete UpsertTx call.
// A missing auto_explain extension is a fixture failure, never a read-budget RED.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/PRO-Robotech/kaname/internal/service"
)

type observedRegistrationBeginner struct{ conn *pgx.Conn }

func (b observedRegistrationBeginner) Begin(ctx context.Context) (service.Tx, error) {
	return b.conn.Begin(ctx)
}

func TestPermanentProjectNestedReads_FullUpsertBudget(t *testing.T) {
	w := newPPWorld(t)
	w.deliverDK()
	var notices []string
	cfg := w.pool.Config().ConnConfig.Copy()
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { notices = append(notices, n.Message) }
	conn, err := pgx.ConnectConfig(w.ctx, cfg)
	require.NoError(t, err, "fixture: dedicated observation connection")
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	_, err = conn.Exec(w.ctx, `LOAD 'auto_explain';
		SET auto_explain.log_min_duration = 0;
		SET auto_explain.log_nested_statements = on;
		SET auto_explain.log_analyze = on;
		SET auto_explain.log_buffers = on;
		SET auto_explain.log_level = notice;
		SET auto_explain.log_format = json;
		SET client_min_messages = notice`)
	require.NoError(t, err, "fixture: real nested-statement instrumentation")
	queries := func() []string {
		var out []string
		for _, n := range notices {
			at := strings.Index(n, "\n{")
			if at < 0 {
				continue
			}
			var plan struct {
				Query string `json:"Query Text"`
			}
			if json.Unmarshal([]byte(n[at+1:]), &plan) == nil && plan.Query != "" {
				out = append(out, plan.Query)
			}
		}
		return out
	}
	countBinding := func() int {
		n := 0
		for _, q := range queries() {
			q = strings.ToLower(strings.Join(strings.Fields(q), " "))
			if strings.HasPrefix(q, "select ") && strings.Contains(q, "from kaname.object_project_binding") {
				n++
			}
		}
		return n
	}
	// Positive instrumentation control: observe the real binding read, twice;
	// this establishes that the counter cannot silently accept an empty trace.
	notices = nil
	for range 2 {
		_, err = conn.Exec(w.ctx, `SELECT project_id FROM kaname.object_project_binding WHERE object_type=$1 AND object_id=$2`, pcrRegType, "counter-control")
		require.NoError(t, err)
	}
	require.Equal(t, 2, countBinding(), "fixture: observer must distinguish two binding SELECTs")

	row := resource_mirror.Row{ObjectType: ppRegCat, ObjectID: "983-nested-budget", ParentProjectID: string(w.prjA),
		ParentAccountID: string(w.accA), ParentChain: []string{"project:" + string(w.prjA), "account:" + string(w.accA)},
		SourceVersion: time.Now().UTC()}
	cases := []struct {
		name      string
		alter     func()
		wantReads int
	}{
		{"new", func() {}, 1},
		{"conflict_update", func() {
			row.SourceVersion = row.SourceVersion.Add(time.Second)
			row.Labels = map[string]string{"revision": "changed"}
		}, 1},
		{"version_only", func() { row.SourceVersion = row.SourceVersion.Add(time.Second) }, 1},
		{"two_project_links", func() {
			row.SourceVersion = row.SourceVersion.Add(time.Second)
			row.ParentChain = []string{"project:" + string(w.prjA), "project:" + string(w.prjA), "account:" + string(w.accA)}
		}, 1},
		{"stale", func() { row.SourceVersion = row.SourceVersion.Add(-time.Second) }, 1},
		{"never_declared_control", func() {
			row.ObjectType = "vpc.network"
			row.ObjectID = "983-never-declared"
			row.SourceVersion = row.SourceVersion.Add(time.Second)
		}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.alter()
			tx, err := conn.Begin(w.ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(context.Background()) }()
			notices = nil
			out, err := resource_mirror.UpsertTx(w.ctx, tx, row)
			require.NoError(t, err, "fixture: lawful complete registration must succeed")
			require.Equal(t, tc.name != "stale", out.Applied, "fixture: source-version outcome")
			reads := countBinding()
			for _, q := range queries() {
				t.Logf("nested production SQL: %s", q)
			}
			t.Logf("983 complete UpsertTx: binding SELECTs=%d expected=%d; latency not measured", reads, tc.wantReads)
			require.NoError(t, tx.Commit(w.ctx))
			assert.Equal(t, tc.wantReads, reads, "983 approved binding read budget includes mirror/edge triggers")
		})
	}
	// Whole accepted Register, including admission/derive and transactional
	// audit/outbox. Its successful path must not add BindingRefusesTx reads.
	registrar := internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(),
		observedRegistrationBeginner{conn}, kanamepg.NewCatalogTypeReader(),
		kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), pcrFacts{w.pcrWorld}),
		kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader(),
	).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithAccountResolver(kanamepg.NewProjectAccountResolver())
	notices = nil
	require.NoError(t, registrar.Register(w.ctx, w.regReq("983-whole-register-budget", w.prjA, w.accA)))
	require.Equal(t, 1, countBinding(), "whole Register must reuse the complete command's one binding read")

}

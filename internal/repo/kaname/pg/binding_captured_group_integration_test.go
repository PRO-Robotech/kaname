// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func capturedGroupRequest(t *testing.T, r protocolRig) protocolRig {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 30*time.Second)
	t.Cleanup(cancel)
	r.ctx = ctx
	return r
}

func TestBindingCapturedGroupSameRRDifferentialAndClosedKeys(t *testing.T) {
	r := writerProtocolRig(t)
	r = capturedGroupRequest(t, r)
	groups := stageSeedGroups(t, r, r.a, 1, "blue")
	r = capturedGroupRequest(t, r)
	first := stageBinding(t, r, r.a, true)
	r = capturedGroupRequest(t, r)
	second := stageBinding(t, r, r.a, true)
	// Real lifecycle writers created the carriers and subjects. These additional
	// stale materialization rows are storage fixtures, never authority evidence.
	// They exist only in this actual RR transaction and are all rolled back.
	r = capturedGroupRequest(t, r)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	missing, empty := ids.NewID("grp"), ids.NewID("grp")
	var subjects []string
	for _, binding := range []domain.AccessBindingID{first, second} {
		var subject string
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT subject_id FROM kaname.access_bindings WHERE id=$1`, string(binding)).Scan(&subject))
		subjects = append(subjects, subject)
	}
	for _, binding := range []domain.AccessBindingID{first, second} {
		for _, group := range []string{groups[0], missing} {
			for i, status := range []string{"ACTIVE", "REJECTED", "PENDING_VERIFICATION"} {
				_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_target_members(binding_id,role_id,rule_fp,object_type,object_id,verification_status)
 SELECT id,role_id,$2,'iam.group',$3,$4 FROM kaname.access_bindings WHERE id=$1`, string(binding), fmt.Sprintf("captured-fp-%d", 2-i), group, status)
				require.NoError(t, err)
			}
			for _, subject := range subjects {
				for _, relation := range []string{"v_get", "v_list"} {
					_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,member_object_type,member_object_id,fga_user,relation,object,source)
 VALUES($1,'iam.group',$2,$3,$4,$5,'member')`, string(binding), group, "user:"+subject, relation, "iam_group:"+group)
					require.NoError(t, err)
				}
			}
		}
	}
	kanamepg.BindingCapturedGroupDifferentialForTest(t, r.ctx, tx, r.bundle, first, []string{groups[0], missing, empty})
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	err = tx.Rollback(cleanup)
	cancel()
	require.NoError(t, err)
	r = capturedGroupRequest(t, r)
	var leftovers int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=ANY($1::text[]) AND rule_fp LIKE 'captured-fp-%'`, []string{string(first), string(second)}).Scan(&leftovers))
	require.Zero(t, leftovers, "independent connection observes rollback")
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE member_object_type='iam.group' AND member_object_id=$1`, missing).Scan(&leftovers))
	require.Zero(t, leftovers, "ledger fixture rolled back as well")
}

type capturedGroupTrace struct {
	mu                                                                 sync.Mutex
	legacyProjection, legacyMembers, legacyLedger                      int
	canonicalProjection, canonicalMembers, canonicalLedger, ancestors  int
	beforeRRRows, beforeRRReads, beforePrepareRows, beforePrepareReads int
	captureCalls, prepareCalls, failures                               int
	pid                                                                uint32
	payload                                                            []byte
}

func (c *capturedGroupTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := strings.Join(strings.Fields(d.SQL), " ")
	groupArg := func(i int) bool { return len(d.Args) > i && d.Args[i] == "iam.group" }
	if strings.HasPrefix(q, "SELECT o.id,") && strings.Contains(q, " FROM kaname.groups o") && strings.HasSuffix(q, "WHERE o.id = $1") {
		c.legacyProjection++
	}
	if strings.HasPrefix(q, "SELECT binding_id, role_id, rule_fp, object_type, object_id, verification_status") && groupArg(1) {
		c.legacyMembers++
	}
	if strings.HasPrefix(q, "SELECT fga_user, relation, object FROM kaname.access_binding_emitted_tuples") && groupArg(1) {
		c.legacyLedger++
	}
	if strings.HasPrefix(q, "SELECT jsonb_build_array(r.xmin::text,r.ctid::text,to_jsonb(r))::text,to_jsonb(r)::text FROM ") {
		if strings.Contains(q, "FROM kaname.groups r WHERE r.id=$1") {
			c.canonicalProjection++
		}
		if groupArg(0) && strings.Contains(q, "FROM kaname.access_binding_target_members r") {
			c.canonicalMembers++
		}
		if groupArg(0) && strings.Contains(q, "FROM kaname.access_binding_emitted_tuples r") {
			c.canonicalLedger++
		}
	}
	if strings.Contains(q, "ORDER BY pe.depth ASC") && groupArg(0) {
		c.ancestors++
	}
	if strings.Contains(q, "FROM kaname.authority_binding_stage_sequence_capture_v3(") {
		c.captureCalls++
		c.pid = conn.PgConn().PID()
		c.payload = append([]byte(nil), d.Args[0].([]byte)...)
		c.beforeRRRows, c.beforeRRReads = d.Args[3].(int), d.Args[4].(int)
	}
	if strings.Contains(q, "FROM kaname.authority_binding_stage_sequence_prepare_v3(") {
		c.prepareCalls++
		if c.pid != conn.PgConn().PID() {
			c.failures++
		}
		c.beforePrepareRows, c.beforePrepareReads = d.Args[3].(int), d.Args[4].(int)
	}
	return ctx
}
func (c *capturedGroupTrace) TraceQueryEnd(_ context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err != nil {
		c.mu.Lock()
		c.failures++
		c.mu.Unlock()
	}
}

func TestBindingCapturedGroupWholeAttemptBudgetAndActualSQLFamilies(t *testing.T) {
	for _, inventory := range []int{257, 513} {
		t.Run(fmt.Sprintf("inventory_%d", inventory), func(t *testing.T) {
			r := writerProtocolRig(t)
			r = capturedGroupRequest(t, r)
			stageSeedGroups(t, r, r.a, inventory, "blue")
			r = capturedGroupRequest(t, r)
			binding := stageBinding(t, r, r.a, true)
			trace := &capturedGroupTrace{}
			cfg := r.runtime.Config()
			cfg.ConnConfig.Tracer = trace
			pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			r.runtime, r.repo = pool, kanamepg.New(pool, nil)
			r = capturedGroupRequest(t, r)
			r.repo, _ = fullContractActivate(t, r)
			r = capturedGroupRequest(t, r)
			observed := kanamepg.ProbeBindingCapturedBudgetForTest(t, r.ctx, r.repo, r.bundle, binding)
			trace.mu.Lock()
			defer trace.mu.Unlock()
			require.Zero(t, trace.failures)
			require.Equal(t, 1, trace.captureCalls)
			require.Equal(t, 1, trace.prepareCalls)
			require.Equal(t, inventory+1, observed.Groups, "exact fixture includes its existing group")
			require.Equal(t, inventory+4, observed.Coordinates)
			require.Equal(t, 3*observed.Coordinates+6, observed.SourceKeys)
			require.Equal(t, 4096-(observed.SourceKeys+4*observed.Coordinates-3*observed.Groups), trace.beforeRRReads, "canonical source charges plus actual legacy queries")
			require.Equal(t, trace.beforeRRReads-observed.SourceKeys-3, observed.AfterRRReads, "independent owner source rereads, two candidate types, bundle")
			require.Positive(t, observed.Descriptors)
			require.Equal(t, observed.Groups, trace.canonicalProjection)
			require.Equal(t, observed.Groups, trace.canonicalMembers)
			require.Equal(t, observed.Groups, trace.canonicalLedger)
			require.Equal(t, observed.Groups, trace.ancestors)
			require.Zero(t, trace.legacyProjection)
			require.Zero(t, trace.legacyMembers)
			require.Zero(t, trace.legacyLedger)
			require.Equal(t, map[int]int{257: 774, 513: 1542}[inventory], 3*observed.Groups, "three absent legacy SQL families per observed group, not a counter discount")
			var payload struct {
				Sources     []json.RawMessage `json:"sources"`
				Coordinates []json.RawMessage `json:"coordinates"`
			}
			require.NoError(t, json.Unmarshal(trace.payload, &payload))
			require.Len(t, payload.Sources, observed.SourceKeys)
			require.Len(t, payload.Coordinates, observed.Coordinates)
			require.Equal(t, observed.AfterRRReads, trace.beforePrepareReads)
			require.Equal(t, observed.AfterRRRows, trace.beforePrepareRows)
			require.Less(t, observed.AfterRRReads, trace.beforeRRReads)
			require.Less(t, observed.AfterPrepareReads, observed.AfterRRReads)
			require.GreaterOrEqual(t, observed.AfterPrepareReads, 0)
			t.Logf("BINDING_CAPTURED_GROUP_BUDGET inventory=%d before_rr_rows=%d before_rr_reads=%d observed=%+v actual_legacy_projection=%d actual_legacy_members=%d actual_legacy_ledger=%d canonical_group_reads=%d retained_ancestor_reads=%d", inventory, trace.beforeRRRows, trace.beforeRRReads, observed, trace.legacyProjection, trace.legacyMembers, trace.legacyLedger, trace.canonicalProjection+trace.canonicalMembers+trace.canonicalLedger, trace.ancestors)
		})
	}
}

func TestBindingCapturedGroupActualReadLimitFailsClosed(t *testing.T) {
	r := writerProtocolRig(t)
	r = capturedGroupRequest(t, r)
	binding := stageBinding(t, r, r.a, true)
	r = capturedGroupRequest(t, r)
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, tx.Rollback(cleanup))
	}()
	kanamepg.BindingCapturedGroupReadLimitForTest(t, r.ctx, tx, r.bundle, binding)
}

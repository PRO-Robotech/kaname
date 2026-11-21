// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type mirrorCrossQueryKey struct{}
type mirrorCrossInternalKey struct{}
type mirrorCrossQuery struct {
	sql  string
	args []any
}
type mirrorCrossProtected struct {
	pid    uint32
	proof  []byte
	writes []string
	err    error
}

// Records driver errors before whole-attempt retry can erase their evidence.
// The barrier is AFTER the real writer's successful policy-protection statement.
type mirrorCrossTrace struct {
	pause          bool
	once           sync.Once
	reached        chan mirrorCrossProtected
	resume         chan struct{}
	pid            atomic.Uint32
	epochCompleted atomic.Int32
	mu             sync.Mutex
	deadlocks      []string
	entries        map[uint32][]byte
}

func (s *mirrorCrossTrace) TraceQueryStart(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if ctx.Value(mirrorCrossInternalKey{}) != nil {
		return ctx
	}
	s.pid.Store(c.PgConn().PID())
	// Квитанция живёт только до новой transaction/entry границы того же backend.
	sql := strings.ToLower(strings.TrimSpace(d.SQL))
	if strings.HasPrefix(sql, "begin") || strings.HasPrefix(sql, "commit") || strings.HasPrefix(sql, "rollback") || strings.Contains(sql, "authority_protocol_enter_") {
		s.mu.Lock()
		delete(s.entries, c.PgConn().PID())
		s.mu.Unlock()
	}
	return context.WithValue(ctx, mirrorCrossQueryKey{}, mirrorCrossQuery{d.SQL, d.Args})
}
func (s *mirrorCrossTrace) TraceQueryEnd(ctx context.Context, c *pgx.Conn, d pgx.TraceQueryEndData) {
	if ctx.Value(mirrorCrossInternalKey{}) != nil {
		return
	}
	var pe *pgconn.PgError
	if errors.As(d.Err, &pe) && pe.Code == "40P01" {
		s.mu.Lock()
		s.deadlocks = append(s.deadlocks, fmt.Sprintf("pid=%d %s", c.PgConn().PID(), pe.Message))
		s.mu.Unlock()
	}
	q, ok := ctx.Value(mirrorCrossQueryKey{}).(mirrorCrossQuery)
	if !ok || d.Err != nil {
		return
	}
	// Успешный реальный owner entry сохраняет именно эти аргументы в закрытой
	// attestation. До QueryEnd успеха квитанция отсутствует; caller intent один
	// не принимается. Последующий policy SQL заново проверяет owner attestation.
	if q.sql == "SELECT kaname.authority_protocol_enter_full_v3($1,$2::text[],$3::jsonb,$4,$5,$6,$7,$8,$9::jsonb)" && len(q.args) == 9 && c.PgConn().TxStatus() == 'T' {
		mode, modeOK := q.args[0].(string)
		accounts, accountsOK := q.args[1].([]string)
		kind, kindOK := q.args[3].(string)
		purpose, purposeOK := q.args[7].(string)
		if modeOK && accountsOK && kindOK && purposeOK {
			entry, err := json.Marshal(struct {
				Mode     string   `json:"mode"`
				Accounts []string `json:"accounts"`
				Kind     string   `json:"kind"`
				Purpose  string   `json:"purpose"`
			}{mode, accounts, kind, purpose})
			if err == nil {
				s.mu.Lock()
				if s.entries == nil {
					s.entries = make(map[uint32][]byte)
				}
				s.entries[c.PgConn().PID()] = entry
				s.mu.Unlock()
			}
		}
	}
	if strings.Contains(q.sql, "SELECT kaname.authority_binding_epoch_lock(") {
		s.epochCompleted.Add(1)
	}
	if !s.pause || !strings.Contains(q.sql, "authority_policy_epoch_lock_full_v2(") {
		return
	}
	s.once.Do(func() {
		observed := mirrorCrossProtected{pid: c.PgConn().PID()}
		if len(q.args) > 1 {
			observed.writes, _ = q.args[1].([]string)
		}
		// Этот успешный policy SQL внутри SECURITY DEFINER повторно проверил
		// private attestation и FULL consumer. Берём квитанцию успешного entry
		// того же backend без нового SQL, EXECUTE grant или owner connection.
		s.mu.Lock()
		observed.proof = append([]byte(nil), s.entries[c.PgConn().PID()]...)
		s.mu.Unlock()
		if len(observed.proof) == 0 || c.PgConn().TxStatus() != 'T' {
			observed.err = fmt.Errorf("successful same-transaction FULL entry receipt absent")
		}
		select {
		case s.reached <- observed:
		case <-ctx.Done():
			return
		}
		select {
		case <-s.resume:
		case <-ctx.Done():
		}
	})
}
func (s *mirrorCrossTrace) errors() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.deadlocks...)
}

func TestBindingMirrorCrossAccountPolicyBeforeBindingEpoch(t *testing.T) {
	r, binding, object, uid := mirrorLocalityFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	r.ctx = ctx
	actor := policyActor(t, r, r.b)
	require.NotEqual(t, string(actor.ID), uid, "recipient must not be the B actor")
	// Canonical role producer, with no carrier for this role before T2 CREATE.
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(r.bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	rules := domain.Rules{{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"tier": "blue"}}}
	permissions, err := domain.CompileRules(rules)
	require.NoError(t, err)
	setup, err := lifecycleOwner(r).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = setup.Rollback(context.WithoutCancel(ctx)) }()
	role, err := setup.RolesW().Insert(ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(r.b), Name: domain.RoleName("cross_order_" + ids.NewID("rol")), Rules: rules, Permissions: permissions})
	require.NoError(t, err)
	require.NoError(t, setup.RolesW().ReplaceRuleSelectors(ctx, role.ID, facts.GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, setup.RolesW().ReplaceRoleVerbs(ctx, role.ID, facts.RoleVerbsFromSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, setup.Commit(ctx))
	var nonanchor, unused, distinct bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.role_rule_selectors WHERE role_id=$1 AND (arm<>'anchor' OR container_type IS NOT NULL)),NOT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE role_id=$1),hashtext($2)<>hashtext($3)`, string(role.ID), r.a, r.b).Scan(&nonanchor, &unused, &distinct))
	require.True(t, nonanchor)
	require.True(t, unused)
	require.True(t, distinct, "fixture account fences must differ")
	ta := &mirrorCrossTrace{}
	tb := &mirrorCrossTrace{pause: true, reached: make(chan mirrorCrossProtected, 1), resume: make(chan struct{})}
	var resumeOnce sync.Once
	release := func() { resumeOnce.Do(func() { close(tb.resume) }) }
	defer release()
	makePool := func(trace *mirrorCrossTrace) *pgxpool.Pool {
		cfg := r.runtime.Config()
		cfg.ConnConfig.Tracer = trace
		p, e := pgxpool.NewWithConfig(ctx, cfg)
		require.NoError(t, e)
		t.Cleanup(p.Close)
		return p
	}
	aRig := r
	aRig.runtime = makePool(ta)
	aRig.repo = kanamepg.New(aRig.runtime, nil)
	// The complete canonical A/B world above precedes the single FULL staging.
	aRig.repo, _ = fullContractActivate(t, aRig)
	bRig := r
	bRig.runtime = makePool(tb)
	bRig.repo = kanamepg.New(bRig.runtime, nil)
	// FULL is already active for this exact bundle. Validate a separate, pool-bound
	// contract for B; staging the active world again correctly fails with 55000.
	bContract, err := kanamepg.NewFullWriterContract(ctx, bRig.repo, r.bundle)
	require.NoError(t, err)
	bRig.repo, err = bRig.repo.WithFullWriterContract(bContract)
	require.NoError(t, err)
	kanamepg.BindingMirrorViewerStageForTest(t, ctx, aRig.repo, r.bundle, binding, r.a, uid, object)
	engine := bindingStageEngine(t, aRig, nil)
	factory, err := kanamepg.NewGrantPolicyWriters(ctx, bRig.repo, r.bundle)
	require.NoError(t, err)
	recipient := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	proposal := domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), RoleID: role.ID, SubjectType: recipient.Type, SubjectID: recipient.ID, Subjects: []domain.Subject{recipient}, ResourceType: "account", ResourceID: r.b, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}}
	doneB := make(chan error, 1)
	joinedB := make(chan struct{})
	go func() {
		defer close(joinedB)
		doneB <- factory.RunBindingDecision(ctx, actor, proposal, true, nil, func(ctx context.Context, w kaname.SemanticAuthorityWriter, b domain.AccessBinding, current domain.Role) error {
			if e := grantpolicy.RequireBinding(ctx, w, actor, granteffect.Binding{SourceID: string(b.ID), Role: current, Scope: domain.ScopeAnchor{Type: "account", ID: r.b}, Recipient: recipient, Subjects: []domain.Subject{recipient}, Target: b.Target, CapabilityVersion: 1}); e != nil {
				return e
			}
			created, e := w.AccessBindingsW().Insert(ctx, b)
			if e != nil {
				return e
			}
			if e = w.AccessBindingsW().InsertSubjects(ctx, created.ID, b.Subjects); e != nil {
				return e
			}
			tuples := []ab.RelationTuple{{User: "account:" + r.b, Relation: "account", Object: "iam_access_binding:" + string(created.ID)}}
			if e = w.AccessBindingsW().EmitRelationWrite(ctx, tuples); e != nil {
				return e
			}
			return w.AccessBindingsW().InsertEmittedTuples(ctx, created.ID, tuples)
		})
	}()
	defer func() {
		cancel()
		release()
		select {
		case <-joinedB:
		case <-time.After(5 * time.Second):
			t.Error("B worker cleanup did not finish")
		}
	}()
	var protected mirrorCrossProtected
	select {
	case protected = <-tb.reached:
	case e := <-doneB:
		t.Fatalf("B real protection not reached: %v", e)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.NoError(t, protected.err)
	var proof struct {
		Mode     string   `json:"mode"`
		Accounts []string `json:"accounts"`
		Kind     string   `json:"kind"`
		Purpose  string   `json:"purpose"`
	}
	require.NoError(t, json.Unmarshal(protected.proof, &proof))
	require.Equal(t, "accounts", proof.Mode, "GLOBAL Given does not exercise this cycle")
	require.Equal(t, []string{r.b}, proof.Accounts, "B must not serialize A at account entry")
	require.Equal(t, "binding", proof.Kind)
	require.Equal(t, "decision", proof.Purpose)
	require.Contains(t, protected.writes, "user:"+uid, "actual successful protection must include U in write set")
	// Reset after all setup/probes; observe only the actual A worker.
	ta.pid.Store(0)
	ta.epochCompleted.Store(0)
	doneA := make(chan error, 1)
	joinedA := make(chan struct{})
	go func() { defer close(joinedA); doneA <- engine.ReconcileBinding(ctx, binding) }()
	defer func() {
		cancel()
		release()
		select {
		case <-joinedA:
		case <-time.After(5 * time.Second):
			t.Error("A worker cleanup did not finish")
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if pid := ta.pid.Load(); pid != 0 {
			var blocked bool
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_catalog.pg_blocking_pids($1))`, pid, protected.pid).Scan(&blocked))
			if blocked {
				break
			}
		}
		select {
		case e := <-doneA:
			t.Fatalf("A did not wait on real B writer: %v", e)
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	require.Less(t, ta.epochCompleted.Load(), int32(2), "policy wait must precede final clock")
	release()
	select {
	case err = <-doneB:
		t.Logf("backend deadlocks before B result assertion: A=%v B=%v", ta.errors(), tb.errors())
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case err = <-doneA:
		t.Logf("backend deadlocks before A result assertion: A=%v B=%v", ta.errors(), tb.errors())
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	require.Empty(t, tb.errors(), "retry must not hide B backend deadlock")
	require.Empty(t, ta.errors(), "retry must not hide A backend deadlock")
	var committed bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.access_bindings WHERE id=$1 AND subject_id=$2 AND resource_id=$3)`, string(proposal.ID), uid, r.b).Scan(&committed))
	require.True(t, committed)
	// Preserve the existing complete viewer/native oracle, including known v_get issue.
	mirrorRequireCommittedViewer(t, ctx, aRig, binding, uid, object)
}

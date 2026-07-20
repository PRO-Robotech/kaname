// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_rules_integration_test.go — RBAC rules-model 2026
// integration tests (RED → GREEN), driven through the pg ReconcileAdapter +
// testcontainers Postgres 16. The reconciler is now driven by role.rules
// ARM_LABELS selectors (NOT binding.selector): a thin all_in_scope binding
// carrying a rules-role with matchLabels rules materializes per-rule membership.
//
// Coverage:
//   - matchLabels per-object only on matched-and-contained objects; a later
//     label flip on a non-matched object materializes it (no broad anchor).
//   - Role.Update removing/editing an ARM_LABELS rule → the removed
//     rule's per-object members are eager-revoked by rule_fp (no residual).
//   - containment: a matched object under a foreign scope → REJECTED + audit.
//   - concurrent reconcile of one rules-binding → exactly one emit (idempotent).
//
// Run: `make test` (testcontainers + Docker). Skipped under -short.

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedRulesRole inserts a PROJECT-scoped custom role whose rules[] is the supplied
// authored policy, compiling the anchor/names arms into permissions (ARM_LABELS
// excluded) and syncing role_rule_selectors — exactly what Role.Create does, but
// direct-SQL for the reconcile integration fixtures.
//
// A custom role is account- XOR project-scoped (DB CHECK roles_definition_tier_xor +
// the roles_acc/prj_custom_unique partial indexes). role_repo.Insert now persists
// project_id (previously dropped), so the role MUST carry exactly ONE scope column.
// These reconcile fixtures bind on the member's project scope, so the seeded role
// is project-scoped: AccountID stays empty (passing both would violate the XOR and
// Insert raises SQLSTATE 23514 — and a bare require.NoError on that error would
// FailNow before Commit, leaking the writer-tx connection; see the rollback note).
func seedRulesRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kachopg.Repository, prj domain.ProjectID, name string, rules domain.Rules) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	role := domain.Role{
		ID: rid, ProjectID: prj, Name: domain.RoleName(name),
		Description: domain.Description("rules role " + name), Rules: rules, Permissions: compiled, IsSystem: false,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	// Always release the writer-tx connection. On a failed Insert/Replace a bare
	// require.NoError → t.FailNow → runtime.Goexit skips the explicit Commit, and
	// the held connection would never return to the pool → pool.Close() blocks on
	// the puddle WaitGroup until the job-level 30m timeout (the hang symptom).
	// After a successful Commit this Rollback is a no-op.
	defer func() { _ = w.Rollback(ctx) }()
	inserted, err := w.RolesW().Insert(ctx, role)
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID, inserted.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))
	return rid
}

// insertThinBinding inserts an ACTIVE all_in_scope binding (no selector spec) for a
// rules-role — the role.rules selectors drive membership, not the binding.
func insertThinBinding(t *testing.T, ctx context.Context, repo *kachopg.Repository, subject domain.UserID, roleID domain.RoleID, prj domain.ProjectID) domain.AccessBindingID {
	t.Helper()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: roleID, ResourceType: "project", ResourceID: string(prj),
		Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

// memberStatusByRule reads a materialized member's status for a specific rule_fp.
func memberStatusByRule(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, ruleFP, objType, objID string) (domain.VerificationStatus, bool) {
	t.Helper()
	var st string
	err := pool.QueryRow(ctx,
		`SELECT verification_status FROM kacho_iam.access_binding_target_members
		  WHERE binding_id=$1 AND rule_fp=$2 AND object_type=$3 AND object_id=$4`,
		string(bid), ruleFP, objType, objID).Scan(&st)
	if err != nil {
		return "", false
	}
	return domain.VerificationStatus(st), true
}

// ── matchLabels per-object, no over-grant ─────────────────────────────────────

func TestC22_MatchLabels_PerObject_NoOverGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c22")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "create"},
		MatchLabels: map[string]string{"env": "prod"},
	}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c22role", domain.Rules{rule})

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "i1", string(fx.prj), string(fx.accID), map[string]string{"env": "prod"}, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "i2", string(fx.prj), string(fx.accID), map[string]string{"env": "staging"}, now)

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// Only i1 (env=prod) is ACTIVE under the rule_fp; i2 is not a member.
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "i1")
	require.True(t, ok, "matched object materialized")
	assert.Equal(t, domain.VerificationActive, st)
	_, ok2 := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "i2")
	assert.False(t, ok2, "non-matched object is not a member")

	// Per-object tuple on i1 (v_create + tier editor); NO anchor/scope_grant tuple.
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i1"), 1)
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i2"), "no tuple on non-matched")
	var anchorTuples int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox WHERE payload->>'object' LIKE 'scope_grant:%'`).Scan(&anchorTuples))
	assert.Equal(t, 0, anchorTuples, "matchLabels never emits a scope_grant anchor (fix #8)")

	// Later: i2 gets env=prod → reconcile by object → i2 becomes a member ACTIVE.
	seedMirrorRow(t, ctx, pool, "compute.instance", "i2", string(fx.prj), string(fx.accID), map[string]string{"env": "prod"}, now.Add(time.Second))
	require.NoError(t, rec.ReconcileObject(ctx, "compute.instance", "i2"))
	st2, ok2b := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "i2")
	require.True(t, ok2b, "i2 newly-labelled prod becomes a member")
	assert.Equal(t, domain.VerificationActive, st2)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i2"), 1)
}

// ── containment — matched-but-foreign → REJECTED + audit ──────────────────────

func TestC24_MatchLabels_ForeignScope_Rejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c24")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c24role", domain.Rules{rule})

	// matches labels but lives under prj_other (foreign scope).
	seedMirrorRow(t, ctx, pool, "compute.instance", "i-foreign", string(fx.prjOth), string(fx.accID), map[string]string{"env": "prod"}, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "i-foreign")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationRejected, st, "foreign-scope match → REJECTED")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:i-foreign"))
	assert.GreaterOrEqual(t, countContainmentAudit(t, ctx, pool, "i-foreign"), 1, "REJECTED → audit (not silent)")
}

// ── Role.Update removing an ARM_LABELS rule → eager-revoke by fp ───────────────

func TestC20C21_RuleRemoved_EagerRevokeByRuleFP_NoResidual(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c20")
	rec, _ := newReconciler(pool)

	ruleKeep := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "a"}}
	ruleGone := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "b"}}
	fpKeep, fpGone := ruleKeep.Fingerprint(), ruleGone.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c20role", domain.Rules{ruleKeep, ruleGone})

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "ia", string(fx.prj), string(fx.accID), map[string]string{"team": "a"}, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "ib", string(fx.prj), string(fx.accID), map[string]string{"team": "b"}, now)

	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	// both members ACTIVE under their rules.
	stA, _ := memberStatusByRule(t, ctx, pool, bid, fpKeep, "compute.instance", "ia")
	stB, _ := memberStatusByRule(t, ctx, pool, bid, fpGone, "compute.instance", "ib")
	require.Equal(t, domain.VerificationActive, stA)
	require.Equal(t, domain.VerificationActive, stB)

	// Role.Update removes ruleGone (team=b). Sync role_rule_selectors + reconcile.
	w, err := fx.repo.Writer(ctx)
	require.NoError(t, err)
	updated := domain.Role{ID: roleID, AccountID: fx.accID, ProjectID: fx.prj, Name: "c20role",
		Rules: domain.Rules{ruleKeep}, Permissions: mustCompile(t, domain.Rules{ruleKeep}), IsSystem: false}
	_, err = w.RolesW().Update(ctx, updated, []string{"rules"})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, roleID, updated.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))

	// Fan-out reconcile of the binding picks up the new role.rules.
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// ib (the removed rule's member) is gone; its tuple eager-revoked. ia stays.
	_, okB := memberStatusByRule(t, ctx, pool, bid, fpGone, "compute.instance", "ib")
	assert.False(t, okB, "removed-rule member purged (no residual)")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "compute_instance:ib"), 1,
		"removed-rule member tuple eager-revoked")
	stA2, okA := memberStatusByRule(t, ctx, pool, bid, fpKeep, "compute.instance", "ia")
	require.True(t, okA, "kept-rule member survives")
	assert.Equal(t, domain.VerificationActive, stA2)

	// Ledger holds NO residual for ib (no orphan), still holds ia's tuples.
	var ibLedger, iaLedger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id=$1 AND object='compute_instance:ib'`,
		string(bid)).Scan(&ibLedger))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_emitted_tuples WHERE binding_id=$1 AND object='compute_instance:ia'`,
		string(bid)).Scan(&iaLedger))
	assert.Equal(t, 0, ibLedger, "removed-rule object has zero ledger residual (C-20)")
	assert.Greater(t, iaLedger, 0, "kept-rule object retains its ledger tuples")
}

// ── concurrent reconcile of one rules-binding → idempotent ────────────────────

func TestC26_ConcurrentRulesReconcile_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c26")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c26role", domain.Rules{rule})
	seedMirrorRow(t, ctx, pool, "compute.instance", "ix", string(fx.prj), string(fx.accID), map[string]string{"env": "prod"}, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rec.ReconcileBinding(ctx, bid) }()
	}
	wg.Wait()
	require.NoError(t, rec.ReconcileBinding(ctx, bid)) // converge

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ix")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationActive, st)
	// Exactly one member row; LoadBinding's SELECT FOR UPDATE serializes passes.
	var members int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members WHERE binding_id=$1 AND rule_fp=$2`,
		string(bid), fp).Scan(&members))
	assert.Equal(t, 1, members, "exactly one materialized member (idempotent, no dupes)")
}

// ── expiry eager-revoke for a role.rules binding ──────────────────────────────
//
// In this control plane the NON_EXPIRED condition is enforced by the expiry
// sweep: an expired ACTIVE binding is CAS-transitioned to REVOKED and EVERY ACTIVE
// member's per-object FGA tuple is eager-revoked, so a subsequent Check denies
// (the raw tuple is GONE). This test verifies it for role.rules per-object
// members (revoked via the saved ledger, since the rule verbs are still present
// but the binding is expired). fail-closed: the binding flips REVOKED atomically.
func TestC23_ExpiredRulesBinding_EagerRevoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c23")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c23role", domain.Rules{rule})
	seedMirrorRow(t, ctx, pool, "compute.instance", "iexp", string(fx.prj), string(fx.accID), map[string]string{"env": "prod"}, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iexp")
	require.True(t, ok)
	require.Equal(t, domain.VerificationActive, st)

	// Backdate created_at + expires_at into the past (expires_at > created_at to
	// satisfy access_bindings_expires_future_ck) so the binding is now expired —
	// exactly the state the expiry sweep finds via expires_at < now().
	_, err = pool.Exec(ctx,
		`UPDATE kacho_iam.access_bindings
		    SET created_at = now() - interval '2 hours',
		        expires_at = now() - interval '1 hour'
		  WHERE id=$1`, string(bid))
	require.NoError(t, err)
	require.NoError(t, rec.ExpireBinding(ctx, bid))

	// Binding REVOKED; member purged; per-object tuple eager-revoked → Check denies.
	var status string
	require.NoError(t, pool.QueryRow(ctx, `SELECT status FROM kacho_iam.access_bindings WHERE id=$1`, string(bid)).Scan(&status))
	assert.Equal(t, "REVOKED", status, "expired binding CAS→REVOKED")
	_, okM := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iexp")
	assert.False(t, okM, "expired binding's member removed")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.delete", "compute_instance:iexp"), 1,
		"expiry eager-revokes the per-object tuple (Check denies after expiry)")
}

// ── cross-scope label-tampering defence — containment re-verify ───────────────
//
// A low-priv tenant relabels a FOREIGN-scope object to match a foreign admin's
// matchLabels selector. On EACH reconcile the IsContainedIn(scopeRef) re-verify
// rejects the out-of-scope object (REJECTED, no tuple) — the cross-scope injection
// never yields a grant even though the label now matches. (The author-time
// requireGrantAuthority gate is the use-case-layer half, enforced on Create for
// every binding; this is the reconciler-side defence in depth.)
func TestC25_LabelTampering_ContainmentReverify_NoInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "c25")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"}}
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "c25role", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj) // scope = prj (own)

	// Low-priv tenant relabels a FOREIGN-project object to match the selector.
	seedMirrorRow(t, ctx, pool, "compute.instance", "ievil", string(fx.prjOth), string(fx.accID), map[string]string{"env": "prod"}, time.Now())
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ievil")
	require.True(t, ok)
	assert.Equal(t, domain.VerificationRejected, st, "out-of-scope match → REJECTED (no cross-scope injection)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:ievil"),
		"label-tampered foreign object never gets a tuple")
	assert.GreaterOrEqual(t, countContainmentAudit(t, ctx, pool, "ievil"), 1, "rejection audited (not silent)")
}

// seedAccountRulesRole inserts an ACCOUNT-scoped custom role whose rules[] is the
// supplied authored policy (for iam-direct iam.project/iam.account selectors), and
// syncs role_rule_selectors — like Role.Create but direct-SQL.
func seedAccountRulesRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, repo *kachopg.Repository, acc domain.AccountID, name string, rules domain.Rules) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	role := domain.Role{
		ID: rid, AccountID: acc, Name: domain.RoleName(name),
		Description: domain.Description("account rules role " + name), Rules: rules, Permissions: compiled, IsSystem: false,
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	// Release the writer-tx connection on a failed Insert/Replace (a bare
	// require.NoError → FailNow skips Commit and would leak the held connection →
	// pool.Close hangs until the job-level timeout). No-op after a successful Commit.
	defer func() { _ = w.Rollback(ctx) }()
	inserted, err := w.RolesW().Insert(ctx, role)
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, inserted.ID, inserted.Rules.MaterializingSelectors()))
	require.NoError(t, w.Commit(ctx))
	return rid
}

// insertThinBindingScope inserts an ACTIVE all_in_scope (no selector spec) binding
// for a rules-role on an arbitrary scope anchor (project|account) — the role.rules
// selectors drive membership, not the binding.
func insertThinBindingScope(t *testing.T, ctx context.Context, repo *kachopg.Repository, subject domain.UserID, roleID domain.RoleID, resType, resID string, scope domain.Scope) domain.AccessBindingID {
	t.Helper()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: roleID, ResourceType: domain.ResourceType(resType), ResourceID: resID,
		Scope: scope, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

// ── iam-direct fast-path UNIONs role_rule_selectors (rules-role) ──────────────
//
// A rules-role binding selecting iam.project by label must materialize membership
// on the iam.project label-change event (Q2 trigger → ReconcileObject), via the
// fast-path (≤2s), NOT only on the periodic sweep (~30s). This is the iam-direct
// twin of TestC22 (mirror-fed) — before the fix IAMDirectSelectorBindingsMatchingObject
// queried only the legacy access_binding_selector, so a rules-role binding whose
// member did not yet exist for the freshly-labelled project was invisible to the
// fast-path (RED).
func TestDB1_IamDirectFastPath_RulesRole_LabelChangeMaterializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "db1")
	rec, _ := newReconciler(pool)

	// Account-scoped rules-role: ARM_LABELS rule selecting iam.project tier=gold.
	rule := domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"tier": "gold"},
	}
	fp := rule.Fingerprint()
	roleID := seedAccountRulesRole(t, ctx, pool, fx.repo, fx.accID, "db1role", domain.Rules{rule})
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, roleID, "account", string(fx.accID), domain.ScopeAccount)

	// Initially prj does NOT match (tier=silver) → no member after a full reconcile.
	setProjectLabels(t, ctx, pool, fx.prj, map[string]string{"tier": "silver"})
	require.NoError(t, rec.ReconcileBinding(ctx, bid))
	_, ok0 := memberStatusByRule(t, ctx, pool, bid, fp, "iam.project", string(fx.prj))
	require.False(t, ok0, "silver project is not yet a member")

	// Q2 trigger: the project is relabelled tier=gold; the label-change event drives
	// ReconcileObject("iam.project", prj). The fast-path MUST find the rules-role
	// binding (role_rule_selectors UNION) and materialize membership now.
	setProjectLabels(t, ctx, pool, fx.prj, map[string]string{"tier": "gold"})
	require.NoError(t, rec.ReconcileObject(ctx, "iam.project", string(fx.prj)))

	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.project", string(fx.prj))
	require.True(t, ok, "iam.project label-change must materialize the rules-role member via fast-path (not only sweep)")
	assert.Equal(t, domain.VerificationActive, st, "gold project under account → ACTIVE (iam-direct, D6)")
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "project:"+string(fx.prj)), 1,
		"materialized iam.project member emits a tuple")
}

func mustCompile(t *testing.T, rules domain.Rules) domain.Permissions {
	t.Helper()
	c, err := domain.CompileRules(rules)
	require.NoError(t, err)
	return c
}

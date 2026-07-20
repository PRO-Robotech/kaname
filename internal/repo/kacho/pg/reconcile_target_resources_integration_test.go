// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_target_resources_integration_test.go — redesign-2026 F8 (IAM-1-21)
// least-privilege spine: when an AccessBinding carries a PER-OBJECT target
// (target.resources[]), materialization must emit the per-object v_* tuples EXACTLY
// on the listed objects — NOT on the whole scope. An ARM_ANCHOR role (rules without
// resourceNames/matchLabels) previously expanded to MatchAllInScope and granted the
// subject access to EVERY object of the type in scope (+ future), silently discarding
// the client's per-object least-priv intent while Get echoed the narrow target
// (masked over-grant). These tests pin the intersection (role-rule × target) so a
// per-object target binding grants ONLY the listed objects.
//
// Driven through the pg ReconcileAdapter + testcontainers Postgres 16. Skipped under
// -short; run under -race for the materialization path.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// insertPerObjectBinding inserts an ACTIVE project-scoped binding carrying a per-object
// target (target.resources[]) for a rules-role — the binding's target restricts the
// role.rules materialization to EXACTLY the listed objects.
func insertPerObjectBinding(t *testing.T, ctx context.Context, repo *kachopg.Repository,
	subject domain.UserID, roleID domain.RoleID, prj domain.ProjectID, refs ...domain.ResourceRef) domain.AccessBindingID {
	t.Helper()
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subject),
		RoleID: roleID, ResourceType: "project", ResourceID: string(prj),
		Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
		Target: domain.AccessTarget{Resources: refs},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

// IAM-1-21 (least-priv): an ARM_ANCHOR role + a per-object target[compute.instance:ins-abc]
// materializes v_* ONLY on ins-abc, NOT on the other in-scope instance (ins-other). The
// role's anchor arm no longer expands to MatchAllInScope for a per-object target.
func TestP4_TargetResources_AnchorRole_OnlyListedObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "tgtres1")
	rec, _ := newReconciler(pool)

	// ARM_ANCHOR compute.instance get/list/update (rules WITHOUT names/labels).
	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list", "update"}}
	require.Equal(t, domain.ArmAnchor, rule.Arm(), "fixture must be an ARM_ANCHOR rule")
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "tgtres1role", domain.Rules{rule})

	now := time.Now()
	// Two compute.instance objects IN the binding's project scope.
	seedMirrorRow(t, ctx, pool, "compute.instance", "ins-abc", string(fx.prj), string(fx.accID), nil, now)
	seedMirrorRow(t, ctx, pool, "compute.instance", "ins-other", string(fx.prj), string(fx.accID), nil, now)

	// Per-object target lists ONLY ins-abc.
	bid := insertPerObjectBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj,
		domain.ResourceRef{Type: "compute.instance", ID: "ins-abc"})
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	// ins-abc materialized ACTIVE + per-object tuple emitted.
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ins-abc")
	require.True(t, ok, "listed target object ins-abc materialized")
	assert.Equal(t, domain.VerificationActive, st)
	assert.GreaterOrEqual(t, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:ins-abc"), 1,
		"per-object v_* tuple on the listed target object")

	// ins-other (in scope, but NOT in the target) must NOT be materialized (least-priv).
	_, okOther := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ins-other")
	assert.False(t, okOther, "unlisted in-scope object ins-other must NOT be materialized (per-object target)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:ins-other"),
		"no tuple on the unlisted in-scope object (over-grant guard)")
}

// IAM-1-21 (forward-path least-priv): a compute.instance registered AFTER the per-object
// target binding — but NOT listed in the target — must NOT be materialized by the
// additive forward fast-path (ReconcileObjectForward). Only a listed object is granted.
func TestP4_TargetResources_ForwardPath_OnlyListedObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "tgtres2")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}}
	require.Equal(t, domain.ArmAnchor, rule.Arm())
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "tgtres2role", domain.Rules{rule})

	bid := insertPerObjectBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj,
		domain.ResourceRef{Type: "compute.instance", ID: "ins-listed"})

	now := time.Now()
	// A LISTED object registers later → forward materializes it.
	seedMirrorRow(t, ctx, pool, "compute.instance", "ins-listed", string(fx.prj), string(fx.accID), nil, now)
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "ins-listed"))
	st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ins-listed")
	require.True(t, ok, "listed object materialized by forward path")
	assert.Equal(t, domain.VerificationActive, st)

	// An UNLISTED object registers later → forward must NOT materialize it.
	seedMirrorRow(t, ctx, pool, "compute.instance", "ins-unlisted", string(fx.prj), string(fx.accID), nil, now)
	require.NoError(t, rec.ReconcileObjectForward(ctx, "compute.instance", "ins-unlisted"))
	_, okU := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "ins-unlisted")
	assert.False(t, okU, "unlisted object must NOT be materialized by forward path (per-object target)")
	assert.Equal(t, 0, countFGAOutbox(t, ctx, pool, "fga.tuple.write", "compute_instance:ins-unlisted"))
}

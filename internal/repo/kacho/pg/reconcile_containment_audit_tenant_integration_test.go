// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_containment_audit_tenant_integration_test.go — #2 (data-correctness):
// the containment-rejected audit_outbox row written by EmitContainmentAudit must
// carry the owning ACCOUNT id in its tenant_account_id column (the account-keyed
// compliance-scoping column), NOT the binding's scope id verbatim.
//
// For a PROJECT-scoped binding the scope id is a `prj…` id; writing it into the
// account-keyed column polluted per-account audit aggregation (it is consistent only
// for account-scope, where scope.ID already IS the account). EmitContainmentAudit
// now resolves the project's owning account; cluster / cross-service scopes write
// NULL (mirroring auditTenantAccountID). Driven through the real pg ReconcileAdapter
// + testcontainers Postgres 16.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// containmentAuditTenant returns (tenant_account_id, isNull) for the
// containment-rejected audit_outbox row of objID.
func containmentAuditTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objID string) (string, bool) {
	t.Helper()
	var tenant *string
	err := pool.QueryRow(ctx,
		`SELECT tenant_account_id FROM kacho_iam.audit_outbox
		  WHERE event_type='iam.access_binding.containment_rejected'
		    AND event_payload->>'object_id'=$1
		  ORDER BY created_at DESC LIMIT 1`,
		objID).Scan(&tenant)
	require.NoError(t, err, "read containment audit tenant_account_id")
	if tenant == nil {
		return "", true
	}
	return *tenant, false
}

// TestContainmentAudit_ProjectScope_TenantIsAccount — #2: a project-scoped binding's
// containment-rejected audit must carry the project's OWNING ACCOUNT id (not the
// project id) in tenant_account_id.
func TestContainmentAudit_ProjectScope_TenantIsAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	fx := setupGamma(t, ctx, pool, "auditten")
	rec, _ := newReconciler(pool)

	rule := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "audittenrole", domain.Rules{rule})

	// Matches labels but lives under prj_other (foreign scope) → REJECTED → containment audit.
	seedMirrorRow(t, ctx, pool, "compute.instance", "i-aud-foreign", string(fx.prjOth), string(fx.accID),
		map[string]string{"env": "prod"}, time.Now())
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	require.NoError(t, rec.ReconcileBinding(ctx, bid))

	require.GreaterOrEqual(t, countContainmentAudit(t, ctx, pool, "i-aud-foreign"), 1,
		"foreign-scope match → containment audit (precondition)")

	tenant, isNull := containmentAuditTenant(t, ctx, pool, "i-aud-foreign")
	require.False(t, isNull, "project-scoped binding → tenant_account_id resolved (not NULL)")
	assert.Equal(t, string(fx.accID), tenant,
		"#2: project-scoped containment audit tenant_account_id must be the owning ACCOUNT id, not the project id")
	assert.NotEqual(t, string(fx.prj), tenant,
		"#2: tenant_account_id must NOT be the project id")
}

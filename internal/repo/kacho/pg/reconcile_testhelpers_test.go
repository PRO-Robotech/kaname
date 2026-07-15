// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_testhelpers_test.go — shared integration-test scaffolding for the
// reconciler suites (driven through the pg ReconcileAdapter + testcontainers
// Postgres 16). Hosts the fixtures (account/project/owner/member/role +
// resource_mirror seeding) and assertion helpers used by the surviving
// role.rules ARM_LABELS reconcile tests (reconcile_rules_integration_test.go).
// The legacy per-binding selector / byName-target seeding helpers were dropped
// with the clean-cut of the access_binding_selector / access_binding_targets arms.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// seedComputeEditorRole inserts a project-scoped reusable role covering
// compute.instance.* (verb-bundle), assignable on the given project.
func seedComputeEditorRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID, name string) domain.RoleID {
	t.Helper()
	rid := domain.RoleID(ids.NewID(domain.PrefixRole))
	// 4-segment RBAC-v2 grammar (migration 0005): module.resource.resourceName.verb.
	// `compute.instance.*.update` → editor tier on compute_instance (verb-bundle).
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions, is_system)
		VALUES ($1, $2, $3, $4, '["compute.instance.*.update"]'::jsonb, false)`,
		string(rid), string(prj), name, "compute editor "+name)
	require.NoError(t, err, "seed compute-editor role")
	return rid
}

// seedMirrorRow UPSERTs a resource_mirror row directly (simulating a
// compute→iam RegisterResource landing). sourceVersion orders monotonic updates.
func seedMirrorRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objType, objID, parentProject, parentAccount string, labels map[string]string, sourceVersion time.Time) {
	t.Helper()
	payload := jsonObject(labels)
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.resource_mirror
		  (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
		VALUES ($1, $2, $3, $4, $5::jsonb, $6, now())
		ON CONFLICT (object_type, object_id) DO UPDATE
		   SET parent_project_id = EXCLUDED.parent_project_id,
		       parent_account_id = EXCLUDED.parent_account_id,
		       labels            = EXCLUDED.labels,
		       source_version    = EXCLUDED.source_version,
		       updated_at        = now()
		 WHERE kacho_iam.resource_mirror.source_version < EXCLUDED.source_version`,
		objType, objID, parentProject, parentAccount, payload, sourceVersion)
	require.NoError(t, err, "seed resource_mirror row")
}

// setProjectLabels sets labels on a projects row (iam-direct feed source, D6).
func setProjectLabels(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID, labels map[string]string) {
	t.Helper()
	payload := jsonObject(labels)
	_, err := pool.Exec(ctx,
		`UPDATE kacho_iam.projects SET labels = $2::jsonb WHERE id = $1`, string(prj), payload)
	require.NoError(t, err, "set project labels")
}

// jsonObject renders a label map as a deterministic JSON object literal.
func jsonObject(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	b := "{"
	first := true
	for k, v := range labels {
		if !first {
			b += ","
		}
		b += fmt.Sprintf("%q:%q", k, v)
		first = false
	}
	return b + "}"
}

// countFGAOutbox counts fga_outbox rows of an event_type whose payload object matches.
func countFGAOutbox(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType, object string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE event_type=$1 AND payload->>'object'=$2`,
		eventType, object).Scan(&n)
	require.NoError(t, err)
	return n
}

// countContainmentAudit counts containment-rejected audit_outbox rows for object.
func countContainmentAudit(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objID string) int {
	t.Helper()
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox
		  WHERE event_type='iam.access_binding.containment_rejected'
		    AND event_payload->>'object_id'=$1`,
		objID).Scan(&n)
	require.NoError(t, err)
	return n
}

func newReconciler(pool *pgxpool.Pool) (*reconcile.Reconciler, *kachopg.ReconcileAdapter) {
	adapter := kachopg.NewReconcileAdapter(pool)
	return reconcile.New(adapter, nil), adapter
}

// gammaFixture sets up account/project/owner/member/role and returns the repo.
type gammaFixture struct {
	repo   *kachopg.Repository
	prj    domain.ProjectID
	prjOth domain.ProjectID
	accID  domain.AccountID
	member domain.UserID
	role   domain.RoleID
}

func setupGamma(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) gammaFixture {
	t.Helper()
	repo := kachopg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, "gowner"+suffix)
	member := mustSeedUser(t, ctx, pool, "gmember"+suffix)
	acc := seedAccount(t, ctx, repo, "acc-g"+suffix, owner)
	prj := seedProject(t, ctx, repo, acc.ID, "prj-prod-"+suffix)
	prjOth := seedProject(t, ctx, repo, acc.ID, "prj-other-"+suffix)
	role := seedComputeEditorRole(t, ctx, pool, prj.ID, "ce_"+suffix)
	return gammaFixture{repo: repo, prj: prj.ID, prjOth: prjOth.ID, accID: acc.ID, member: member, role: role}
}

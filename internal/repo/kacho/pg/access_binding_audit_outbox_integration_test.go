// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// access_binding_audit_outbox_integration_test.go — integration tests for the
// audit_outbox compliance emit-in-tx contract on the access_bindings writer.
//
// P0 compliance: an IAM control plane MUST durably record "who granted which
// role to whom on which resource, and when" — the single most security-relevant
// fact about an access-control system. Before this change the AccessBinding
// grant/revoke writer-tx emitted only fga_outbox (ReBAC sync) +
// subject_change_outbox (cache invalidation); neither is a durable compliance
// trail. This file pins the new behaviour:
//
//   - GRANT-EMIT: AccessBindingsW().Insert + EmitAuditEvent(granted) + Commit
//     leaves exactly one audit_outbox row (event_type='iam.access_binding.granted')
//     carrying actor / subject / resource / role_id / binding_id in the payload.
//   - REVOKE-EMIT: AccessBindingsW().Delete + EmitAuditEvent(revoked) + Commit
//     leaves exactly one audit_outbox row (event_type='iam.access_binding.revoked').
//   - ROLLBACK: rollback of the writer-tx discards the audit_outbox row too
//     (запрет #10 — atomic emit-in-tx, no orphan compliance rows).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// countAuditRows returns the number of audit_outbox rows whose payload binding_id
// matches the supplied binding id (scopes assertions to the test row, ignoring
// any seed/bootstrap audit rows).
func countAuditRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, bindingID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox WHERE event_payload->>'binding_id' = $1`,
		bindingID).Scan(&n))
	return n
}

func TestAB_AuditOutboxTx_GrantEmitsGrantedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud01g")
	acc := seedAccount(t, ctx, repo, "acc-aud01-grant", uid)

	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:              bindingID,
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          "rol000000000sysviewer",
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	}
	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeGranted,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Commit(ctx))

	// Exactly one audit row for this binding.
	require.Equal(t, 1, countAuditRows(ctx, t, pool, string(bindingID)),
		"grant must emit exactly one audit_outbox row")

	var (
		eventType  string
		tenant     string
		payloadRaw string
		status     string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, tenant_account_id, event_payload::text, status
		   FROM kacho_iam.audit_outbox
		  WHERE event_payload->>'binding_id' = $1`, string(bindingID)).
		Scan(&eventType, &tenant, &payloadRaw, &status))

	require.Equal(t, "iam.access_binding.granted", eventType)
	require.Equal(t, string(acc.ID), tenant, "tenant_account_id carried for compliance scoping")
	require.Equal(t, "pending", status, "fresh audit row starts pending for the drainer")

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(uid), payload["actor"])
	require.Equal(t, string(uid), payload["subject_id"])
	require.Equal(t, "user", payload["subject_type"])
	require.Equal(t, "account", payload["resource_type"])
	require.Equal(t, string(acc.ID), payload["resource_id"])
	require.Equal(t, "rol000000000sysviewer", payload["role_id"])
	require.Equal(t, string(bindingID), payload["binding_id"])
}

func TestAB_AuditOutboxTx_RevokeEmitsRevokedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud02r")
	acc := seedAccount(t, ctx, repo, "acc-aud02-revoke", uid)
	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          "rol000000000sysviewer",
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	})

	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeRevoked,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, binding.ID))
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Commit(ctx))

	require.Equal(t, 1, countAuditRows(ctx, t, pool, string(binding.ID)),
		"revoke must emit exactly one audit_outbox row")

	var eventType string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kacho_iam.audit_outbox
		  WHERE event_payload->>'binding_id' = $1`, string(binding.ID)).Scan(&eventType))
	require.Equal(t, "iam.access_binding.revoked", eventType)
}

// TestAB_AuditOutboxTx_RollbackDiscardsAuditRow — запрет #10:
// rolling back the writer-tx MUST also discard the audit_outbox emit row.
// Confirms the compliance event is atomic with the domain mutation (if the
// grant rolls back, no audit row claims it happened).
func TestAB_AuditOutboxTx_RollbackDiscardsAuditRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud03rb")
	acc := seedAccount(t, ctx, repo, "acc-aud03-rollback", uid)

	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:              bindingID,
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          "rol000000000sysviewer",
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	}
	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeGranted,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Rollback(ctx)) // explicit rollback

	// Neither the binding row nor the audit_outbox row should be visible.
	var bindingCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE id = $1`,
		string(bindingID)).Scan(&bindingCount))
	require.Equal(t, 0, bindingCount, "binding row must be rolled back")

	require.Equal(t, 0, countAuditRows(ctx, t, pool, string(bindingID)),
		"audit_outbox row must be rolled back atomically with the binding row")
}

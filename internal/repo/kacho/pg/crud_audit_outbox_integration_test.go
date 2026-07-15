// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// crud_audit_outbox_integration_test.go — repo-level audit_outbox tests. Pins
// the new Writer.EmitAuditEvent emit-in-tx contract used by
// the Account/Project/User/ServiceAccount/Group/Role async CRUD use-cases, and
// the cross-cutting invariants that are cleanest to assert at the repo level:
//
//   - 5.2-34 commit-together: mutation + audit row commit atomically.
//   - 5.2-35 rollback-no-orphan: rollback discards the audit row too.
//   - 5.2-37 22-char id regression-guard: emitted id matches ^evt_…{20,30}$
//     and reads back (CHECK passed, not silently dropped).
//   - 5.2-38 event_type CHECK: every new CRUD event_type satisfies
//     audit_outbox_event_type_check (incl. 3-segment underscore values like
//     iam.service_account.created).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// TestCrudAudit_5_2_34_CommitTogether — AccountsW().Insert + EmitAuditEvent +
// Commit leaves exactly one audit row carrying the CRUD payload.
func TestCrudAudit_5_2_34_CommitTogether(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "crud34")
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID: accID, Name: domain.AccountName("crud34-acc"), OwnerUserID: uid, Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType:       "iam.account.created",
		TenantAccountID: string(accID),
		Payload: map[string]any{
			"actor": string(uid), "resource_type": "account",
			"resource_id": string(accID), "name": "crud34-acc",
		},
	}))
	require.NoError(t, w.Commit(ctx))

	var (
		eventType, status, payloadRaw string
		tenant                        *string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, status, tenant_account_id, event_payload::text
		   FROM kacho_iam.audit_outbox WHERE event_payload->>'resource_id' = $1`,
		string(accID)).Scan(&eventType, &status, &tenant, &payloadRaw))
	require.Equal(t, "iam.account.created", eventType)
	require.Equal(t, "pending", status)
	require.NotNil(t, tenant)
	require.Equal(t, string(accID), *tenant)
	var payload map[string]any
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(uid), payload["actor"])
}

// TestCrudAudit_5_2_35_RollbackNoOrphan — rolling back the writer-tx discards the
// audit row (atomic with the mutation, запрет #10).
func TestCrudAudit_5_2_35_RollbackNoOrphan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "crud35")
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID: accID, Name: domain.AccountName("crud35-acc"), OwnerUserID: uid, Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.EmitAuditEvent(ctx, service.AuditEvent{
		EventType: "iam.account.created",
		Payload:   map[string]any{"resource_id": string(accID), "actor": string(uid)},
	}))
	require.NoError(t, w.Rollback(ctx))

	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.audit_outbox WHERE event_payload->>'resource_id' = $1`,
		string(accID)).Scan(&n))
	require.Equal(t, 0, n, "rolled-back mutation must leave no orphan audit row")

	var acctN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.accounts WHERE id = $1`, string(accID)).Scan(&acctN))
	require.Equal(t, 0, acctN, "the account row must also be rolled back")
}

// TestCrudAudit_5_2_37_38_EventIdAndTypeCheck — every CRUD event_type inserts
// with a 22-char evt_ id and passes both audit_outbox_id_check and
// audit_outbox_event_type_check (the row reads back → CHECK passed, not silently
// dropped).
func TestCrudAudit_5_2_37_38_EventIdAndTypeCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	eventTypes := []string{
		"iam.account.created", "iam.account.updated", "iam.account.deleted",
		"iam.project.created", "iam.project.updated", "iam.project.deleted",
		"iam.user.created", "iam.user.updated", "iam.user.deleted",
		"iam.service_account.created", "iam.service_account.updated", "iam.service_account.deleted",
		"iam.group.created", "iam.group.updated", "iam.group.deleted",
		"iam.role.created", "iam.role.updated", "iam.role.deleted",
	}

	for _, et := range eventTypes {
		marker := "rid-" + et
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		require.NoError(t, w.EmitAuditEvent(ctx, service.AuditEvent{
			EventType: et,
			Payload:   map[string]any{"resource_id": marker},
		}), "event_type %s must pass audit_outbox_event_type_check", et)
		require.NoError(t, w.Commit(ctx))

		var id string
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT id FROM kacho_iam.audit_outbox WHERE event_payload->>'resource_id' = $1`,
			marker).Scan(&id), "row for %s must read back (CHECK passed, not dropped)", et)
		require.Regexp(t, sessionEvtIDRe, id, "id for %s must be 22-char evt_ format (#126 guard)", et)
	}
}

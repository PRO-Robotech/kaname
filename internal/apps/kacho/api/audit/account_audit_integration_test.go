// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package audit_test

// account_audit_integration_test.go — Account Create / Update / Delete durable
// audit_outbox emit, atomic with the async writer-tx mutation.
//
// Scenarios: create, update (+ changed_fields), delete, plus the cross-cutting
// atomicity, 22-char id, actor from principal (not body), and no-op no-emit on
// idempotent update.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

func TestAccountAudit_5_2_10_CreateEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc10")

	uc := account.NewCreateAccountUseCase(env.repo, env.opsRepo)
	op, err := uc.Execute(withPrincipal(owner), domain.Account{
		Name:        domain.AccountName("acme-acc10"),
		Description: domain.Description("created in 5.2-10"),
		Labels:      domain.Labels{},
		OwnerUserID: owner,
	})
	require.NoError(t, err)
	awaitWorkers(t)

	got, err := env.opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, got.Done)
	require.Nil(t, got.Error, "Account.Create Operation.error must not be set")

	// resolve the created account id from the metadata.
	accID := accountIDFromMetadata(t, ctx, env, "acme-acc10")
	r := requireOneAuditRow(ctx, t, env.pool, "iam.account.created", accID)
	require.Equal(t, "account", r.payload["resource_type"])
	require.Equal(t, accID, r.payload["resource_id"])
	require.Equal(t, "acme-acc10", r.payload["name"])
	require.Equal(t, string(owner), r.payload["actor"])
	require.Equal(t, "pending", r.status)
	require.Regexp(t, evtIDFormat, r.id, "audit id must be the 22-char evt_ format (#126 guard)")
}

func TestAccountAudit_5_2_11_UpdateEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc11")
	accID := createAccount(t, env, owner, "acme-acc11", "before")

	uc := account.NewUpdateAccountUseCase(env.repo, env.opsRepo)
	desc := domain.Description("renamed")
	_, err := uc.Execute(withPrincipal(owner), account.UpdateAccountInput{
		ID:          domain.AccountID(accID),
		Description: &desc,
		UpdateMask:  []string{"description"},
	})
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.account.updated", accID)
	require.Equal(t, accID, r.payload["resource_id"])
	require.Equal(t, string(owner), r.payload["actor"])
	require.ElementsMatch(t, []any{"description"}, r.payload["changed_fields"],
		"changed_fields must list the applied mutable fields")
}

func TestAccountAudit_5_2_12_DeleteEmits(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc12")
	accID := createAccount(t, env, owner, "acme-acc12", "to-delete")

	uc := account.NewDeleteAccountUseCase(env.repo, env.opsRepo)
	_, err := uc.Execute(withPrincipal(owner), domain.AccountID(accID))
	require.NoError(t, err)
	awaitWorkers(t)

	r := requireOneAuditRow(ctx, t, env.pool, "iam.account.deleted", accID)
	require.Equal(t, accID, r.payload["resource_id"])
	require.Equal(t, string(owner), r.payload["actor"])
}

// 5.2-35 atomicity (rollback no orphan): a Create that violates the
// accounts_name_unique UNIQUE rolls back the writer-tx — no audit row survives.
func TestAccountAudit_5_2_35_RollbackNoOrphan(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc35")
	// First create commits two audit rows for the account id in the SAME writer-tx
	// (P6, mig 0035): iam.account.created + iam.access_binding.granted for the
	// co-committed owner AccessBinding (both carry resource_id=<accountID>).
	first := createAccount(t, env, owner, "dup-acc35", "first")
	require.Equal(t, 2, countAuditByResource(ctx, t, env.pool, first))

	// Second create with the SAME name → 23505 inside the worker-tx → rollback.
	uc := account.NewCreateAccountUseCase(env.repo, env.opsRepo)
	op, err := uc.Execute(withPrincipal(owner), domain.Account{
		Name:        domain.AccountName("dup-acc35"),
		Labels:      domain.Labels{},
		OwnerUserID: owner,
	})
	require.NoError(t, err)
	awaitWorkers(t)
	got, err := env.opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, got.Done)
	require.NotNil(t, got.Error, "duplicate-name create must fail (ALREADY_EXISTS)")

	// No NEW audit row was committed for the failed second attempt — the first
	// account's count stays at the 2 rows committed by its successful create
	// (account.created + owner-binding granted); the rolled-back second attempt
	// (account + owner-binding + both audit rows) leaves nothing behind.
	require.Equal(t, 2, countAuditByResource(ctx, t, env.pool, first),
		"a rolled-back create must leave no orphan audit row (atomicity, запрет #10)")
}

// 5.2-40 anti-spoofing: actor is the verified principal, not any body field.
func TestAccountAudit_5_2_40_ActorFromPrincipal(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc40")
	accID := createAccount(t, env, owner, "acme-acc40", "x")

	r := requireOneAuditRow(ctx, t, env.pool, "iam.account.created", accID)
	require.Equal(t, string(owner), r.payload["actor"],
		"actor must be the authenticated principal, never the resource id or a body value")
	require.NotEqual(t, accID, r.payload["actor"])
}

// 5.2-41 idempotent no-op update emits no audit row (emit-per-committed-change):
// an Update whose mutable field equals the current value commits no change.
func TestAccountAudit_5_2_41_NoOpUpdateNoEmit(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()
	owner, _ := seedUserAccount(t, ctx, env.pool, "acc41")
	accID := createAccount(t, env, owner, "acme-acc41", "same-desc")

	uc := account.NewUpdateAccountUseCase(env.repo, env.opsRepo)
	desc := domain.Description("same-desc") // unchanged value
	_, err := uc.Execute(withPrincipal(owner), account.UpdateAccountInput{
		ID:          domain.AccountID(accID),
		Description: &desc,
		UpdateMask:  []string{"description"},
	})
	require.NoError(t, err)
	awaitWorkers(t)

	require.Empty(t, auditRowsByEventResource(ctx, t, env.pool, "iam.account.updated", accID),
		"a no-op update (value unchanged) must NOT emit an audit row")
}

// ── local helpers ─────────────────────────────────────────────────────────────

func createAccount(t *testing.T, env *testEnv, owner domain.UserID, name, desc string) string {
	t.Helper()
	ctx := context.Background()
	uc := account.NewCreateAccountUseCase(env.repo, env.opsRepo)
	_, err := uc.Execute(withPrincipal(owner), domain.Account{
		Name:        domain.AccountName(name),
		Description: domain.Description(desc),
		Labels:      domain.Labels{},
		OwnerUserID: owner,
	})
	require.NoError(t, err)
	awaitWorkers(t)
	return accountIDFromMetadata(t, ctx, env, name)
}

func accountIDFromMetadata(t *testing.T, ctx context.Context, env *testEnv, name string) string {
	t.Helper()
	var id string
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT id FROM kacho_iam.accounts WHERE name = $1`, name).Scan(&id))
	return id
}

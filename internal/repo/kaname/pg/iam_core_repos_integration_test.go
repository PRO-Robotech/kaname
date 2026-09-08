// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// iam_core_repos_integration_test.go — repository-level integration tests for
// the core IAM repos. testcontainers Postgres 16.
//
// Coverage:
// - TestIamExt_Role_MultiScope_Project / Account / InvalidTwoScopes
// - TestIamExt_AccessBinding_StateMachine_Active_ToRevoked /
// PendingToActive / RevokedTerminal / IllegalBackward
// - TestIamExt_Condition_Insert_Whitelist / RejectsUnknown
// - TestIamExt_Federation_HappyPath / WildcardRejected / ExpiresNotNull / ExpiresOver1Y /
// DuplicateIssuerPattern
// - TestIamExt_SAOAuthClient_Happy / DuplicateHydra / FKMissing / RestrictDelete
// - TestIamExt_JIT_Happy / DurationOver8h
// - TestIamExt_OutboxAtomicity_Commit / Rollback
// - TestIamExt_Bootstrap_UserNotFound / Happy / Idempotent / Concurrent
//
// Запуск: `go test ./internal/repo/kaname/pg/... -run TestIamExtRepos -race`.

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	seedpkg "github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// kac127Setup — общий setup: testcontainers + pgxpool + return DSN-pool pair.
func kac127Setup(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return ctx, pool
}

// mustBeginTx — открывает tx с auto-rollback через t.Cleanup. Защищает от
// puddle WaitGroup hang во время pool.Close, когда тест валится через
// require.* (FailNow → runtime.Goexit) ДО явного tx.Rollback/Commit: tx
// остается acquired, pool.Close блокируется на WaitGroup. Cleanup гарантирует
// освобождение conn'а до Close. Cleanup игнорирует tx.ErrTxClosed (после
// Commit/explicit Rollback) — это штатный путь.
func mustBeginTx(t *testing.T, ctx context.Context, pool *pgxpool.Pool) pgx.Tx {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	return tx
}

// kac127SeedUserAndAccount — INSERT-flow для seeding User+Account (deferred FK).
// Возвращает (userID, accountID). Suffix должен быть длиной 1..10 chars.
func kac127SeedUserAndAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (string, string) {
	t.Helper()
	uid := padOrTrim20("usr_kac127" + suffix)
	accID := padOrTrim20("acc_kac127" + suffix)

	tx := mustBeginTx(t, ctx, pool)
	_, err := tx.Exec(ctx, "SET CONSTRAINTS ALL DEFERRED")
	require.NoError(t, err)
	_, err = tx.Exec(ctx,
		`INSERT INTO accounts (id, name, owner_user_id)
		 VALUES ($1, $2, $3)`,
		accID, "kac127-"+suffix, uid)
	require.NoError(t, err)
	_, err = tx.Exec(ctx,
		`INSERT INTO users (id, external_id, email, account_id, invite_status)
		 VALUES ($1, $2, $3, $4, 'ACTIVE')`,
		uid, "ext-"+suffix, "u-"+suffix+"@kac127.local", accID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// kac127SeedProject — INSERT project с детерминированным id.
func kac127SeedProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID, suffix string) string {
	t.Helper()
	pid := padOrTrim20("prj_kac127" + suffix)
	_, err := pool.Exec(ctx,
		`INSERT INTO projects (id, account_id, name) VALUES ($1, $2, $3)`,
		pid, accID, "kac127-"+suffix+"-prj")
	require.NoError(t, err)
	return pid
}

// ────────────────────────────────────────────────────────────────────────────
// Multi-scope Role CHECK
// (Organization CRUD + organization-scoped role tests removed —
//  Organization/SCIM/SAML are dead and the organizations table + roles/accounts
//  organization_id columns are dropped in migration 0008.)
// ────────────────────────────────────────────────────────────────────────────

func TestIamExtRepos_6_4_1_Role_ProjectScope_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)

	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "rl41")
	prjID := kac127SeedProject(t, ctx, pool, accID, "rl41")

	roleID := "rol00000kac127rl410ab"[:20]
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, 'deployer_rl41', 'project role',
		 '["compute.instances.*.read"]'::jsonb)`,
		roleID, prjID)
	require.NoError(t, err)
}

func TestIamExtRepos_6_4_2_Role_AccountScope_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "rl42")

	roleID := "rol00000kac127rl420ab"[:20]
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		VALUES ($1, $2, 'billing_admin', 'account role',
		 '["billing.invoices.*.read"]'::jsonb)`,
		roleID, accID)
	require.NoError(t, err)
}

func TestIamExtRepos_6_4_4_Role_TwoScopes_CHECK_Fails(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "rl44")
	prjID := kac127SeedProject(t, ctx, pool, accID, "rl44")

	roleID := "rol00000kac127rl440ab"[:20]
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, account_id, project_id, name, description, permissions)
		VALUES ($1, $2, $3, 'invalid_role', '', '["x.y.*.z"]'::jsonb)`,
		roleID, accID, prjID)
	require.Error(t, err)
	assertSQLState(t, err, "23514")
}

// ────────────────────────────────────────────────────────────────────────────
// AccessBinding state machine — CAS pattern
//
// Тесты гоняют lifecycle через repo.AccessBindings().Insert + .TransitionStatus.
// Только тест на невалидный enum (CHECK constraint) использует raw SQL — repo
// блокирует bad statuses на Go-стороне через domain.AccessBindingStatus.Validate.
// ────────────────────────────────────────────────────────────────────────────

// kac127SeedABRow — общий setup для тестов state-machine: user+account+project+role +
// insert one AccessBinding с заданным начальным status через repo.Writer.
func kac127SeedABRow(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string,
	initialStatus domain.AccessBindingStatus,
) (repo *kanamepg.Repository, abID, uid, roleID string) {
	t.Helper()
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, suffix)
	prjID := kac127SeedProject(t, ctx, pool, accID, suffix)
	roleID = padOrTrim20("rol00000kac127" + suffix)
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, $3, '', '["x.y.*.z"]'::jsonb)`,
		roleID, prjID, "role_"+suffix)
	require.NoError(t, err)

	repo = kanamepg.New(pool, nil)
	abID = padOrTrim20("acb00000kac127" + suffix)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:              domain.AccessBindingID(abID),
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          domain.RoleID(roleID),
		ResourceType:    domain.ResourceType("project"),
		ResourceID:      prjID,
		Status:          initialStatus,
		GrantedByUserID: domain.UserID(uid),
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return repo, abID, uid, roleID
}

func TestIamExtRepos_6_5_3_AccessBinding_ActiveToRevoked_CAS(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	repo, abID, uid, _ := kac127SeedABRow(t, ctx, pool, "ab53", domain.AccessBindingStatusActive)

	// ACTIVE → REVOKED via repo.TransitionStatus (single-statement CAS).
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revBy := domain.UserID(uid)
	out, err := w.AccessBindingsW().TransitionStatus(ctx,
		domain.AccessBindingID(abID),
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked,
		&revBy,
	)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	assert.Equal(t, domain.AccessBindingStatusRevoked, out.Status)
	require.NotNil(t, out.RevokedAt)
	require.NotNil(t, out.RevokedByUserID)
	assert.Equal(t, revBy, *out.RevokedByUserID)

	// Verify по чистому SELECT.
	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status FROM access_bindings WHERE id=$1`, abID).Scan(&status))
	assert.Equal(t, "REVOKED", status)
}

func TestIamExtRepos_6_5_3b_AccessBinding_PendingToActive_CAS(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	repo, abID, _, _ := kac127SeedABRow(t, ctx, pool, "ab53b", domain.AccessBindingStatusPending)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.AccessBindingsW().TransitionStatus(ctx,
		domain.AccessBindingID(abID),
		[]domain.AccessBindingStatus{domain.AccessBindingStatusPending},
		domain.AccessBindingStatusActive,
		nil,
	)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.AccessBindingStatusActive, out.Status)
	assert.Nil(t, out.RevokedAt)
	assert.Nil(t, out.RevokedByUserID)
}

func TestIamExtRepos_6_5_4_AccessBinding_RevokedTerminal_CAS_NoMatch(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	// Seed напрямую в REVOKED (terminal state).
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "ab54")
	prjID := kac127SeedProject(t, ctx, pool, accID, "ab54")
	roleID := padOrTrim20("rol00000kac127ab54")
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, 'role_ab54', '', '["x.y.*.z"]'::jsonb)`,
		roleID, prjID)
	require.NoError(t, err)

	repo := kanamepg.New(pool, nil)
	abID := padOrTrim20("acb00000kac127ab54")
	// First Insert as ACTIVE (CHECK на revoked_consistency блокирует direct REVOKED insert
	// без revoked_at), затем CAS → REVOKED.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
		ID:              domain.AccessBindingID(abID),
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          domain.RoleID(roleID),
		ResourceType:    domain.ResourceType("project"),
		ResourceID:      prjID,
		Status:          domain.AccessBindingStatusActive,
		GrantedByUserID: domain.UserID(uid),
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	revBy := domain.UserID(uid)
	_, err = w2.AccessBindingsW().TransitionStatus(ctx,
		domain.AccessBindingID(abID),
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked,
		&revBy,
	)
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	// Now try CAS for ACTIVE/PENDING → must be FailedPrecondition (REVOKED terminal).
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w3.Rollback(ctx) }()
	_, err = w3.AccessBindingsW().TransitionStatus(ctx,
		domain.AccessBindingID(abID),
		[]domain.AccessBindingStatus{
			domain.AccessBindingStatusActive,
			domain.AccessBindingStatusPending,
		},
		domain.AccessBindingStatusActive,
		nil,
	)
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition),
		"expected ErrFailedPrecondition (terminal state), got %v", err)

	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT status FROM access_bindings WHERE id=$1`, abID).Scan(&status))
	assert.Equal(t, "REVOKED", status, "row must remain REVOKED")
}

func TestIamExtRepos_6_5_5_AccessBinding_InvalidStatus_CHECK(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	// Raw SQL — repo блокирует bad enum в Go (domain.AccessBindingStatus.Validate),
	// поэтому DB CHECK constraint проверяется только через прямой SQL bypass.
	ctx, pool := kac127Setup(t)
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "ab55")
	prjID := kac127SeedProject(t, ctx, pool, accID, "ab55")
	roleID := padOrTrim20("rol00000kac127ab55")
	_, err := pool.Exec(ctx, `
		INSERT INTO roles (id, project_id, name, description, permissions)
		VALUES ($1, $2, 'role_ab55', '', '["x.y.*.z"]'::jsonb)`,
		roleID, prjID)
	require.NoError(t, err)

	abID := padOrTrim20("acb00000kac127ab55")
	_, err = pool.Exec(ctx, `
		INSERT INTO access_bindings (id, subject_type, subject_id, role_id, resource_type, resource_id,
		 status, granted_by_user_id)
		VALUES ($1, 'user', $2, $3, 'project', $4, 'GHOST', $2)`,
		abID, uid, roleID, prjID)
	require.Error(t, err)
	assertSQLState(t, err, "23514")
}

// ────────────────────────────────────────────────────────────────────────────
// Conditions whitelist
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Federation Trust Policy
// ────────────────────────────────────────────────────────────────────────────

func seedSvcAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accID, suffix string) string {
	t.Helper()
	sid := padOrTrim20("sva_kac127" + suffix)
	_, err := pool.Exec(ctx,
		`INSERT INTO service_accounts (id, account_id, name) VALUES ($1, $2, $3)`,
		sid, accID, "sva-kac127-"+suffix)
	require.NoError(t, err)
	return sid
}

// ────────────────────────────────────────────────────────────────────────────
// ServiceAccountOAuthClient
// ────────────────────────────────────────────────────────────────────────────

func TestIamExtRepos_6_6_6_SAOAuth_Insert_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "so66")
	sid := seedSvcAccount(t, ctx, pool, accID, "so66")

	repo := kanamepg.NewSAOAuthClientRepo(pool)
	tx := mustBeginTx(t, ctx, pool)
	out, err := repo.Insert(ctx, tx, domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind:  domain.CredentialKindKeypair,
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           domain.ServiceAccountID(sid),
		OAuthClientID:   domain.OAuthClientID("hydra-client-66-001"),
		Description:     domain.Description("CI builder OAuth client"),
		CreatedByUserID: domain.UserID(uid),
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	assert.Equal(t, domain.OAuthClientID("hydra-client-66-001"), out.OAuthClientID)
	assert.Nil(t, out.LastUsedAt)
}

func TestIamExtRepos_6_6_7a_SAOAuth_DuplicateHydraID_Unique(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, accID := kac127SeedUserAndAccount(t, ctx, pool, "so7a")
	sid1 := seedSvcAccount(t, ctx, pool, accID, "so7a1")
	sid2 := seedSvcAccount(t, ctx, pool, accID, "so7a2")

	repo := kanamepg.NewSAOAuthClientRepo(pool)
	tx := mustBeginTx(t, ctx, pool)
	_, err := repo.Insert(ctx, tx, domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind:  domain.CredentialKindKeypair,
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           domain.ServiceAccountID(sid1),
		OAuthClientID:   domain.OAuthClientID("dup-hydra-id-7a"),
		CreatedByUserID: domain.UserID(uid),
	})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	tx2 := mustBeginTx(t, ctx, pool)
	_, err = repo.Insert(ctx, tx2, domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind:  domain.CredentialKindKeypair,
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           domain.ServiceAccountID(sid2),
		OAuthClientID:   domain.OAuthClientID("dup-hydra-id-7a"),
		CreatedByUserID: domain.UserID(uid),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrAlreadyExists),
		"expected ErrAlreadyExists, got %v", err)
}

func TestIamExtRepos_6_6_7b_SAOAuth_MissingSva_FK(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, _ := kac127SeedUserAndAccount(t, ctx, pool, "so7b")

	repo := kanamepg.NewSAOAuthClientRepo(pool)
	tx := mustBeginTx(t, ctx, pool)
	_, err := repo.Insert(ctx, tx, domain.ServiceAccountOAuthClient{
		// Вид ЗАПИСЫВАЕТСЯ каждым писателем (#1142): закрытый
		// словарь таблицы отвергает строку, вида не назвавшую.
		CredentialKind:  domain.CredentialKindKeypair,
		ID:              domain.SAOAuthClientID(domain.NewKac127ID(domain.PrefixSAOAuthClient)),
		SvaID:           domain.ServiceAccountID("sva_kac127nonexist01"),
		OAuthClientID:   domain.OAuthClientID("hyd-7b"),
		CreatedByUserID: domain.UserID(uid),
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition))
}

// ────────────────────────────────────────────────────────────────────────────
// JIT eligibility — REMOVED (JIT/PIM removed alongside the
// access_bindings_jit_eligibility table).
// ────────────────────────────────────────────────────────────────────────────

// ────────────────────────────────────────────────────────────────────────────
// Outbox atomicity
// ────────────────────────────────────────────────────────────────────────────

func TestIamExtRepos_6_11_1a_OutboxAtomic_Commit(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "ob11a")

	auditRepo := kanamepg.NewAuditOutboxRepo(pool)
	tx := mustBeginTx(t, ctx, pool)

	roleID := "rol00000kac127ob1a0ab"[:20]
	_, err := tx.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		VALUES ($1, $2, 'role_ob1a', '', '["x.y.*.z"]'::jsonb)`, roleID, accID)
	require.NoError(t, err)

	tenantAcc := domain.AccountID(accID)
	evtID := "evt_" + strings.Repeat("a", 22)
	_, err = auditRepo.InsertTx(ctx, tx, domain.AuditOutboxEntry{
		ID:              domain.AuditEventID(evtID),
		EventType:       domain.EventTypeName("iam.role.created"),
		TenantAccountID: &tenantAcc,
		EventPayload:    []byte(`{"role_id":"` + roleID + `"}`),
		Status:          domain.AuditOutboxStatusPending,
	})
	require.NoError(t, err)

	require.NoError(t, tx.Commit(ctx))

	// Both visible after commit.
	var roleCount, auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE id=$1`, roleID).Scan(&roleCount))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_outbox WHERE id=$1`, evtID).Scan(&auditCount))
	assert.Equal(t, 1, roleCount)
	assert.Equal(t, 1, auditCount)
}

func TestIamExtRepos_6_11_1b_OutboxAtomic_Rollback(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	_, accID := kac127SeedUserAndAccount(t, ctx, pool, "ob11b")

	auditRepo := kanamepg.NewAuditOutboxRepo(pool)
	tx := mustBeginTx(t, ctx, pool)

	roleID := "rol00000kac127ob1b0ab"[:20]
	_, err := tx.Exec(ctx, `
		INSERT INTO roles (id, account_id, name, description, permissions)
		VALUES ($1, $2, 'role_ob1b', '', '["x.y.*.z"]'::jsonb)`, roleID, accID)
	require.NoError(t, err)

	evtID := "evt_" + strings.Repeat("b", 22)
	_, err = auditRepo.InsertTx(ctx, tx, domain.AuditOutboxEntry{
		ID:           domain.AuditEventID(evtID),
		EventType:    domain.EventTypeName("iam.role.created"),
		EventPayload: []byte(`{"role_id":"` + roleID + `"}`),
		Status:       domain.AuditOutboxStatusPending,
	})
	require.NoError(t, err)

	require.NoError(t, tx.Rollback(ctx))

	// Neither visible.
	var roleCount, auditCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE id=$1`, roleID).Scan(&roleCount))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_outbox WHERE id=$1`, evtID).Scan(&auditCount))
	assert.Equal(t, 0, roleCount)
	assert.Equal(t, 0, auditCount)
}

// ────────────────────────────────────────────────────────────────────────────
// Bootstrap admin
// ────────────────────────────────────────────────────────────────────────────

func TestIamExtRepos_6_10_3_Bootstrap_UserNotFound_GracefulSkip(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	logger := slog.Default()

	res, err := seedpkg.RunBootstrapAdmin(ctx, pool, logger, seedpkg.BootstrapAdminInput{
		Email: "nonexistent@kacho.cloud",
	})
	require.NoError(t, err)
	assert.True(t, res.Skipped)
	assert.Equal(t, seedpkg.BootstrapSkipNotRegistered, res.SkipReason)

	// granted_by='bootstrap' is also carried by the ServiceAccount grant that
	// migration 0058 seeds, so scope the assertion to the rows RunBootstrapAdmin
	// itself can write (it hard-codes subject_type='user').
	var cagCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants
		  WHERE granted_by='bootstrap' AND subject_type='user'`).Scan(&cagCount))
	assert.Equal(t, 0, cagCount, "graceful skip must write no bootstrap user grant")
}

func TestIamExtRepos_6_10_1_Bootstrap_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, _ := kac127SeedUserAndAccount(t, ctx, pool, "boot1")
	// Set email to a known value.
	_, err := pool.Exec(ctx, `UPDATE users SET email='root@kacho.cloud' WHERE id=$1`, uid)
	require.NoError(t, err)

	res, err := seedpkg.RunBootstrapAdmin(ctx, pool, slog.Default(), seedpkg.BootstrapAdminInput{
		Email: "root@kacho.cloud",
	})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, uid, res.UserID)
	assert.NotEmpty(t, res.GrantID)
	assert.NotEmpty(t, res.AuditOutboxID)

	// Verify grant exists.
	var grantedBy string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT granted_by FROM cluster_admin_grants WHERE subject_id=$1`, uid).Scan(&grantedBy))
	assert.Equal(t, "bootstrap", grantedBy)
}

func TestIamExtRepos_6_10_2_Bootstrap_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, _ := kac127SeedUserAndAccount(t, ctx, pool, "boot2")
	_, err := pool.Exec(ctx, `UPDATE users SET email='idem@kacho.cloud' WHERE id=$1`, uid)
	require.NoError(t, err)

	// First run.
	res1, err := seedpkg.RunBootstrapAdmin(ctx, pool, slog.Default(), seedpkg.BootstrapAdminInput{
		Email: "idem@kacho.cloud",
	})
	require.NoError(t, err)
	require.False(t, res1.Skipped)

	// Second run (idempotent — 23505 → graceful skip).
	res2, err := seedpkg.RunBootstrapAdmin(ctx, pool, slog.Default(), seedpkg.BootstrapAdminInput{
		Email: "idem@kacho.cloud",
	})
	require.NoError(t, err)
	assert.True(t, res2.Skipped)
	assert.Equal(t, seedpkg.BootstrapSkipConcurrentRace, res2.SkipReason)

	// Only 1 grant exists.
	var cagCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, uid).Scan(&cagCount))
	assert.Equal(t, 1, cagCount)
}

func TestIamExtRepos_6_10_5_Bootstrap_ConcurrentHA_OneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("requires Docker")
	}
	ctx, pool := kac127Setup(t)
	uid, _ := kac127SeedUserAndAccount(t, ctx, pool, "boot5")
	_, err := pool.Exec(ctx, `UPDATE users SET email='ha@kacho.cloud' WHERE id=$1`, uid)
	require.NoError(t, err)

	const N = 5
	var wg sync.WaitGroup
	var winners int32
	var skipped int32
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := seedpkg.RunBootstrapAdmin(ctx, pool, slog.Default(), seedpkg.BootstrapAdminInput{
				Email: "ha@kacho.cloud",
			})
			// testify require.* unsafe в goroutines (FailNow → runtime.Goexit
			// валидно только в main test-goroutine). Используем assert + early-return.
			if !assert.NoError(t, err) {
				return
			}
			if res.Skipped {
				atomic.AddInt32(&skipped, 1)
			} else {
				atomic.AddInt32(&winners, 1)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, int32(1), atomic.LoadInt32(&winners), "ровно 1 winner")
	assert.Equal(t, int32(N-1), atomic.LoadInt32(&skipped), "остальные skip'нули на 23505")

	var cagCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id=$1`, uid).Scan(&cagCount))
	assert.Equal(t, 1, cagCount, "ровно 1 row в cluster_admin_grants")
}

// ────────────────────────────────────────────────────────────────────────────
// Permission registry seed test
// ────────────────────────────────────────────────────────────────────────────

func TestIamExtRepos_PermissionRegistry_Load_Idempotent(t *testing.T) {
	// Не требует БД: pure embed parsing.
	ctx := context.Background()
	logger := slog.Default()
	reg1, err := seedpkg.LoadPermissionRegistry(ctx, logger)
	require.NoError(t, err)
	require.NotNil(t, reg1)
	entries1 := reg1.All()
	require.NotEmpty(t, entries1, "catalog must contain at least one entry")

	// Идемпотентность: повторный вызов дает identical content.
	reg2, err := seedpkg.LoadPermissionRegistry(ctx, logger)
	require.NoError(t, err)
	entries2 := reg2.All()
	assert.Equal(t, len(entries1), len(entries2))
	for i := range entries1 {
		assert.Equal(t, entries1[i].FQN, entries2[i].FQN, "deterministic FQN ordering")
	}

	// Admin role gets wildcard.
	adminPerms := reg1.PermissionsForRole("kacho-system.admin")
	assert.Equal(t, []string{"*.*.*.*"}, adminPerms)
}

// TestIamExtRepos_PermissionCatalog_AllEmpty_Sanity — expected state:
// ≥99% catalog entries имеют пустое `permission` поле (proto annotations
// еще не наполнены).
//
// **Этот тест fail'ится** когда catalog generator наполнит annotations.
// При наполнении: переименуй в `TestIamExtRepos_PermissionCatalog_AllPopulated`
// + поменяй assert на `assert.False(t, reg.IsPhase1Bootstrap(), ...)`.
// `IsPhase1Bootstrap()` — heuristic name preserved for call-site stability.
func TestIamExtRepos_PermissionCatalog_AllEmpty_Sanity(t *testing.T) {
	ctx := context.Background()
	reg, err := seedpkg.LoadPermissionRegistry(ctx, slog.Default())
	require.NoError(t, err)
	require.NotNil(t, reg)

	entries := reg.All()
	require.NotEmpty(t, entries, "catalog must contain at least one entry")

	// Считаем empty-permission entries для diagnostic message.
	var emptyCount int
	for _, e := range entries {
		if e.Permission == "" {
			emptyCount++
		}
	}
	ratio := float64(emptyCount) / float64(len(entries))

	// The catalog was regenerated from kacho-proto with annotations populated.
	// The bootstrap invariant flipped: catalog is now strongly populated. Until the
	// catalog generator emits 4-segment strings (a kacho-proto follow-up),
	// permission values stay 3-segment but the runtime is tier-tolerant
	// (authzmap.verbClass takes the last segment, ignoring grammar shape).
	assert.False(t, reg.IsPhase1Bootstrap(),
		"post-RBAC-v2 expected: catalog populated (got %d empty / %d total = %.2f%% empty)",
		emptyCount, len(entries), ratio*100)
	assert.Greater(t, len(entries)-emptyCount, 100,
		"expected the populated portion to cover the majority of RPCs")

	// Viewer role expands to the catalog's read-class entries — non-empty.
	viewerPerms := reg.PermissionsForRole("kacho-system.viewer")
	assert.NotEmpty(t, viewerPerms,
		"viewer role expected to expand to the catalog's read-class permissions "+
			"after the catalog regeneration")
}

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

// padOrTrim20 — паддит/обрезает строку до 20 символов (3 char prefix + 17 char body).
// id schema kaname: accounts/users/projects/etc — TEXT, без CHECK regex'а на длину
// (CHECK только на name); тестам нужны валидные 20-char id's parity с production
// ids.NewID(). Используется только в test setup.
func padOrTrim20(s string) string {
	const total = 20
	if len(s) >= total {
		return s[:total]
	}
	return s + strings.Repeat("0", total-len(s))
}

// assertSQLState — проверяет, что error соответствует ожидаемому SQLSTATE.
// Поскольку repo wraps `pgconn.PgError` в iam-sentinel-error через
// `wrapPgErr` (см. internal/repo/kaname/pg/pgmaperr.go), физический
// PgError может быть утерян. Поэтому assertSQLState mapping:
//
//	23505 → ErrAlreadyExists
//	23503 → ErrFailedPrecondition
//	23514 → ErrInvalidArg
//	23502 → ErrInvalidArg
//	23P01 → ErrFailedPrecondition
//
// Для raw SQL (без wrap'а) — fall back на pgconn.PgError text/code check.
func assertSQLState(t *testing.T, err error, sqlstate string) {
	t.Helper()
	require.Error(t, err)
	// Path 1: raw pgconn error (test пишет raw SQL без repo).
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		assert.Equal(t, sqlstate, pgErr.Code, "SQLSTATE mismatch (msg=%s)", pgErr.Message)
		return
	}
	// Path 2: sentinel-wrapped (repo wraps via pg.wrapPgErr).
	switch sqlstate {
	case "23505":
		assert.True(t, errors.Is(err, iamerr.ErrAlreadyExists),
			"expected ErrAlreadyExists for SQLSTATE 23505, got %v", err)
	case "23503":
		assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition),
			"expected ErrFailedPrecondition for SQLSTATE 23503, got %v", err)
	case "23514", "23502":
		assert.True(t, errors.Is(err, iamerr.ErrInvalidArg),
			"expected ErrInvalidArg for SQLSTATE %s, got %v", sqlstate, err)
	case "23P01":
		assert.True(t, errors.Is(err, iamerr.ErrFailedPrecondition),
			"expected ErrFailedPrecondition for SQLSTATE 23P01, got %v", err)
	default:
		// Fallback: text-contains check.
		assert.Contains(t, err.Error(), sqlstate)
	}
}

// Compile guard: ensure sql import retained.
var _ = sql.ErrNoRows

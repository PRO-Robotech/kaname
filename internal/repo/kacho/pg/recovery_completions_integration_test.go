// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// recovery_completions_integration_test.go — testcontainers integration tests
// for InternalUserService.OnRecoveryCompleted, driven through the use-case
// (operations LRO) against a real Postgres.
//
// Scenario trace:
//   - TestOnRecoveryCompleted_S01_Blocked_KeepBlocked_Revoke_Audit_Idempotent
//   - TestOnRecoveryCompleted_S02_Active_Revoke_Audit
//   - TestOnRecoveryCompleted_S03_UnknownExternalID_NotFound_NoSideEffects
//   - TestOnRecoveryCompleted_S04_EmailMismatch_FailedPrecondition_NoSideEffects
//   - TestOnRecoveryCompleted_S05_DuplicateJTI_IdempotentNoop (concurrent goroutines)
//   - sync-validation → covered by use-case unit tests (internal_on_recovery_test.go)
//   - TestOnRecoveryCompleted_S07_MidTxFailure_FullRollback (fault-injection)
//   - TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll (личность в N
//     аккаунтах — членствами, а не строками)
//
// Восстановление возвращает учётные данные, но не право пользоваться ими:
// заблокированная строка остаётся заблокированной (снимает запрет
// администратор), отсечка сессий ставится на каждой затронутой строке.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	userapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/user"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// recoveryAuditFaultErr — the injected mid-tx failure (fault-injection path).
var recoveryAuditFaultErr = fmt.Errorf("injected audit fault")

// seedAccountAndUser inserts (account, user) with the given external_id / email /
// invite_status in one tx (DEFERRABLE FK chicken-and-egg). Returns the ids.
func seedAccountAndUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, externalID, email, status string) (domain.UserID, domain.AccountID) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		string(uid), string(accID), externalID, email, "Recovery User", status)
	require.NoError(t, err, "seed user")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID), fmt.Sprintf("rec-acc-%s", accID[len(accID)-6:]), string(uid))
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// awaitOp polls the ops repo until done (or timeout).
func awaitOp(t *testing.T, ctx context.Context, opsRepo operations.Repo, id string) *operations.Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		op, err := opsRepo.Get(ctx, id)
		require.NoError(t, err)
		if op.Done {
			return op
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operation %s not done within deadline", id)
	return nil
}

func auditRowCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, recoveryJTI string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user.recovery_completed'
		   AND event_payload->>'recovery_jti' = $1`, recoveryJTI).Scan(&n))
	return n
}

// ── S01 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S01_Blocked_KeepBlocked_Revoke_Audit_Idempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, accID := seedAccountAndUser(t, ctx, pool, "krt_alice", "alice@example.com", "BLOCKED")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
	})
	require.NoError(t, err)
	require.NotNil(t, op)

	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error, "operation must succeed")

	// metadata
	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(uid), meta.GetUserId())
	assert.GreaterOrEqual(t, meta.GetRevokedSessionCount(), int32(1))

	// Запрет пережил восстановление: снимает его администратор, а не тот, кто
	// доказал владение почтовым ящиком.
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "BLOCKED", statusDB, "BLOCKED остаётся BLOCKED")

	// revoke-all cutoff present, reason password-change
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	// exactly one audit row, tenant=acc
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_001"))
	var tenant string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT tenant_account_id FROM kacho_iam.audit_outbox
		 WHERE event_payload->>'recovery_jti' = $1`, "rec_flow_001").Scan(&tenant))
	assert.Equal(t, string(accID), tenant)

	// ledger row exists
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_001").Scan(&ledgerN))
	assert.Equal(t, 1, ledgerN)
}

// ── S02 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S02_Active_Revoke_Audit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_bob", "bob@example.com", "ACTIVE")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_bob", RecoveryJTI: "rec_flow_002", Email: "bob@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error)

	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB, "ACTIVE stays ACTIVE")

	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, meta.GetRevokedSessionCount(), int32(1))

	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_002"))
}

// ── S03 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S03_UnknownExternalID_NotFound_NoSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_ghost", RecoveryJTI: "rec_flow_003", Email: "ghost@example.com",
	})
	require.Error(t, err, "unknown identity → sync NOT_FOUND (no Operation)")
	assert.Nil(t, op)

	// no side-effects
	assertNoSideEffects(t, ctx, pool, "rec_flow_003")
}

// ── S04 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S04_EmailMismatch_FailedPrecondition_NoSideEffects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_carol", "carol@example.com", "ACTIVE")

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_carol", RecoveryJTI: "rec_flow_004", Email: "attacker@evil.example.com",
	})
	require.Error(t, err)
	assert.Nil(t, op)

	// status unchanged
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "ACTIVE", statusDB)
	assertNoSideEffects(t, ctx, pool, "rec_flow_004")
}

// ── S05 ─────────────────────────────────────────────────────────────────
func TestOnRecoveryCompleted_S05_DuplicateJTI_IdempotentNoop(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_alice", "alice@example.com", "BLOCKED")
	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)

	// First processing.
	op1, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
	})
	require.NoError(t, err)
	require.Nil(t, awaitOp(t, ctx, opsRepo, op1.ID).Error)

	// Capture cutoff C1.
	var c1 time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&c1))

	// Concurrent duplicate deliveries of the SAME recovery_jti (at-least-once).
	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			dop, derr := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
				ExternalID: "krt_alice", RecoveryJTI: "rec_flow_001", Email: "alice@example.com",
			})
			if derr == nil && dop != nil {
				_ = awaitOp(t, ctx, opsRepo, dop.ID).Error
			}
		}()
	}
	wg.Wait()

	// Cutoff did NOT move forward (no second cutoff).
	var c2 time.Time
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&c2))
	assert.WithinDuration(t, c1, c2, time.Millisecond,
		"duplicate delivery must NOT advance the cutoff (monotonicity preserved relative to recovery moment)")

	// Exactly one audit row, exactly one ledger row.
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_001"), "no duplicate audit row")
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_001").Scan(&ledgerN))
	assert.Equal(t, 1, ledgerN, "exactly one ledger row")
}

// ── S07 — mid-tx failure → full rollback, no stuck idempotency key ────────
func TestOnRecoveryCompleted_S07_MidTxFailure_FullRollback(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	realRepo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	uid, _ := seedAccountAndUser(t, ctx, pool, "krt_dan", "dan@example.com", "BLOCKED")

	// Fault-injection: a repo whose Writer fails on EmitAuditEvent (after the
	// idempotency-insert + cutoff, before commit) → full rollback.
	faulty := &faultyAuditRepo{Repository: realRepo}
	uc := userapp.NewOnRecoveryCompletedUseCase(faulty, opsRepo)

	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_dan", RecoveryJTI: "rec_flow_007", Email: "dan@example.com",
	})
	require.NoError(t, err, "sync stages pass; the fault is inside the async writer-tx")
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.NotNil(t, done.Error, "operation must fail")

	// Full rollback: status stays BLOCKED, no cutoff, no audit, no ledger row.
	var statusDB string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uid)).Scan(&statusDB))
	assert.Equal(t, "BLOCKED", statusDB, "состояние не тронуто")

	var cutoffN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`, string(uid)).Scan(&cutoffN))
	assert.Equal(t, 0, cutoffN, "cutoff rolled back")

	assert.Equal(t, 0, auditRowCount(t, ctx, pool, "rec_flow_007"), "audit rolled back")

	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, "rec_flow_007").Scan(&ledgerN))
	assert.Equal(t, 0, ledgerN, "no stuck idempotency key — flow can be reprocessed")
}

// addMembership — членство человека в аккаунте, написанное сырым SQL.
//
// Сырым намеренно: предмет S09 — многоаккаунтная личность, и она обязана быть
// СОБРАНА пробой, а не получиться побочно от пути приглашения. Идентификатор
// чеканит та же функция, что и зеркало (`membership_mirror_id`), поэтому
// повторный вызов не заводит второго членства в том же аккаунте.
func addMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	userID domain.UserID, accID domain.AccountID, state string,
) {
	t.Helper()
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.memberships (id, user_id, account_id, state)
		VALUES (kacho_iam.membership_mirror_id($1, $2), $1, $2, $3)
		ON CONFLICT (user_id, account_id) DO UPDATE SET state = EXCLUDED.state`,
		string(userID), string(accID), state)
	require.NoError(t, err, "посев членства")
}

// ── S09 — одна личность Kratos, состоящая в НЕСКОЛЬКИХ аккаунтах ──────────
//
// # Что здесь стояло раньше и почему фикстура переписана
//
// Многоаккаунтность собиралась ДВУМЯ строками пользователя на одну почту:
// заблокированная в аккаунте A и приглашённая в аккаунте B. Такого состояния
// больше не бывает — `users_identity_email_uniq`
// (20260823050000_users_identity_uniqueness_goes_global) держит одну строку на
// человека, и посев второй падал на 23505 ещё до того, как сценарий начинался.
//
// СВОЙСТВО при этом никуда не делось и осталось ровно тем же: человек
// по-прежнему может состоять в нескольких аккаунтах — теперь это выражено
// ЧЛЕНСТВАМИ, а не строками. Поэтому переписана фикстура, а утверждения
// сохранены дословно по смыслу:
//
//   - восстановление НЕ снимает административный запрет: заблокированная строка
//     остаётся заблокированной;
//   - отсечка сессий ставится и на ней — учётные данные только что сменили,
//     и живые сессии обрубаются независимо от того, разрешено ли входить;
//   - отсечка ставится НА ЧЕЛОВЕКА, а не на членство, поэтому одна её строка
//     накрывает все аккаунты, в которых он состоит; членства при этом не
//     трогаются вовсе — восстановление не есть операция над принадлежностью;
//   - посторонний, оказавшийся в том же аккаунте, не задет ничем.
//
// # Почему посторонний, а не «приглашённый близнец»
//
// Прежний отрицательный контроль опирался на вторую строку той же почты с
// пустым внешним субъектом. Строка была неотличима от личности, и контроль
// заодно утверждал, что резолв по внешнему субъекту не хватает лишнего.
// Личность теперь одна, и тот же вопрос задаётся честнее: в аккаунте сидит
// ДРУГОЙ человек со своей почтой, и он обязан остаться нетронутым. Без этого
// контроля «строка заблокирована и отсечена» зеленело бы и у обработчика,
// который отсекает всех подряд.
func TestOnRecoveryCompleted_S09_MultiAccountIdentity_RevokeAll(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)
	opsRepo := operations.NewRepo(pool, "kacho_iam")

	// Личность: одна строка, заблокирована, домашний аккаунт — accA.
	u1, accA := seedAccountAndUser(t, ctx, pool, "krt_eve", "eve@example.com", "BLOCKED")
	// Посторонний в аккаунте accB: своя почта, ждёт первого входа.
	uBystander, accB := seedAccountAndUser(t, ctx, pool, "", "bystander-eve@example.com", "PENDING")
	// Личность состоит и в accB тоже — вот она, многоаккаунтность.
	addMembership(t, ctx, pool, u1, accB, "ACTIVE")

	before := membershipsOf(t, ctx, pool, u1)
	require.Len(t, before, 2,
		"ПРЕДПОСЫЛКА сценария: личность обязана состоять в ДВУХ аккаунтах — "+
			"на одноаккаунтной фикстуре проба проверяла бы не то, что называет")
	require.ElementsMatch(t, []string{string(accA), string(accB)},
		[]string{before[0].AccountID, before[1].AccountID})

	uc := userapp.NewOnRecoveryCompletedUseCase(repo, opsRepo)
	op, err := uc.Execute(ctx, userapp.OnRecoveryCompletedInput{
		ExternalID: "krt_eve", RecoveryJTI: "rec_flow_009", Email: "eve@example.com",
	})
	require.NoError(t, err)
	done := awaitOp(t, ctx, opsRepo, op.ID)
	require.Nil(t, done.Error)

	// Строка личности остаётся заблокированной — восстановление запрет не снимает.
	var s1 string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(u1)).Scan(&s1))
	assert.Equal(t, "BLOCKED", s1, "восстановление не отменяет административный запрет")

	// Отсечка ставится на ЧЕЛОВЕКА: одна строка на все его аккаунты.
	var cutoffN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`, string(u1)).Scan(&cutoffN))
	assert.Equal(t, 1, cutoffN,
		"отсечка принадлежит личности, а не членству: двух её быть не должно, "+
			"сколько бы аккаунтов человек ни назвал своими")
	var reason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT reason FROM user_token_revocations WHERE user_id = $1`, string(u1)).Scan(&reason))
	assert.Equal(t, "password-change", reason)

	// Членства не тронуты: восстановление — не операция над принадлежностью.
	after := membershipsOf(t, ctx, pool, u1)
	require.Len(t, after, 2, "восстановление не вправе ни завести, ни снять членство")
	assert.ElementsMatch(t,
		[]string{before[0].ID, before[1].ID},
		[]string{after[0].ID, after[1].ID},
		"те же самые членства, а не пересозданные")

	// Отрицательный контроль: посторонний в том же аккаунте не задет.
	var sBystander string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM users WHERE id = $1`, string(uBystander)).Scan(&sBystander))
	assert.Equal(t, "PENDING", sBystander,
		"чужая строка не участвует в восстановлении: её почта и субъект другие")
	var bystanderCutoffN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM user_token_revocations WHERE user_id = $1`,
		string(uBystander)).Scan(&bystanderCutoffN))
	assert.Equal(t, 0, bystanderCutoffN, "постороннему отсечка не ставится")

	// metadata: user_id = строка личности, count = 1 (затронута ровно она).
	meta, err := operations.MetadataFor[*iamv1.OnRecoveryCompletedMetadata](done)
	require.NoError(t, err)
	assert.Equal(t, string(u1), meta.GetUserId(), "metadata.user_id — строка личности")
	assert.Equal(t, int32(1), meta.GetRevokedSessionCount())

	// Одна запись журнала на одно восстановление личности.
	assert.Equal(t, 1, auditRowCount(t, ctx, pool, "rec_flow_009"))
}

// assertNoSideEffects — no cutoff / no audit / no ledger row for the given jti.
func assertNoSideEffects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, recoveryJTI string) {
	t.Helper()
	var auditN int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.audit_outbox
		 WHERE event_type = 'iam.user.recovery_completed'
		   AND event_payload->>'recovery_jti' = $1`, recoveryJTI).Scan(&auditN))
	assert.Equal(t, 0, auditN, "no audit row")
	var ledgerN int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM recovery_completions WHERE recovery_jti = $1`, recoveryJTI).Scan(&ledgerN))
	assert.Equal(t, 0, ledgerN, "no ledger row")
}

// faultyAuditRepo wraps a real Repository; its Writer fails on EmitAuditEvent so
// the recovery writer-tx fails AFTER the idempotency-insert + cutoff
// but BEFORE commit (fault-injection path). Everything else delegates to the
// real tx, so the rollback is the real Postgres rollback.
type faultyAuditRepo struct {
	*kachopg.Repository
}

func (r *faultyAuditRepo) Writer(ctx context.Context) (kachorepo.Writer, error) {
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return &faultyAuditWriter{Writer: w}, nil
}

type faultyAuditWriter struct {
	kachorepo.Writer
}

// EmitAuditEvent — injected fault: returns an error so the recovery writer-tx
// rolls back (the use-case maps the failure and rolls back via DoWithWriteTx).
func (w *faultyAuditWriter) EmitAuditEvent(context.Context, service.AuditEvent) error {
	return recoveryAuditFaultErr
}

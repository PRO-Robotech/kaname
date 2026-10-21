// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// upsert_invite_grant_fga_integration_test.go — RC-2 + RC-5 integration
// (testcontainers Postgres) on the live invite-activation lane: activation IN
// THE OUTCOME OF ADDRESS VERIFICATION (`userapp.ActivateInviteOnVerificationTx`,
// kaname#456) against a real DB, probing the transactional outbox rows + DB
// state. Прежде пробы шли через глагол заведения личности по внешнему
// удостоверению; он снят (kaname#929, AWI-09), а предмет проб — тело активации и
// заведения личных ресурсов — живёт на полосе подтверждения адреса.
//
// Scenarios:
//   T-I3 — invite-activation co-commits the member hierarchy tuple
//          (account:<A>#account@iam_user:<id>) IN THE SAME writer-tx as the
//          iam.user.updated audit-event + the ActivateInvite UPDATE (ban #10 atomic
//          co-commit through w.EmitFGARelationWrite, НЕ записью после коммита — она снята).
//   T-I5 — an invitee that owns ZERO accounts gets a personal default Account +
//          "default" Project bootstrapped (RC-5 gate), WITHOUT a 2nd InsertActive
//          (the invitee user-row already exists → a re-INSERT would 23505 on
//          UNIQUE(external_id)); the RC-2 inviter member-tuple co-exists.
//   T-E4(int) — repeated bootstrap is idempotent: still exactly ONE owned
//          personal account; a second activation of the already-ACTIVE row is
//          refused (the row is no longer PENDING) and changes nothing.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// seedInviterAndPendingInvite creates an ACTIVE inviter + its owned account, then
// a PENDING-invite-row for inviteeEmail under that account (the invitee user-row
// already exists; it owns no account). Returns inviter uid, account id, invitee
// pending user-id.
func seedInviterAndPendingInvite(t *testing.T, ctx context.Context, repo *kanamepg.Repository, suffix, inviteeEmail string) (domain.UserID, domain.AccountID, domain.UserID) {
	t.Helper()
	inviterID, accID := bootstrapAdmin(t, ctx, repo, suffix)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	inviteeID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, _, err = w.UsersW().InsertPending(ctx, domain.User{
		ID:           inviteeID,
		AccountID:    accID,
		Email:        domain.Email(inviteeEmail),
		DisplayName:  domain.DisplayName("Invitee"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    inviterID,
	}, time.Time{})
	require.NoError(t, err)
	_, err = kanamepg.WriterTx(w).Exec(ctx, activewayin.InviteePasswordSQL, string(inviteeID))
	require.NoError(t, err, "пароль приглашённого — до активации (kaname#456, kaname#608)")
	require.NoError(t, w.Commit(ctx))
	return inviterID, accID, inviteeID
}

func fgaOutboxCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, user, relation, object string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.fga_outbox
		 WHERE event_type = 'fga.tuple.write'
		   AND payload->>'user' = $1
		   AND payload->>'object' = $3
		   AND `+fga_outbox.RelationPredicate("payload", "$2"), user, relation, object).Scan(&n))
	return n
}

func auditUpdatedCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type = 'iam.user.updated'
		   AND event_payload->>'resource_id' = $1`, userID).Scan(&n))
	return n
}

func ownedAccountCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerUserID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.accounts WHERE owner_user_id = $1`, ownerUserID).Scan(&n))
	return n
}

// activeRowCountByExternalID — number of ACTIVE user-rows for an external_id
// (must stay 1 — a 2nd InsertActive would 23505 on UNIQUE(external_id)).
func activeRowCountByExternalID(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ext string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE external_id = $1 AND invite_status = 'ACTIVE'`, ext).Scan(&n))
	return n
}

// activateOnVerification — активация приглашения в исходе подтверждения адреса
// одним writer'ом, как у полосы входа (`ActivateInviteForLane`): строка
// приглашения читается, активируется, личность чеканится полосой, личные ресурсы
// заводятся той же транзакцией; затем фиксация.
func activateOnVerification(t *testing.T, ctx context.Context, repo *kanamepg.Repository, inviteeID domain.UserID) (userapp.BootstrapResult, error) {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	pending, err := rd.Users().Get(ctx, inviteeID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	res, err := userapp.ActivateInviteOnVerificationTx(ctx, w, pending, string(pending.ID))
	if err != nil {
		return userapp.BootstrapResult{}, err
	}
	require.NoError(t, w.Commit(ctx))
	return res, nil
}

// externalIDOf — личность строки, отчеканенная полосой при активации.
func externalIDOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID) string {
	t.Helper()
	var ext string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT external_id FROM kaname.users WHERE id = $1`, string(userID)).Scan(&ext))
	return ext
}

// ── T-I3 — RC-2 member-tuple co-committed with audit in the activation writer-tx ──────
func TestUpsertInviteGrant_TI3_RC2_MemberTupleCoCommitWithAudit(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const email = "invitee-ti3@example.com"
	_, accID, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti3", email)
	// Приглашённый подтвердил адрес — активация идёт только в этом исходе (kaname#456, Р11).
	markAddressVerified(t, ctx, pool, inviteeID)

	res, err := activateOnVerification(t, ctx, repo, inviteeID)
	require.NoError(t, err, "активация в исходе подтверждения адреса")
	require.Equal(t, inviteeID, res.User.ID, "активирована та же строка (id сохранён)")

	// PENDING → ACTIVE, id preserved, identity minted by our lane.
	var status, gotExt string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status, external_id FROM kaname.users WHERE id = $1`, string(inviteeID)).
		Scan(&status, &gotExt))
	assert.Equal(t, "ACTIVE", status, "invite activated")
	assert.Equal(t, string(res.User.ExternalID), gotExt, "external_id set on the SAME row (id preserved)")
	assert.NotEmpty(t, gotExt, "личность отчеканена полосой при активации")

	// iam.user.updated audit-event present for the activated row.
	assert.GreaterOrEqual(t, auditUpdatedCount(t, ctx, pool, string(inviteeID)), 1,
		"iam.user.updated audit-event emitted on activation")

	// RC-2: member hierarchy-tuple intent co-committed (account:<A>#account@iam_user:<id>).
	memberTuples := fgaOutboxCount(t, ctx, pool,
		"account:"+string(accID), "account", "iam_user:"+string(inviteeID))
	assert.Equal(t, 1, memberTuples,
		"exactly one RC-2 member hierarchy-tuple intent must be co-committed with activation")
}

// T-I3 atomicity — a rolled-back activation tx leaves NEITHER the audit row NOR the
// fga member-tuple intent. We assert the co-commit invariant directly on the
// writer-tx (the only way both rows can appear/disappear atomically is via the
// SAME w.EmitFGARelationWrite + w.EmitAuditEvent on one pgx.Tx).
func TestUpsertInviteGrant_TI3_RC2_RollbackDiscardsBoth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const email = "invitee-ti3rb@example.com"
	_, accID, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti3rb", email)

	// Replicate the activation writer-tx shape, then ROLLBACK: activate + audit + fga
	// member-tuple, all on one tx, abandoned.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	markAddressVerified(t, ctx, pool, inviteeID)
	_, err = w.UsersW().ActivateInvite(ctx, inviteeID,
		domain.ExternalSubject("ext_INV_ti3rb"), domain.DisplayName("Rolled Back"))
	require.NoError(t, err)
	memberTuple := fmt.Sprintf("iam_user:%s", inviteeID)
	require.NoError(t, w.EmitFGARelationWrite(ctx, []service.RelationTuple{{
		User: "account:" + string(accID), Relation: "account", Object: memberTuple,
	}}))
	require.NoError(t, w.Rollback(ctx))

	// Neither outbox row visible (atomic discard).
	assert.Equal(t, 0, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accID), "account", memberTuple),
		"rolled-back fga member-tuple intent must not be visible")
	// Still PENDING.
	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM kaname.users WHERE id = $1`, string(inviteeID)).Scan(&status))
	assert.Equal(t, "PENDING", status, "rolled-back activation leaves row PENDING")
}

// ── T-I5 — RC-5 bootstrap fires for invitee owning zero accounts, no 2nd InsertActive ──
func TestUpsertInviteGrant_TI5_RC5_BootstrapFiresOwnsZero_NoSecondInsertActive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const email = "invitee-ti5@example.com"
	_, accA, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "ti5", email)
	// Приглашённый подтвердил адрес — активация идёт только в этом исходе (kaname#456, Р11).
	markAddressVerified(t, ctx, pool, inviteeID)

	// Pre-condition: invitee owns ZERO accounts.
	require.Equal(t, 0, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"pre-state: invitee owns no account")

	res, err := activateOnVerification(t, ctx, repo, inviteeID)
	require.NoError(t, err, "активация с заведением личных ресурсов — без 23505 от второй вставки строки")
	ext := externalIDOf(t, ctx, pool, inviteeID)

	// ActivateInvite ran, id preserved, exactly one ACTIVE row (no 2nd InsertActive).
	assert.Equal(t, 1, activeRowCountByExternalID(t, ctx, pool, ext),
		"exactly one ACTIVE user-row (no duplicate InsertActive → no 23505)")
	var status string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status FROM kaname.users WHERE id = $1`, string(inviteeID)).Scan(&status))
	assert.Equal(t, "ACTIVE", status, "invitee activated on the existing row")

	// RC-5: bootstrap fired → exactly ONE personal account owned by the invitee.
	assert.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"RC-5: invitee now owns exactly one personal account")

	// the personal account has a "default" project.
	var personalAcc string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.accounts WHERE owner_user_id = $1`, string(inviteeID)).Scan(&personalAcc))
	var defaultPrjCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.projects WHERE account_id = $1 AND name = 'default'`, personalAcc).
		Scan(&defaultPrjCount))
	assert.Equal(t, 1, defaultPrjCount, `RC-5: personal account has a "default" project`)

	// 2 self-admin AccessBindings (account + project) for the invitee on personal scope.
	var abCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings ab
		   WHERE ab.subject_id = $1 AND ab.revoked_at IS NULL
		     AND ( (ab.resource_type='account' AND ab.resource_id=$2)
			OR (ab.resource_type='project' AND ab.resource_id IN
			      (SELECT id FROM kaname.projects WHERE account_id=$2)) )`,
		string(inviteeID), personalAcc).Scan(&abCount))
	assert.Equal(t, 2, abCount, "RC-5: 2 self-admin AccessBindings on personal scope")

	// bootstrapTuples intents present for the personal graph (owner + member hierarchy).
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"user:"+string(inviteeID), "owner", "account:"+personalAcc),
		"RC-5: owner grant on personal account")
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"account:"+personalAcc, "account", "iam_user:"+string(inviteeID)),
		"RC-5: user→personal-account hierarchy")

	// RC-2 inviter member-tuple ALSO emitted (membership in inviter's account A).
	assert.Equal(t, 1, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accA), "account", "iam_user:"+string(inviteeID)),
		"RC-2: inviter member-tuple co-exists with RC-5 personal bootstrap")

	// The bootstrap reused the activated row, not a new identity.
	assert.Equal(t, inviteeID, res.User.ID, "заведение личных ресурсов — на активированной строке")
	assert.Equal(t, domain.AccountID(personalAcc), res.AccountID, "личный аккаунт исхода — тот, что заведён")
}

// ── T-E4 (integration) — idempotent re-activation: still exactly one owned account ──
func TestUpsertInviteGrant_TE4_RC5_ReActivateIdempotent_SingleOwnedAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const email = "invitee-te4@example.com"
	_, accA, inviteeID := seedInviterAndPendingInvite(t, ctx, repo, "te4", email)
	// Приглашённый подтвердил адрес — активация идёт только в этом исходе (kaname#456, Р11).
	markAddressVerified(t, ctx, pool, inviteeID)

	// First activation.
	first, err := activateOnVerification(t, ctx, repo, inviteeID)
	require.NoError(t, err)
	require.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"first activation → one owned account")
	ext := externalIDOf(t, ctx, pool, inviteeID)

	// Повторная активация уже ACTIVE строки: оператор активации её не находит
	// (строка не PENDING), транзакция откатывается, ничего не меняется.
	_, err = activateOnVerification(t, ctx, repo, inviteeID)
	require.ErrorIs(t, err, iamerr.ErrNotFound, "повторная активация отвергнута: строка уже не PENDING")

	// Повторное заведение личных ресурсов той же личностью: под транзакционной
	// блокировкой число собственных аккаунтов уже ненулевое, и второго заведения
	// нет — возвращается та же строка.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	again, err := userapp.BootstrapPersonalResourcesTx(ctx, w, userapp.BootstrapInput{
		CandidateUserID: string(inviteeID), ExternalID: domain.ExternalSubject(ext),
		Email: domain.Email(email), Actor: "system", NewIdentity: false,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, first.User.ID, again.User.ID, "та же строка человека")

	assert.Equal(t, 1, ownedAccountCount(t, ctx, pool, string(inviteeID)),
		"RC-5 idempotent: still exactly one owned personal account after a repeated bootstrap")
	assert.Equal(t, 1, activeRowCountByExternalID(t, ctx, pool, ext),
		"still exactly one ACTIVE row")
	// member tuple in inviter account still present.
	assert.GreaterOrEqual(t, fgaOutboxCount(t, ctx, pool,
		"account:"+string(accA), "account", "iam_user:"+string(inviteeID)), 1,
		"inviter member-tuple intent present (at-least-once, idempotent drain)")
}

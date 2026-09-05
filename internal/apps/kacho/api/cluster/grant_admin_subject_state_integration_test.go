// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// grant_admin_subject_state_integration_test.go — GrantAdmin судит СОСТОЯНИЕ
// субъекта, а не его наличие.
//
// Право уровня кластера, выданное личности, которой запрещено
// аутентифицироваться, не исчезает вместе с запретом: оно лежит и ждёт. В тот
// день, когда запрет снимут, у личности окажется полный доступ, которого ей
// никто осознанно не давал — выдача произошла тогда, когда решение принимал
// вопрос «есть ли такая строка».
//
// Здесь проверяется наблюдаемый исход: заблокированному пользователю и
// отключённой служебной учётке право НЕ выдаётся, отказ называет причину и
// отличается от «не найдено», и строки в cluster_admin_grants после отказа нет.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// mustSeedBlockedUser сеет пользователя в состоянии BLOCKED (+ его аккаунт).
// DB-CHECK users_invite_status_consistency требует непустой external_id для
// ACTIVE/BLOCKED — поэтому он заполнен.
func mustSeedBlockedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'BLOCKED')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-blocked-%s-%s", suffix, uid),
		fmt.Sprintf("blocked-%s@example.com", suffix),
		"Blocked User "+suffix,
	)
	require.NoError(t, err, "seed BLOCKED user")

	_, err = tx.Exec(ctx, `
		INSERT INTO kacho_iam.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("blocked-acc-%s", accID[len(accID)-6:]),
		string(uid),
	)
	require.NoError(t, err, "seed account of BLOCKED user")

	require.NoError(t, tx.Commit(ctx))
	return uid
}

// mustSeedServiceAccount сеет служебную учётку с заданным `enabled` (+ аккаунт
// и его владельца, т.к. accounts.owner_user_id — FK на users).
func mustSeedServiceAccount(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string, enabled bool,
) domain.ServiceAccountID {
	t.Helper()
	owner := mustSeedUser(t, ctx, pool, "sa-owner-"+suffix)

	var accID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT account_id FROM kacho_iam.users WHERE id = $1`, string(owner)).Scan(&accID))

	svaID := domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.service_accounts (id, account_id, name, description, labels, enabled)
		VALUES ($1, $2, $3, '', '{}'::jsonb, $4)`,
		string(svaID), accID, fmt.Sprintf("sa-%s-%s", suffix, svaID[len(svaID)-6:]), enabled)
	require.NoError(t, err, "seed service account")
	return svaID
}

func countGrantRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subject string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.cluster_admin_grants WHERE subject_id = $1`,
		subject).Scan(&n))
	return n
}

// TestCluster_GrantAdmin_RefusesBlockedUser — заблокированный пользователь
// существует, и именно поэтому проверка на наличие его пропускала.
func TestCluster_GrantAdmin_RefusesBlockedUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "callerblockedcase")
	target := mustSeedBlockedUser(t, ctx, pool, "target")

	h := buildHandler(t, dsn)
	_, err := h.GrantAdmin(withPrincipal(ctx, string(caller)), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(target),
	})

	require.Error(t, err, "cluster admin must not be granted to a blocked user")
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"состояние субъекта не позволяет выдать право — это не «неверный аргумент» и не «не найдено»")
	require.Equal(t, fmt.Sprintf("User %s is blocked", target), status.Convert(err).Message(),
		"отказ обязан назвать причину, а не выдать себя за отсутствие строки")
	require.Zero(t, countGrantRows(t, ctx, pool, string(target)),
		"после отказа в cluster_admin_grants не должно остаться строки")
}

// TestCluster_GrantAdmin_RefusesDisabledServiceAccount — машинная половина того
// же вопроса: `enabled=false` означает «не вправе аутентифицироваться».
func TestCluster_GrantAdmin_RefusesDisabledServiceAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "callerdisabledcase")
	target := mustSeedServiceAccount(t, ctx, pool, "disabled", false)

	h := buildHandler(t, dsn)
	_, err := h.GrantAdmin(withPrincipal(ctx, string(caller)), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   string(target),
	})

	require.Error(t, err, "cluster admin must not be granted to a disabled service account")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, fmt.Sprintf("ServiceAccount %s is disabled", target), status.Convert(err).Message())
	require.Zero(t, countGrantRows(t, ctx, pool, string(target)))
}

// TestCluster_GrantAdmin_AllowsEnabledServiceAccount — контрольный случай той
// же формы: гейт обязан молчать на субъекте, состояние которого позволяет.
// Без него проверка выше доказывает лишь «что-то отказывает».
func TestCluster_GrantAdmin_AllowsEnabledServiceAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "callerenabledcase")
	target := mustSeedServiceAccount(t, ctx, pool, "enabled", true)

	h := buildHandler(t, dsn)
	op, err := h.GrantAdmin(withPrincipal(ctx, string(caller)), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT,
		SubjectId:   string(target),
	})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	require.Equal(t, 1, countGrantRows(t, ctx, pool, string(target)))
}

// TestCluster_GrantAdmin_RefusesPendingInvitee — приглашение, которое ещё никто
// не подтвердил, external_id не несёт: подтвердит его тот, кто первым войдёт по
// этому адресу почты. Право уровня кластера, повешенное на такую строку,
// достанется именно ему.
func TestCluster_GrantAdmin_RefusesPendingInvitee(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "callerpendingcase")

	// PENDING-строка: DB-CHECK требует external_id='' для этого состояния.
	owner := mustSeedUser(t, ctx, pool, "pendinghost")
	var accID string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT account_id FROM kacho_iam.users WHERE id = $1`, string(owner)).Scan(&accID))
	invitee := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO kacho_iam.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, 'Invitee', 'PENDING')`,
		string(invitee), accID, fmt.Sprintf("pending-%s@example.com", invitee[len(invitee)-6:]))
	require.NoError(t, err)

	h := buildHandler(t, dsn)
	_, err = h.GrantAdmin(withPrincipal(ctx, string(caller)), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   string(invitee),
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, fmt.Sprintf("User %s is not active", invitee), status.Convert(err).Message(),
		"причина называется точно: это не блокировка, а неподтверждённое приглашение")
	require.Zero(t, countGrantRows(t, ctx, pool, string(invitee)))
}

// TestCluster_GrantAdmin_MissingSubjectStaysDistinct — отсутствие строки
// по-прежнему отличимо от запрета: коды разные, тексты разные.
func TestCluster_GrantAdmin_MissingSubjectStaysDistinct(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool := poolFromDSN(t, dsn)

	caller := mustSeedUser(t, ctx, pool, "callerabsentcase")
	absent := ids.NewID(domain.PrefixUser)

	h := buildHandler(t, dsn)
	_, err := h.GrantAdmin(withPrincipal(ctx, string(caller)), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_USER,
		SubjectId:   absent,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, fmt.Sprintf("User %s not found", absent), status.Convert(err).Message())
}

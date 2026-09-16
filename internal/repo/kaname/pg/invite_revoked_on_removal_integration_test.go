// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invite_revoked_on_removal_integration_test.go — снятие участия обесценивает
// НЕВЫКУПЛЕННОЕ приглашение (приёмка ID-MAIL-1, §10 п. 16, MAIL-24/MAIL-46).
//
// Утверждение сформулировано по ИСХОДУ глагола — «человек перестал быть
// участником», — а не по его имени: новый глагол того же смысла попадает под
// него по построению, и это же требует гейт дерева
// (`internal/check/membership_removal_expires_invite.go`).

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestInviteRevoked_RemovalOfTheOnlyMembershipDevaluesTheInvite — ОТРИЦАНИЕ.
func TestInviteRevoked_RemovalOfTheOnlyMembershipDevaluesTheInvite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail46a")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "excluded@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Исключение из аккаунта — ДО первого входа.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	removed, rerr := w2.UsersW().RemoveMembership(ctx, pending.ID, accID)
	require.NoError(t, rerr)
	require.NoError(t, w2.Commit(ctx))
	assert.True(t, removed, "членство обязано было сняться — иначе проба судит не тот путь")

	// Первый вход после исключения: строка НЕ активируется.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, aerr := w3.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("sub-mail46a"), domain.DisplayName("Real"))
	_ = w3.Rollback(ctx)
	require.Error(t, aerr)
	assert.True(t, stderrors.Is(aerr, iamerr.ErrInviteExpired),
		"невыкупленное приглашение пережило снятие участия: %v", aerr)
}

// TestInviteRevoked_SecondMembershipKeepsTheInviteAlive — ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ и граница правки.
//
// Строка приглашения ГЛОБАЛЬНА: обесценив её при исключении из ОДНОГО аккаунта,
// правка отняла бы у человека приглашения в остальные — молча. Без этой пробы
// отрицание выше зеленело бы и на такой поломке.
func TestInviteRevoked_SecondMembershipKeepsTheInviteAlive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "mail46b1")
	_, accB := bootstrapAdmin(t, ctx, repo, "mail46b2")

	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accA,
		Email:        "twoaccounts@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Второе приглашение — той же почты во ВТОРОЙ аккаунт: строка одна,
	// членств два.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, _, err = w2.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accB,
		Email:        "twoaccounts@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	// Исключение из ПЕРВОГО аккаунта.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	removed, rerr := w3.UsersW().RemoveMembership(ctx, pending.ID, accA)
	require.NoError(t, rerr)
	require.NoError(t, w3.Commit(ctx))
	require.True(t, removed)

	// Приглашение во ВТОРОЙ аккаунт по-прежнему выкупается.
	w4, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, aerr := w4.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("sub-mail46b"), domain.DisplayName("Real"))
	require.NoError(t, aerr, "исключение из ОДНОГО аккаунта отняло приглашение в остальные")
	require.NoError(t, w4.Commit(ctx))
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
}

// TestInviteRevoked_RemovalDoesNotTouchARedeemedRow — второй положительный
// контроль: у ВЫКУПЛЕННОГО участника исключение из аккаунта не трогает ни
// одного поля строки личности. Человек, исключённый из аккаунта A, продолжает
// работать в аккаунте B — это контракт `RemoveMembership`, и правка его не
// меняет.
func TestInviteRevoked_RemovalDoesNotTouchARedeemedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail46c")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	before, err := rd.Users().Get(ctx, adminID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.Equal(t, domain.InviteStatusActive, before.InviteStatus)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, rerr := w.UsersW().RemoveMembership(ctx, adminID, accID)
	require.NoError(t, rerr)
	require.NoError(t, w.Commit(ctx))

	rd2, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd2.Rollback(ctx) }()
	after, err := rd2.Users().Get(ctx, adminID)
	require.NoError(t, err)
	assert.Equal(t, domain.InviteStatusActive, after.InviteStatus,
		"исключение изменило состояние ВЫКУПЛЕННОЙ строки")
}

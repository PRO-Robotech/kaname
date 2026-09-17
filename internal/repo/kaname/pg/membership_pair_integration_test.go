// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// membership_pair_integration_test.go — чтение членства ПАРОЙ «человек ×
// аккаунт» внутри транзакции писателя (kaname#181).
//
// Зачем это чтение, когда есть аккаунт-скоупные `Get`/`List`. Те открывают СВОЮ
// сессию на пуле чтения — на реплике, если она есть, — и ответ создания,
// собранный ими после коммита, мог бы не увидеть строки, только что записанной
// на мастере. Ответ операции создания обязан быть тем, что записала ЕЁ
// транзакция, поэтому строка читается ЕЮ ЖЕ, до фиксации.
//
// Проекция при этом ОДНА на все чтения членства: те же колонки, то же зеркало
// имени аккаунта, тот же тон отсутствия.

import (
	"context"
	"errors"
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

// TestUserReader_KAN181_MembershipOfPairReadsInsideTheWriterTx — строка,
// заведённая вставкой приглашения, читается ТОЙ ЖЕ транзакцией, до коммита, и
// приходит с зеркалом имени аккаунта.
func TestUserReader_KAN181_MembershipOfPairReadsInsideTheWriterTx(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mp181")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()

	invited, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accID,
		Email:        domain.Email("pair-mp181@example.com"),
		DisplayName:  domain.DisplayName("Pair"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Time{})
	require.NoError(t, err)
	require.True(t, inserted)

	// ЧТЕНИЕ ДО КОММИТА — той же транзакцией.
	m, err := w.Users().Membership(ctx, invited.ID, accID)
	require.NoError(t, err, "строка, записанная этой транзакцией, обязана быть ей видна")
	assert.Regexp(t, `^mbr-[0-9a-z]{17}$`, string(m.ID))
	assert.Equal(t, invited.ID, m.UserID)
	assert.Equal(t, accID, m.AccountID)
	assert.NotEmpty(t, string(m.AccountName), "зеркало имени аккаунта заполнено соединением")
	assert.Equal(t, domain.MembershipStatePending, m.State)
	assert.Equal(t, adminID, m.InvitedBy)
	assert.False(t, m.CreatedAt.IsZero())
	assert.False(t, m.UpdatedAt.IsZero())

	// Отсутствующая пара — тон отсутствия членства, а не пустая строка.
	_, err = w.Users().Membership(ctx, invited.ID, domain.AccountID(ids.NewID(domain.PrefixAccount)))
	require.Error(t, err)
	assert.True(t, errors.Is(err, iamerr.ErrNotFound), "пары нет — ErrNotFound, получено: %v", err)
}

// TestUserReader_KAN181_MembershipOfPairMatchesAccountScopedGet — ОДНА проекция:
// пара и аккаунт-скоупное одиночное чтение возвращают побайтово равные строки.
func TestUserReader_KAN181_MembershipOfPairMatchesAccountScopedGet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mp182")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	byPair, err := rd.Users().Membership(ctx, adminID, accID)
	require.NoError(t, err)

	s, err := repo.MembershipReader(ctx)
	require.NoError(t, err)
	defer s.Close(ctx)
	byScoped, err := s.Memberships().Get(ctx, accID, byPair.ID)
	require.NoError(t, err)

	assert.Equal(t, byScoped, byPair, "две дороги к одной строке дают одну и ту же проекцию")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reset_access_keys_holder_line_integration_test.go — ЛИНИЯ ДЕРЖАТЕЛЯ сброса
// ключей доступа на НАСТОЯЩЕЙ базе (задача PRO-Robotech/kaname#638; приёмка
// `cloud-administrator-resets-login-methods.md`, редакция 5, Р2, LMR-03):
// держатель, прошедший край, получает от службы линию прямого чтения —
// несуществующий well-formed `user_id` — `NOT_FOUND` `User <id> not found`,
// кривой — `INVALID_ARGUMENT` `invalid user id '<X>'`; существующий человек без
// ключей в 404 не попадает (положительный контроль: реальный репозиторий его
// находит, и судится состояние — «ключей нет»).
//
// Настоящий Postgres. Пропускается под кратким режимом.

package user

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// TestResetAccessKeysHolderLineOnBadIdsFromRealDB — LMR-03, линия держателя.
func TestResetAccessKeysHolderLineOnBadIdsFromRealDB(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsnWithSchema(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)
	uc := NewResetAccessKeysUseCase(repo, nil, kanamepg.NewLoginMethodRepo(pool), nil).WithCutoffClock(momentclock.Func(time.Now))

	const badForm = "not-a-user-id"
	_, err = uc.Execute(ownerCtx(), domain.UserID(badForm))
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err), "кривой id — 400, раньше чтения")
	require.Equal(t, "invalid user id '"+badForm+"'", status.Convert(err).Message())

	absent := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = uc.Execute(ownerCtx(), absent)
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err), "промах — 404")
	require.Equal(t, "User "+string(absent)+" not found", status.Convert(err).Message())

	present, _ := seedUserWithAccount(t, ctx, pool, "rak1")
	_, err = uc.Execute(ownerCtx(), present)
	require.Error(t, err, "у существующего человека ключей нет — отказ состояния")
	require.NotEqualf(t, codes.NotFound, status.Code(err), "существующий человек получил 404 — промах выше вакуумен")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "user has no access key to reset", status.Convert(err).Message())
}

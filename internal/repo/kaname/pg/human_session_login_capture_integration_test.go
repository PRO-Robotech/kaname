// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// human_session_login_capture_integration_test.go — ЗАХВАТ СТРОКИ ЛИЧНОСТИ
// ТРАНЗАКЦИЕЙ ВЫДАЧИ ВХОДА (задача kaname#385; приёмка «вход, встретивший
// принудительный выход, не выдаёт сессии, которую отсечка уже накрыла», Р4).
//
// Операция писателя сессии берёт строку личности замком `FOR SHARE` и отвечает
// стоящей отсечкой личности. Здесь утверждается то, что видно на самом
// адаптере, одной транзакцией и чужими попытками замка без ожидания:
//
//   - сила: после захвата писатель нескольких сессий (`FOR NO KEY UPDATE`) и
//     удаление (`FOR UPDATE`) отказывают `55P03`, а второй захват той же силы
//     и проверка внешнего ключа (`FOR KEY SHARE`) проходят. Контроль — до
//     захвата строку не держит никто;
//   - четыре исхода различимы: отсечки нет — отдельный ответ, а не нулевой
//     момент; отсечка T — T в разрешении хранилища; строки нет — `NOT_FOUND`;
//     пустая личность — отказ аргументом;
//   - одна транзакция не держит строк двух личностей: захват второй личности
//     отказывает `INTERNAL`, повтор той же — проходит.
//
// Сценарии полосы (ожидание выхода на захвате, чтение отсечки после ожидания,
// второй вход того же человека) — `internal/handler/loginlanehttp/login_overlap_*`.

import (
	"context"
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func TestIntegration_LoginCaptureHoldsThePersonRowForShareAndAnswersTheCutoff(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.NewHumanSessionRepo(pool)
	plain := ceremonyScene(t, ctx, pool, "cptra")
	covered := ceremonyScene(t, ctx, pool, "cptrbb")

	// Отсечка личности covered моментом с долей ниже микросекунды: хранилище
	// держит её до микросекунды, и ответ захвата — в его разрешении.
	cutoff := time.Date(2026, 9, 16, 12, 0, 0, 123456789, time.UTC)
	cw, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, cw.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: domain.UserID(covered.UserID), RevokeBefore: cutoff, Reason: domain.RevokeReasonAdminForceLogout,
	}, ""), "фикстура: отсечка личности")
	require.NoError(t, cw.Commit(ctx))

	t.Run("сила — FOR SHARE", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		require.NoError(t, personRowLockAttempt(t, ctx, pool, plain.UserID, "NO KEY UPDATE"),
			"фикстура: до захвата строку личности не держит никто")

		at, found, err := w.LockPersonForLogin(ctx, domain.UserID(plain.UserID))
		require.NoError(t, err)

		assert.False(t, found, "у личности без отсечки ответ «отсечки нет», а не момент %s", at)
		assert.True(t, at.IsZero(), "при «отсечки нет» момент не несёт значения: %s", at)
		for _, strength := range []string{"NO KEY UPDATE", "UPDATE"} {
			refused := personRowLockAttempt(t, ctx, pool, plain.UserID, strength)
			assert.Equal(t, "55P03", sqlState(refused),
				"захват не держит строку против `FOR %s`: снятие либо удаление прошли бы мимо открытой выдачи (%v)", strength, refused)
		}
		for _, strength := range []string{"SHARE", "KEY SHARE"} {
			assert.NoError(t, personRowLockAttempt(t, ctx, pool, plain.UserID, strength),
				"захват сильнее `FOR SHARE`: он останавливает `FOR %s` — второй вход того же человека либо проверку внешнего ключа", strength)
		}
	})

	t.Run("отсечка T — в разрешении хранилища", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()

		at, found, err := w.LockPersonForLogin(ctx, domain.UserID(covered.UserID))
		require.NoError(t, err)

		require.True(t, found, "отсечка личности стоит — ответ обязан её назвать")
		assert.True(t, at.Equal(cutoff.Truncate(time.Microsecond)),
			"ответ захвата %s — не отсечка %s в разрешении хранилища", at.Format(time.RFC3339Nano),
			cutoff.Truncate(time.Microsecond).Format(time.RFC3339Nano))
	})

	t.Run("строки нет — NOT_FOUND", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()

		_, _, err = w.LockPersonForLogin(ctx, domain.UserID("usr"+ceremonyPad("cptrgoneu")))

		assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "захват личности, которой нет, обязан ответить NOT_FOUND: %v", err)
	})

	t.Run("пустая личность — отказ аргументом", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()

		_, _, err = w.LockPersonForLogin(ctx, "")

		assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg), "захват пустой личности обязан отказать аргументом: %v", err)
	})

	t.Run("та же личность дважды", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, _, err = w.LockPersonForLogin(ctx, domain.UserID(plain.UserID))
		require.NoError(t, err)

		_, _, err = w.LockPersonForLogin(ctx, domain.UserID(plain.UserID))

		assert.NoError(t, err, "повтор той же личности — не вторая личность")
	})

	t.Run("вторая личность", func(t *testing.T) {
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		defer func() { _ = w.Rollback(ctx) }()
		_, _, err = w.LockPersonForLogin(ctx, domain.UserID(plain.UserID))
		require.NoError(t, err)

		_, _, err = w.LockPersonForLogin(ctx, domain.UserID(covered.UserID))

		assert.True(t, stderrors.Is(err, iamerr.ErrInternal),
			"транзакция взяла строки двух личностей: две такие во встречном порядке личностей блокируют друг друга (%v)", err)
	})
}

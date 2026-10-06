// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// admission_carrier_map_integration_test.go — отказы инвариантов носителя окна
// темпа (приёмка A197, Р2; задача PRO-Robotech/kaname#197), пропущенные через
// отображение отказов хранилища службы, — `INTERNAL` с фиксированным текстом.
//
// Отказ берётся у НАСТОЯЩЕГО сервера (A197-05, A197-08, A197-09), а не
// собирается руками: что сервер кладёт в код, имя ограничения и сообщение,
// здесь захвачено. Рядом — положительный контроль соседней ветви той же полосы
// учёта темпа (`KQ004` отдаёт текст производителя дословно), без которого
// «INTERNAL» не отличалось бы от «отображение сломано целиком».

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// a197MapOwnLane — человек нашей полосы с личным аккаунтом (носитель база
// назначает сама).
func a197MapOwnLane(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) string {
	t.Helper()
	userID := ids.NewID(domain.PrefixUser)
	accountID := ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'a197-map', 'ACTIVE')`, userID, accountID, string(domain.NewOwnLaneSubject()), email)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): человек нашей полосы")
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
		accountID, "a197-map-"+strings.ToLower(userID[4:12]), userID)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): личный аккаунт")
	seedWayIn(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return userID
}

func a197MapAddr(tag string) string {
	return "map-" + tag + "-" + strings.ToLower(ids.NewID("tst")[3:9]) + "@example.invalid"
}

// requireAdmissionInternal — отказ отображён в INTERNAL, и в тексте нет ни
// SQLSTATE, ни имени столбца или ограничения, ни сообщения сервера.
func requireAdmissionInternal(t *testing.T, raw error, wantText string, leaks ...string) {
	t.Helper()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, raw, &pgErr, "НЕ-ВЫПОЛНИЛОСЬ: отказ обязан прийти от сервера: %v", raw)
	mapped := wrapPgErr(raw, "", "")
	require.Truef(t, stderrors.Is(mapped, iamerr.ErrInternal), "отказ %s обязан быть INTERNAL, есть: %v", pgErr.Code, mapped)
	text := iamerr.StripSentinel(mapped)
	if wantText != "" {
		require.Equal(t, wantText, text, "фиксированный текст отказа %s", pgErr.Code)
	}
	for _, leak := range append(leaks, pgErr.Code, pgErr.Message, "admission_carrier") {
		if leak == "" {
			continue
		}
		require.NotContainsf(t, mapped.Error(), leak, "в тексте отказа %s утекло %q: %q", pgErr.Code, leak, mapped.Error())
	}
}

// TestA197_MapFixedCarrierAndMissingCarrierAreInternal — A197-05, A197-08,
// A197-09 (их строки «тот же отказ через отображение»).
func TestA197_MapFixedCarrierAndMissingCarrierAreInternal(t *testing.T) {
	pool := cvPool(t)
	ctx := context.Background()

	t.Run("A197-05: правка носителя — KQ006", func(t *testing.T) {
		userID := a197MapOwnLane(t, ctx, pool, a197MapAddr("own-g"))
		_, err := pool.Exec(ctx, `UPDATE kaname.users SET admission_carrier = 'own-z@example.invalid' WHERE id = $1`, userID)
		require.Error(t, err, "A197-05: правка носителя принята")
		requireAdmissionInternal(t, err, "admission rate accounting", userID)
	})

	t.Run("A197-09: присланный чужой носитель на вставке — KQ006", func(t *testing.T) {
		userID := ids.NewID(domain.PrefixUser)
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, admission_carrier)
			VALUES ($1, $2, $3, $4, 'a197-map', 'ACTIVE', 'own-z@example.invalid')`,
			userID, ids.NewID(domain.PrefixAccount), string(domain.NewOwnLaneSubject()), a197MapAddr("own-m"))
		require.Error(t, err, "A197-09: присланный чужой носитель принят")
		requireAdmissionInternal(t, err, "admission rate accounting", userID)
	})

	t.Run("A197-08: наша полоса без носителя — 23514 полосы службы", func(t *testing.T) {
		c, err := pool.Acquire(ctx)
		require.NoError(t, err)
		conn := c.Hijack()
		defer func() { _ = conn.Close(context.Background()) }()
		_, err = conn.Exec(ctx, `SET session_replication_role = replica`)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): режим реплики")
		_, err = conn.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, admission_carrier)
			VALUES ($1, $2, $3, $4, 'a197-map', 'ACTIVE', '')`,
			ids.NewID(domain.PrefixUser), ids.NewID(domain.PrefixAccount), string(domain.NewOwnLaneSubject()), a197MapAddr("own-k"))
		require.Error(t, err, "A197-08: строка нашей полосы без носителя принята")
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "users_own_lane_admission_carrier_check", pgErr.ConstraintName, "A197-08: ограничение названо сервером")
		requireAdmissionInternal(t, err, "", pgErr.ConstraintName)
	})

	t.Run("положительный контроль: KQ004 той же полосы отдаёт текст производителя", func(t *testing.T) {
		const rateText = "identity x has reached its admission rate of 1 iam.account per 3600 seconds"
		mapped := wrapPgErr(&pgconn.PgError{Code: "KQ004", Message: rateText}, "", "")
		require.Truef(t, stderrors.Is(mapped, iamerr.ErrQuotaRateExceeded), "KQ004 перестал быть ErrQuotaRateExceeded: %v", mapped)
		require.Equal(t, rateText, iamerr.StripSentinel(mapped))
	})
}

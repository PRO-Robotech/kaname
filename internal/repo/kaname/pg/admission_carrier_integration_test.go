// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// admission_carrier_integration_test.go — НОСИТЕЛЬ окна темпа заведения
// закрепляется в момент чеканки личности нашей полосы и не следует за адресом
// (приёмка `docs/engineering/acceptance/admission-rate-carrier-is-fixed-at-registration.md`,
// A197; задача PRO-Robotech/kaname#197).
//
// Сценарии уровня хранилища: A197-01 (смена адреса не открывает окно), A197-05
// (носитель не переписывается), A197-07 (полоса поставщика не тронута),
// A197-08 (личности нашей полосы без носителя не бывает), A197-09 (присланный
// чужой носитель отвергается, а не перезаписывается). Отображение тех же
// отказов в INTERNAL утверждается на настоящем отказе сервера —
// `admission_carrier_map_integration_test.go` (пакет адаптера).
//
// Каждое отрицание стоит рядом с близнецом, меняющим РОВНО один факт.
//
// Run: `make test` (Docker). Skipped under -short.

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// a197FixedCarrierText — сообщение сервера отказа KQ006 без идентификатора
// строки (Р2 п. 2): `admission carrier of user <id> is fixed when the identity is minted`.
func a197FixedCarrierText(userID string) string {
	return "admission carrier of user " + userID + " is fixed when the identity is minted"
}

// a197Carrier — носитель строки человека.
func a197Carrier(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) string {
	t.Helper()
	var c string
	require.NoError(t, pool.QueryRow(ctx, `SELECT admission_carrier FROM kaname.users WHERE id = $1`, userID).Scan(&c),
		"носитель строки человека %s", userID)
	return c
}

// a197Window — счётчик окна вида iam.account с носителем carrier; ok=false — окна нет.
func a197Window(t *testing.T, ctx context.Context, pool *pgxpool.Pool, carrier string) (admitted int, ok bool) {
	t.Helper()
	err := pool.QueryRow(ctx, `SELECT admitted FROM kaname.identity_admission_windows
		WHERE kind = 'iam.account' AND carrier_id = $1`, carrier).Scan(&admitted)
	if err == pgx.ErrNoRows {
		return 0, false
	}
	require.NoError(t, err)
	return admitted, true
}

func a197Accounts(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.accounts WHERE owner_user_id = $1`, userID).Scan(&n))
	return n
}

func a197Code(t *testing.T, err error) (code, message string) {
	t.Helper()
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "отказ обязан быть отказом сервера: %v", err)
	return pgErr.Code, pgErr.Message
}

// TestA197_01_AddressChangeDoesNotOpenAWindow — A197-01 и его близнец.
func TestA197_01_AddressChangeDoesNotOpenAWindow(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	for _, tc := range []struct {
		name, tag string
		ceiling   int64
		admit     bool
	}{
		{"потолок 1 — отказ рубежом темпа", "neg", 1, false},
		{"близнец: потолок 2 — заведение проходит по тому же окну", "pos", 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			email, userID := ownLaneFixture(t, ctx, pool, "a197-01-"+tc.tag)
			carrier := strings.ToLower(email)
			setAccountRateCeiling(t, ctx, pool, tc.ceiling, 3600)
			moved := "own-b-" + strings.ToLower(userID[4:10]) + "@example.invalid"
			_, err := pool.Exec(ctx, `UPDATE kaname.users SET email = $2 WHERE id = $1`, userID, moved)
			require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев смены адреса")

			err = insertAccount(ctx, pool, "a197-01-"+strings.ToLower(userID[4:10]), userID)
			if tc.admit {
				require.NoError(t, err, "A197-01 близнец: заведение при потолке 2 обязано пройти")
				n, ok := a197Window(t, ctx, pool, carrier)
				require.True(t, ok && n == 2, "A197-01 близнец: окно носителя %q продолжает считаться — ждали 2, есть %d (окно есть: %v)", carrier, n, ok)
				require.Equal(t, 2, a197Accounts(t, ctx, pool, userID))
			} else {
				require.Error(t, err, "A197-01: смена адреса открыла окно — заведение прошло при полном окне носителя")
				code, _ := a197Code(t, err)
				require.Equal(t, "KQ004", code, "A197-01: отказ рубежом темпа")
				require.Equal(t, 1, a197Accounts(t, ctx, pool, userID), "A197-01: аккаунт у человека по-прежнему один")
				n, ok := a197Window(t, ctx, pool, carrier)
				require.True(t, ok && n == 1, "A197-01: окно носителя %q — принято 1", carrier)
			}
			_, ok := a197Window(t, ctx, pool, moved)
			require.False(t, ok, "A197-01: окна с носителем нового адреса %q нет", moved)
			require.Equal(t, carrier, a197Carrier(t, ctx, pool, userID), "A197-01: носитель — адрес при чеканке")
		})
	}
}

// TestA197_05_CarrierIsFixedAtTheDatabaseLevel — A197-05: правка носителя
// отвергается KQ006 (на чужое значение и на пустое), запись того же значения
// проходит.
func TestA197_05_CarrierIsFixedAtTheDatabaseLevel(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	email, userID := ownLaneFixture(t, ctx, pool, "a197-05")
	carrier := strings.ToLower(email)

	for _, tc := range []struct{ name, value string }{
		{"чужое значение", "own-z-" + strings.ToLower(userID[4:10]) + "@example.invalid"},
		{"второй отрицательный: пустое значение", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, `UPDATE kaname.users SET admission_carrier = $2 WHERE id = $1`, userID, tc.value)
			require.Error(t, err, "A197-05: правка носителя на %q принята", tc.value)
			code, msg := a197Code(t, err)
			require.Equal(t, "KQ006", code, "A197-05: код отказа")
			require.Equal(t, a197FixedCarrierText(userID), msg, "A197-05: сообщение сервера")
			require.Equal(t, carrier, a197Carrier(t, ctx, pool, userID), "A197-05: носитель не изменился")
		})
	}

	t.Run("близнец: записывается нынешнее значение", func(t *testing.T) {
		_, err := pool.Exec(ctx, `UPDATE kaname.users SET admission_carrier = $2 WHERE id = $1`, userID, carrier)
		require.NoError(t, err, "A197-05 близнец: запись того же значения — не правка")
		require.Equal(t, carrier, a197Carrier(t, ctx, pool, userID))
	})
}

// TestA197_07_ProviderLaneIsUntouched — A197-07: у полосы поставщика носитель
// окна — его идентификатор, носителя строки нет.
func TestA197_07_ProviderLaneIsUntouched(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	ext, userID := accountQuotaFixture(t, ctx, pool, "a197-07")
	setAccountRateCeiling(t, ctx, pool, 1, 3600)
	err := insertAccount(ctx, pool, "a197-07-2", userID)
	require.Error(t, err, "A197-07: второе заведение поставщика при потолке 1 прошло")
	code, _ := a197Code(t, err)
	require.Equal(t, "KQ004", code)
	n, ok := a197Window(t, ctx, pool, ext)
	require.True(t, ok && n == 1, "A197-07: окно поставщика ключуется его идентификатором")
	require.Equal(t, "", a197Carrier(t, ctx, pool, userID), "A197-07: у полосы поставщика носителя строки нет")
}

// a197Replica — соединение пробы с отключёнными триггерами строк
// (`session_replication_role = replica`): ограничения строки остаются.
// Соединение после пробы закрывается, а не возвращается в пул.
func a197Replica(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *pgx.Conn {
	t.Helper()
	c, err := pool.Acquire(ctx)
	require.NoError(t, err)
	conn := c.Hijack()
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	_, err = conn.Exec(ctx, `SET session_replication_role = replica`)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): режим реплики требует суперпользователя")
	return conn
}

// TestA197_08_OwnLaneIdentityWithoutACarrierIsImpossible — A197-08.
func TestA197_08_OwnLaneIdentityWithoutACarrierIsImpossible(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	conn := a197Replica(t, ctx, pool)
	insert := func(external, email, carrier string) (string, error) {
		id := ids.NewID(domain.PrefixUser)
		_, err := conn.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, admission_carrier)
			VALUES ($1, $2, $3, $4, 'a197-08', 'ACTIVE', $5)`,
			id, ids.NewID(domain.PrefixAccount), external, email, carrier)
		return id, err
	}
	addr := func(tag string) string {
		return "own-k-" + tag + "-" + strings.ToLower(ids.NewID("tst")[3:9]) + "@example.invalid"
	}

	t.Run("отрицательный: наша полоса с пустым носителем", func(t *testing.T) {
		id, err := insert(string(domain.NewOwnLaneSubject()), addr("neg"), "")
		require.Error(t, err, "A197-08: строка нашей полосы без носителя принята")
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code)
		require.Equal(t, "users_own_lane_admission_carrier_check", pgErr.ConstraintName)
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.users WHERE id = $1`, id).Scan(&n))
		require.Zero(t, n, "A197-08: строки не заведено")
	})
	t.Run("близнец: носитель назван", func(t *testing.T) {
		a := addr("pos")
		_, err := insert(string(domain.NewOwnLaneSubject()), a, a)
		require.NoError(t, err, "A197-08 близнец: строка с носителем обязана пройти")
	})
	t.Run("третий отрицательный: полоса поставщика с носителем", func(t *testing.T) {
		a := addr("prov")
		_, err := insert("ext-a197-08-"+strings.ToLower(ids.NewID("tst")[3:9]), a, a)
		require.Error(t, err, "A197-08: строка поставщика с носителем принята")
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr)
		require.Equal(t, "23514", pgErr.Code)
		require.Equal(t, "users_own_lane_admission_carrier_check", pgErr.ConstraintName)
	})
	t.Run("второй близнец: триггеры включены — носитель назначает база", func(t *testing.T) {
		email, userID := ownLaneFixture(t, ctx, pool, "a197-08")
		require.Equal(t, strings.ToLower(email), a197Carrier(t, ctx, pool, userID),
			"A197-08: фикстура носителя не присылала — база назначила его сама (Р1)")
	})
}

// TestA197_09_SentForeignCarrierIsRefusedNotOverwritten — A197-09: вставка и
// чеканка с присланным носителем, отличным от адреса, — KQ006; равный адресу
// принимается.
func TestA197_09_SentForeignCarrierIsRefusedNotOverwritten(t *testing.T) {
	pool, ctx := newAccountRateDB(t)

	insertOwn := func(t *testing.T, email, carrier string) (string, error) {
		t.Helper()
		userID := ids.NewID(domain.PrefixUser)
		accountID := ids.NewID(domain.PrefixAccount)
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, admission_carrier)
			VALUES ($1, $2, $3, $4, 'a197-09', 'ACTIVE', $5)`,
			userID, accountID, string(domain.NewOwnLaneSubject()), email, carrier); err != nil {
			return userID, err
		}
		_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels) VALUES ($1, $2, $3, '{}'::jsonb)`,
			accountID, "a197-09-"+strings.ToLower(userID[4:10]), userID)
		require.NoError(t, err)
		seedWayIn(t, ctx, tx)
		return userID, tx.Commit(ctx)
	}

	t.Run("вставка: чужой носитель", func(t *testing.T) {
		email := "own-m-" + strings.ToLower(ids.NewID("tst")[3:9]) + "@example.invalid"
		userID, err := insertOwn(t, email, "own-z@example.invalid")
		require.Error(t, err, "A197-09: присланный чужой носитель принят")
		code, msg := a197Code(t, err)
		require.Equal(t, "KQ006", code)
		require.Equal(t, a197FixedCarrierText(userID), msg)
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.users WHERE id = $1`, userID).Scan(&n))
		require.Zero(t, n, "A197-09: строки нет")
	})
	t.Run("близнец вставки: носитель равен адресу", func(t *testing.T) {
		email := "own-m-" + strings.ToLower(ids.NewID("tst")[3:9]) + "@example.invalid"
		userID, err := insertOwn(t, email, email)
		require.NoError(t, err, "A197-09 близнец: носитель, равный адресу, принимается")
		require.Equal(t, email, a197Carrier(t, ctx, pool, userID))
	})

	// Чеканка: строка приглашения в аккаунте действующего человека.
	_, inviter := ownLaneFixture(t, ctx, pool, "a197-09-inviter")
	var account string
	require.NoError(t, pool.QueryRow(ctx, `SELECT account_id FROM kaname.users WHERE id = $1`, inviter).Scan(&account))
	invite := func(t *testing.T) (userID, email string) {
		t.Helper()
		userID = ids.NewID(domain.PrefixUser)
		email = "inv-n-" + strings.ToLower(userID[4:10]) + "@example.invalid"
		_, err := pool.Exec(ctx, `
			INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, invited_by)
			VALUES ($1, $2, '', $3, 'a197-09-invitee', 'PENDING', $4)`, userID, account, email, inviter)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): строка приглашения")
		return userID, email
	}
	mint := func(t *testing.T, userID, carrier string) error {
		t.Helper()
		tx, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, `UPDATE kaname.users SET invite_status = 'ACTIVE', external_id = $2, admission_carrier = $3 WHERE id = $1`,
			userID, string(domain.NewOwnLaneSubject()), carrier); err != nil {
			return err
		}
		seedWayIn(t, ctx, tx)
		return tx.Commit(ctx)
	}

	t.Run("чеканка: чужой носитель", func(t *testing.T) {
		userID, _ := invite(t)
		err := mint(t, userID, "inv-z@example.invalid")
		require.Error(t, err, "A197-09: чеканка с чужим носителем принята")
		code, msg := a197Code(t, err)
		require.Equal(t, "KQ006", code)
		require.Equal(t, a197FixedCarrierText(userID), msg)
		var status, ext, carrier string
		require.NoError(t, pool.QueryRow(ctx, `SELECT invite_status, external_id, admission_carrier FROM kaname.users WHERE id = $1`, userID).
			Scan(&status, &ext, &carrier))
		require.Equal(t, []string{"PENDING", "", ""}, []string{status, ext, carrier}, "A197-09: строка осталась приглашением")
	})
	t.Run("близнец чеканки: носитель равен адресу", func(t *testing.T) {
		userID, email := invite(t)
		require.NoError(t, mint(t, userID, email), "A197-09 близнец: чеканка с носителем, равным адресу")
		require.Equal(t, email, a197Carrier(t, ctx, pool, userID))
	})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// registration_carrier_rate_integration_test.go — НОСИТЕЛЬ КЛЮЧА ТЕМПА
// заведения объявлен заново (приёмка Ф4 Р5, Ф4-12, Ф4-17; задача kacho#1270).
//
// # Предмет
//
// Триггер `accounts_rate_admission` ключует окно тем, чем человек представился:
// у полосы поставщика — его идентификатором, у НАШЕЙ полосы (идентичность с
// головой `own:`) — адресом. Без переобъявления рубеж для наших людей ключевался
// бы отчеканенной идентичностью — свежей у каждого заведения, — то есть перестал
// бы ограничивать молча: ни отказа, ни красного, ни строки переписи.
//
// # Что доказывается
//
//   - у нашей полосы строка окна ключуется `lower(email)`, у полосы поставщика —
//     внешним идентификатором (законный близнец: чужой ключ не тронут);
//   - первое заведение носителя проходит при потолке НОЛЬ (Ф4-17);
//   - N+1-е заведение носителя в окне отвергается кодом темпа (Ф4-12), и
//     носитель в тексте отказа — адрес;
//   - проекция посадки доезжает до живого пути (Ф4-19): величина, записанная
//     проектором, решает исход следующей вставки.
//
// Run: `make test` (Docker). Skipped under -short.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ownLaneFixture — личность нашей полосы: идентичность с головой `own:`, адрес
// — носитель ключа; первый аккаунт заведён (ветвь вставки окна).
func ownLaneFixture(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) (email, userID string) {
	t.Helper()
	userID = ids.NewID(domain.PrefixUser)
	accountID := ids.NewID(domain.PrefixAccount)
	email = "Own-" + suffix + "-" + userID[3:9] + "@Example.Invalid"
	subject := string(domain.NewOwnLaneSubject())

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`, userID, accountID, subject, email, "Own "+suffix)
	require.NoError(t, err, "seed own-lane user")
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, accountID, "own-acc-"+suffix, userID)
	require.NoError(t, err, "seed own-lane account")
	require.NoError(t, tx.Commit(ctx))
	return email, userID
}

func windowCarriers(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT carrier_id FROM kaname.identity_admission_windows WHERE kind = 'iam.account' ORDER BY carrier_id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		require.NoError(t, rows.Scan(&c))
		out = append(out, c)
	}
	return out
}

// TestRegistrationCarrier_F4_R5_OwnLaneIsKeyedByTheAddress — наша полоса
// ключуется адресом (в нижнем регистре), полоса поставщика — его
// идентификатором. Обе строки окна названы поимённо: «ноль чужих ключей» без
// положительной половины было бы верно и о триггере, который не считает никого.
func TestRegistrationCarrier_F4_R5_OwnLaneIsKeyedByTheAddress(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	email, _ := ownLaneFixture(t, ctx, pool, "carrier")
	providerExt, _ := accountQuotaFixture(t, ctx, pool, "carrier-provider")

	carriers := windowCarriers(t, ctx, pool)
	require.ElementsMatch(t, []string{providerExt, strings.ToLower(email)}, carriers,
		"перепись окон: у нашей полосы носитель — адрес в нижнем регистре, у поставщика — его идентификатор")
}

// TestRegistrationCarrier_F4_17_FirstAdmissionOfAnAddressIsUnconditional —
// первое заведение носителя проходит при потолке ноль: фикстура выше и есть
// первое заведение, и потолок на неё не влияет.
func TestRegistrationCarrier_F4_17_FirstAdmissionOfAnAddressIsUnconditional(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	setAccountRateCeiling(t, ctx, pool, 0, 3600)
	email, userID := ownLaneFixture(t, ctx, pool, "first")
	require.Len(t, windowCarriers(t, ctx, pool), 1, "окно носителя заведено первым заведением")

	// Второе заведение того же носителя при нуле — отказ по темпу, и текст
	// называет носителем АДРЕС, а не отчеканенную идентичность.
	err := insertAccount(ctx, pool, "own-acc-first-2", userID)
	require.Error(t, err)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "KQ004", pgErr.Code)
	require.Contains(t, pgErr.Message, strings.ToLower(email))
	require.NotContains(t, pgErr.Message, "own:", "носитель отказа — адрес, а не идентичность")
}

// TestRegistrationCarrier_F4_19_ProjectedRateReachesTheLivePath — величина,
// записанная проектором посадки, решает исход следующей вставки: единица
// отвергает второй аккаунт, четыре — пропускает.
func TestRegistrationCarrier_F4_19_ProjectedRateReachesTheLivePath(t *testing.T) {
	pool, ctx := newAccountRateDB(t)
	_, userID := ownLaneFixture(t, ctx, pool, "proj")
	repo := kanamepg.NewOwnCeilingRepo(pool)

	census, err := repo.ApplyAdmissionRate(ctx, 1, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, census.Written, "строка авторитета переписана проектором")
	require.Error(t, insertAccount(ctx, pool, "own-acc-proj-2", userID),
		"второй аккаунт прошёл при спроецированной единице: величина не читается на пути записи")

	census, err = repo.ApplyAdmissionRate(ctx, 4, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, census.Written)
	require.NoError(t, insertAccount(ctx, pool, "own-acc-proj-2b", userID),
		"спроецированная четвёрка не доехала до живого пути")

	// Строка авторитета одна и та же: проектор правит её, а не заводит вторую.
	var live int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.account_admission_rate_limits WHERE kind = 'iam.account' AND withdrawn_at IS NULL`).Scan(&live))
	require.Equal(t, 1, live)
}

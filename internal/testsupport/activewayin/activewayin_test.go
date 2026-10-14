// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package activewayin

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// recordingExecer — дублёр транзакции pgx: запоминает исполненные операторы.
type recordingExecer struct{ seen []string }

func (r *recordingExecer) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	r.seen = append(r.seen, sql)
	return pgconn.CommandTag{}, nil
}

// TestWithWayInWrapsTheInsertIntoOneStatement — вставка личностей и строка
// пароля ложатся ОДНИМ оператором; пробел вокруг вставки снимается, иначе
// `RETURNING` встал бы после хвостового перевода строки посреди текста фикстуры.
func TestWithWayInWrapsTheInsertIntoOneStatement(t *testing.T) {
	got := WithWayIn("\n\tINSERT INTO kaname.users (id) VALUES ($1)\n")
	require.Equal(t,
		"WITH way_in_people AS (INSERT INTO kaname.users (id) VALUES ($1) RETURNING id, invite_status) "+
			"INSERT INTO kaname.user_login_methods (user_id, kind, verifier) "+
			"SELECT id, 'password', 'fixture-password-row-without-a-known-password' FROM way_in_people "+
			"WHERE invite_status = 'ACTIVE'",
		got)
}

// TestSeedFormsIssueTheirOwnStatement — каждая форма посева исполняет СВОЙ
// оператор, а не соседний: строка пароля и отметка открытого пути — разные
// состояния хранилища (Д-24 и Д-23), и подмена одного другим строит не то «Дано».
func TestSeedFormsIssueTheirOwnStatement(t *testing.T) {
	ctx := context.Background()

	seed := &recordingExecer{}
	Seed(t, ctx, seed)
	require.Equal(t, []string{FixtureSQL}, seed.seen)

	open := &recordingExecer{}
	SeedOpenPath(t, ctx, open)
	require.Equal(t, []string{OpenPathSQL}, open.seen)

	require.NotEqual(t, FixtureSQL, OpenPathSQL)
	require.Contains(t, FixtureSQL, "INSERT INTO kaname.user_login_methods")
	require.Contains(t, OpenPathSQL, "SET recovery_path_opened_at = now()")
	require.Contains(t, GuardedSQL, "users_active_has_a_way_in_fk",
		"посев цепочки миграций судит ревизию по ключу инварианта")
}

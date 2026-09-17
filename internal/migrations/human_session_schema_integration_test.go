// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// human_session_schema_integration_test.go — СХЕМА сессии человека (фаза Ф3,
// задача `kacho#1269`; сторона хранилища Ф3-09, Ф3-11, Ф3-50, Р1, Р5).
//
// Что утверждают пробы: уровень обязателен и из оси Ф11 («сессии без уровня не
// бывает» — Ф11 Р1); множество предъявленного непусто и из словаря
// `assurance.Methods()` — словарь в ограничении сверяется с ПРОИЗВОДИТЕЛЕМ, а не
// выписан; срок позже момента аутентификации; свёртка носителя уникальна и
// шестнадцатерична; снятие несёт пару «момент, причина» либо ничего; строка
// уходит вместе с человеком. У каждого отрицания — вставка, которая проходит.
package migrations_test

import (
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/assurance"
)

func hsDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

func hsSeedPerson(t *testing.T, db *sql.DB, tag string) string {
	t.Helper()
	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	id := "usr" + strings.Repeat("0", 17-len(tag)) + tag
	acc := "acc" + strings.Repeat("0", 17-len(tag)) + tag
	_, err = tx.Exec(`INSERT INTO users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'p', $4, 'ACTIVE')`, id, "own:"+tag, tag+"@example.invalid", acc)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`, acc, "acc-"+tag, id)
	require.NoError(t, err)
	require.NoError(t, tx.Commit())
	return id
}

const hsInsert = `INSERT INTO human_sessions
	(id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at, assurance_level, presented_methods)
	VALUES ($1, $2, $3, now(), now(), now() + interval '1 day', $4, $5)`

func hsConstraint(t *testing.T, err error) string {
	t.Helper()
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "ждали отказ базы, получили %v", err)
	return pgErr.ConstraintName
}

// TestHumanSessionSchema_LevelAndMethodsAreHeldByTheBase — уровень и словарь.
func TestHumanSessionSchema_LevelAndMethodsAreHeldByTheBase(t *testing.T) {
	db := hsDB(t)
	person := hsSeedPerson(t, db, "hss1")
	digest := strings.Repeat("ab", 32)

	_, err := db.Exec(hsInsert, "hss-ok", person, digest, "1", "{password}")
	require.NoError(t, err, "положительный контроль: годная запись проходит")

	_, err = db.Exec(hsInsert, "hss-l0", person, strings.Repeat("cd", 32), "0", "{password}")
	require.Equal(t, "human_sessions_assurance_level_check", hsConstraint(t, err), "Ф11 Р1: уровень вне оси отвергает база")
	_, err = db.Exec(hsInsert, "hss-m0", person, strings.Repeat("ef", 32), "1", "{}")
	require.Equal(t, "human_sessions_presented_methods_check", hsConstraint(t, err), "множество непусто")
	_, err = db.Exec(hsInsert, "hss-mx", person, strings.Repeat("12", 32), "1", "{carrier-pigeon}")
	require.Equal(t, "human_sessions_presented_methods_check", hsConstraint(t, err), "способ вне словаря отвергает база")
	_, err = db.Exec(hsInsert, "hss-dup", person, digest, "1", "{password}")
	require.Equal(t, "human_sessions_bearer_digest_uniq", hsConstraint(t, err), "свёртка носителя уникальна")
	_, err = db.Exec(hsInsert, "hss-bad", person, "not-a-digest", "1", "{password}")
	require.Equal(t, "human_sessions_bearer_digest_check", hsConstraint(t, err), "свёртка — 64 шестнадцатеричных знака")
	_, err = db.Exec(`UPDATE human_sessions SET ended_at = now() WHERE id = 'hss-ok'`)
	require.Equal(t, "human_sessions_ended_pair_check", hsConstraint(t, err), "снятие без причины отвергается")
	_, err = db.Exec(`UPDATE human_sessions SET ended_at = now(), ended_reason = 'sneeze' WHERE id = 'hss-ok'`)
	require.Equal(t, "human_sessions_ended_reason_check", hsConstraint(t, err), "причина вне перечня отвергается")
	_, err = db.Exec(`UPDATE human_sessions SET expires_at = authenticated_at WHERE id = 'hss-ok'`)
	require.Equal(t, "human_sessions_expiry_after_auth_check", hsConstraint(t, err), "срок позже момента аутентификации")

	// Каскад: строка уходит вместе с человеком — читается из объявления ключа
	// (удалить человека в этой базе нельзя: владение аккаунтом RESTRICT, и
	// RESTRICT не откладывается — это чужое ограничение, не предмет пробы).
	var onDelete string
	require.NoError(t, db.QueryRow(`SELECT confdeltype FROM pg_constraint WHERE conname = 'human_sessions_user_fk'`).Scan(&onDelete))
	require.Equal(t, "c", onDelete, "human_sessions_user_fk: ON DELETE CASCADE")
	require.NoError(t, db.QueryRow(`SELECT confdeltype FROM pg_constraint WHERE conname = 'human_first_authentications_user_fk'`).Scan(&onDelete))
	require.Equal(t, "c", onDelete, "human_first_authentications_user_fk: ON DELETE CASCADE")
}

// TestHumanSessionMethodVocabularyAgreesWithTheRule — словарь способов в
// ограничении базы совпадает с производителем `assurance.Methods()`, а ось
// уровня — с уровнями правила. Второе написание сверяется с первым, а не
// объявляется отдельно.
func TestHumanSessionMethodVocabularyAgreesWithTheRule(t *testing.T) {
	db := hsDB(t)
	var def string
	require.NoError(t, db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname = 'human_sessions_presented_methods_check'`).Scan(&def))
	for _, m := range assurance.Methods() {
		require.Contains(t, def, "'"+m.String()+"'", "словарь базы не знает способа %q", m)
	}
	// Обратная сторона: в ограничении нет слова, которого нет у правила.
	quoted := 0
	for _, part := range strings.Split(def, "'") {
		for _, m := range assurance.Methods() {
			if part == m.String() {
				quoted++
			}
		}
	}
	require.Equal(t, len(assurance.Methods()), quoted, "в ограничении ровно словарь правила: %s", def)

	require.NoError(t, db.QueryRow(`SELECT pg_get_constraintdef(oid) FROM pg_constraint
		WHERE conname = 'human_sessions_assurance_level_check'`).Scan(&def))
	for _, l := range []assurance.Level{assurance.Level1, assurance.Level2, assurance.Level3} {
		require.Contains(t, def, "'"+l.String()+"'")
	}
	t.Logf("перепись: способов у правила %d, уровней %d — в ограничениях те же", len(assurance.Methods()), 3)
}

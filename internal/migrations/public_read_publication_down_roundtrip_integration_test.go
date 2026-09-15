// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// public_read_publication_down_roundtrip_integration_test.go — откат миграции
// публикации для анонимного чтения (kaname#107) проходит, возвращает проекцию
// журнала к прежнему телу и не оставляет фактов, которые прежнее тело снять не
// могло бы; повторный накат сходится.
//
// Почему откат обязан снимать факты-глаголы. Прежняя проекция строку снятия
// глагола ОТБРАСЫВАЕТ. Факт публикации, переживший откат, отвечал бы «читать
// может всякий», и снять его после отката было бы нечем — ни одна доставка
// владельца до него уже не доехала бы.

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

const publicReadPublicationVersion int64 = 20260916020000

// enqueueOwnerOrderedPublication кладёт строку журнала ровно той формы, какую
// кладёт путь публикации: кортеж публичного чтения и версия владельца.
func enqueueOwnerOrderedPublication(t *testing.T, db *sql.DB, objectID string) {
	t.Helper()
	_, err := db.Exec(`
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		VALUES ('fga.tuple.write',
		        jsonb_build_object('user', 'user:*', 'relation', 'v_get',
		                           'object', 'registry_repository:' || $1::text,
		                           'source_version', now()),
		        now())`, objectID)
	require.NoError(t, err)
}

func publicationFacts(t *testing.T, db *sql.DB, objectID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = 'registry_repository' AND object_id = $1
		   AND relation = 'v_get' AND subject = 'user:*'`, objectID).Scan(&n))
	return n
}

func TestPublicReadPublication_DownRestoresTheProjectionAndTheReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	// Положительный контроль: на голове публикация складывается в факт. Без него
	// утверждение «после отката факта нет» зеленело бы и на проекции, которая не
	// складывала его никогда.
	enqueueOwnerOrderedPublication(t, db, "reg0000000000down/team/app")
	require.Equal(t, 1, publicationFacts(t, db, "reg0000000000down/team/app"), "на голове публикация не сложилась в факт")

	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < publicReadPublicationVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")

	var tbl int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'kaname' AND table_name = 'public_read_publication'`).Scan(&tbl))
	require.Zero(t, tbl, "состояние публикаций не снято откатом")

	var verbs int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.relation_fact WHERE relation LIKE 'v\_%'`).Scan(&verbs))
	require.Zero(t, verbs, "откат оставил факты-глаголы, которые прежняя проекция снять не может")

	// Прежнее тело: строку, упорядоченную владельцем, оно НЕ складывает.
	enqueueOwnerOrderedPublication(t, db, "reg0000000000back/team/app")
	require.Zero(t, publicationFacts(t, db, "reg0000000000back/team/app"), "после отката проекция складывает глагол — тело не вернулось")

	require.NoError(t, goose.Up(db, "."), "повторный накат обязан проходить")
	enqueueOwnerOrderedPublication(t, db, "reg0000000000again/team/app")
	require.Equal(t, 1, publicationFacts(t, db, "reg0000000000again/team/app"), "после повторного наката публикация не складывается")
}

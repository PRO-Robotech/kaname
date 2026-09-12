// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_ceilings_down_roundtrip_integration_test.go — ОТКАТ МИГРАЦИИ ПРОХОДИТ, и
// проходит целиком.
//
// Задача продукта #2117, приёмка `KAN-QUOTA-1`, `П25`.
//
// # Почему это утверждение нужно отдельно
//
// `Down` пишут все, а исполняет его редко кто: неверный откат обнаруживается в
// день, когда он понадобился, — то есть в худший из возможных. Здесь он несёт три
// разных предмета сразу (снятие таблицы проекции, восстановление величин
// авторитета, восстановление ПРЕЖНИХ тел двух триггерных функций), и любое из
// трёх могло бы не сработать молча.
//
// # Три утверждения, а не одно
//
// Пройденный откат сам по себе ничего не значит: `Down`, состоящий из пустых
// операторов, тоже «проходит». Поэтому утверждается СОСТОЯНИЕ после него —
// таблицы проекции нет, величины вернулись авторитету, — и отдельно то, что
// ПОВТОРНЫЙ накат снова сходится: откат, оставивший дерево непригодным для
// наката, хуже отсутствующего.

package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestOwnCeilings_DownRestoresTheAuthorityAndTheReapplyConverges(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	var before int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.own_ceilings`).Scan(&before))
	require.Equal(t, 3, before)

	require.NoError(t, goose.Down(db, "."), "откат обязан проходить")

	var tbl int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM information_schema.tables
		  WHERE table_schema='kaname' AND table_name='own_ceilings'`).Scan(&tbl))
	require.Zero(t, tbl, "таблица проекции не снята откатом")

	var restored int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.limits
		 WHERE kind IN ('iam.account','iam.user.credential','iam.serviceAccount.credential')`).Scan(&restored))
	require.Equal(t, 3, restored, "откат не вернул величины авторитету")

	require.NoError(t, goose.Up(db, "."), "повторный накат обязан проходить")
	var after int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.own_ceilings`).Scan(&after))
	require.Equal(t, 3, after)
}

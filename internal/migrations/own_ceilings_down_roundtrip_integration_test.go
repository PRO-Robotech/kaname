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

	// Откат идёт ДО СВОЕЙ миграции, а не «на один шаг».
	//
	// Прежняя редакция звала `goose.Down` однажды и тем самым утверждала, что
	// предмет этой пробы — ПОСЛЕДНЯЯ миграция дерева. Утверждение было верно в
	// день записи и переставало быть верным от появления любой следующей: проба
	// откатывала ЧУЖУЮ миграцию и падала на «таблица проекции не снята откатом»,
	// то есть обвиняла свой предмет в чужом изменении. Наблюдалось на #2554, где
	// следующей оказалась миграция имени кластера.
	//
	// Версия названа ЧИСЛОМ, а не выведена из положения в каталоге: положение и
	// есть то допущение, которое сломалось.
	const ownCeilingsVersion int64 = 20260910120000
	steps := 0
	for {
		v, verr := goose.GetDBVersion(db)
		require.NoError(t, verr)
		if v < ownCeilingsVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	// Перепись, а не украшение: без неё цикл, не сделавший НИ ОДНОГО шага,
	// прошёл бы дальше, и все три утверждения ниже зеленели бы на базе, где
	// предмет отката просто не применялся.
	require.Positive(t, steps, "откат не сделал ни шага — утверждения ниже беспредметны")
	t.Logf("откат: миграций снято %d (до версии ниже %d)", steps, ownCeilingsVersion)

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

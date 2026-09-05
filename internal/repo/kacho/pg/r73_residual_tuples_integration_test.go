// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// r73_residual_tuples_integration_test.go — ЧИТАТЕЛЬ ОСТАТКА: что ещё стоит на
// объекте, когда его регистрацию снимают.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ЭТОТ ЧИТАТЕЛЬ ЕСТЬ
//
// Снятие обязано забрать КАЖДОЕ отношение, которое посредник мог поставить на
// объект, а не только то, которое сумел назвать потребитель. Потребитель называет
// указатель области — это всё, чем он располагает; собственное `owner` создателя
// записано от личности, которую после этого никто не хранит.
//
// Раньше эти строки лежали в чужом хранилище и читались СИЛЬНЫМ чтением: набор
// решает, что УДАЛИТЬ, а отставшая копия недосказывает — и недосказанное здесь не
// «повторится и сойдётся», а отношение, пережившее снятие своего объекта и
// продолжающее отвечать «доступ есть». Теперь строки лежат в своей базе, и вопрос
// об отставании отпадает by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ
//
// Читатель называет отношения СВОЕГО объекта и НЕ называет чужие. Второе
// проверяется отдельно и не для симметрии: перечень идёт в удаление, поэтому
// лишнее имя здесь — это снятое право у объекта, которого никто не трогал.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

func TestR7_3_27_ResidualReaderNamesOwnObjectOnly(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	writer := kachopg.NewCreatorTupleWriter(pool)
	require.NotNil(t, writer)
	reader := kachopg.NewResidualTupleReader(pool)
	require.NotNil(t, reader)

	const (
		mine  = "vpc_network:r73net_mine"
		other = "vpc_network:r73net_other"
	)

	// Положительный контроль: ДО записи остатка нет. Без него «после записи
	// нашлось» не утверждает ничего.
	before, err := reader.ObjectTuples(ctx, mine)
	require.NoError(t, err)
	require.Empty(t, before, "у нетронутого объекта остатка быть не может")

	require.NoError(t, writer.RecordTuples(ctx, []clients.RelationTuple{
		{User: "user:usr_r73creator", Relation: "owner", Object: mine},
		{User: "project:prj_r73", Relation: "parent", Object: mine},
		{User: "user:usr_r73neighbour", Relation: "owner", Object: other},
	}))

	got, err := reader.ObjectTuples(ctx, mine)
	require.NoError(t, err)

	names := make(map[string]string, len(got))
	for _, tuple := range got {
		require.Equal(t, mine, tuple.Object,
			"читатель обязан называть ТОЛЬКО свой объект: лишнее имя здесь уезжает в "+
				"удаление и снимает право у объекта, которого никто не трогал")
		names[tuple.Relation] = tuple.User
	}
	require.Equal(t, map[string]string{
		"owner":  "user:usr_r73creator",
		"parent": "project:prj_r73",
	}, names, "названы оба отношения объекта — и то, которое потребитель мог назвать сам "+
		"(указатель области), и то, которое назвать может только сторона с самими строками")

	// Чужой объект остаётся нетронутым и читается отдельно — это вторая половина
	// того же утверждения, и без неё «называет своё» неотличимо от «называет всё,
	// а чужого просто не было».
	neighbour, err := reader.ObjectTuples(ctx, other)
	require.NoError(t, err)
	require.Len(t, neighbour, 1)
	require.Equal(t, "user:usr_r73neighbour", neighbour[0].User)
}

func TestR7_3_27_ResidualReaderRefusesAnUnparsableObject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	_, err = kachopg.NewResidualTupleReader(pool).ObjectTuples(ctx, "мусор-без-двоеточия")
	require.Error(t, err,
		"неразобранный объект обязан быть ошибкой, а не пустым перечнем: пустой перечень "+
			"здесь означает «снимать нечего» и делает снятие тихо неполным")
}

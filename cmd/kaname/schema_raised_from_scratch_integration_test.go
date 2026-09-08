// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_raised_from_scratch_integration_test.go — схема, поднятая цепью
// миграций С НУЛЯ, зовётся именем продукта, и соединение службы в неё попадает.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ШОВ, а не имя
//
// Имя схемы объявлено ДВАЖДЫ и в двух разных местах дерева: цепь миграций его
// СОЗДАЁТ, а строка подключения службы его ВЫБИРАЕТ параметром времени
// исполнения. Гейт дерева рядом (`internal/supplyhygiene`) судит написание —
// он читает текст и не может сказать, сходятся ли две половины на живом
// Postgres.
//
// А разойтись они могут молча и в обе стороны: переименовать схему в миграции,
// не тронув параметр, — и служба подключится к базе, где её схемы нет; сменить
// параметр, не тронув миграцию, — то же самое с другой стороны. Отказ при этом
// приходит не «схемы нет», а «отношение не существует» на первом же операторе,
// то есть в месте, к причине отношения не имеющем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — четыре факта, и порядок их несущий
//
//  1. цепь миграций проигрывается на пустой Postgres и СОЗДАЁТ схему с
//     каноническим именем. Проверяется системным каталогом, а не текстом файла;
//  2. `search_path`, который строит помощник службы, РАЗРЕШАЕТСЯ в эту схему:
//     `current_schema()` отдаёт её имя. Несуществующая схема в `search_path`
//     ошибкой не является — она молча пропускается, и без этого утверждения
//     промах был бы неотличим от попадания;
//  3. таблица службы читается БЕЗ квалификатора. Первые два факта верны и на
//     схеме пустой; этот говорит, что `search_path` выбирает ту схему, в
//     которой лежат данные;
//  4. отставленного имени схемы в базе НЕТ. Без этого «переименовал» было бы
//     неотличимо от «завёл вторую рядом», а вторая схема с прежними таблицами
//     есть худший исход обоих: оба имени резолвятся, и какое из них читает
//     служба, решает порядок `search_path`.
package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// canonicalSchemaName — имя схемы, которое обязаны производить обе половины
// шва. Литерал здесь НАМЕРЕННЫЙ: проба обязана утверждать имя, а не
// пересказывать то же выражение, которым его строит проверяемый код. Взяв имя
// у помощника, она сравнивала бы его с самим собой и зеленела при любом.
const canonicalSchemaName = "kaname"

// retiredSchemaName — имя, отставленное вместе с прежним именем продукта.
const retiredSchemaName = "kacho_iam"

func TestIntegration_SchemaRaisedFromScratchIsNamedForTheProduct(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: проба поднимает схему цепью миграций")
	}

	ctx := context.Background()

	// NewTestPostgres отдаёт базу, на которой цепь миграций уже проиграна, и
	// дописывает в строку подключения тот же параметр `search_path`, что строит
	// composition root службы.
	pool, err := pgxpool.New(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	// Закрытие — С ПРЕДЕЛОМ: проба, упавшая внутри открытой транзакции,
	// соединение не вернёт, и отложенное закрытие ждало бы его вечно, унося
	// вердикт ВСЕГО пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	// (1) Цепь создала схему с каноническим именем — спрошено у каталога.
	var raised bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`,
		canonicalSchemaName).Scan(&raised))
	require.Truef(t, raised,
		"цепь миграций не создала схему %q: имя схемы объявлено в миграции, и это её половина шва",
		canonicalSchemaName)

	// (2) Параметр строки подключения разрешается в неё же.
	var current string
	require.NoError(t, pool.QueryRow(ctx, `SELECT current_schema()`).Scan(&current))
	require.Equalf(t, canonicalSchemaName, current,
		"search_path соединения службы разрешился в %q, а не в %q: несуществующая схема "+
			"в search_path молча пропускается, поэтому промах виден только этим утверждением",
		current, canonicalSchemaName)

	// (3) Таблица службы читается без квалификатора — значит выбрана та схема,
	// в которой лежат данные, а не одноимённая пустая.
	var reachable int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM roles`).Scan(&reachable),
		"таблица службы не читается без квалификатора: search_path выбрал не ту схему")
	require.Positivef(t, reachable,
		"схема %q поднята пустой: утверждения (1) и (2) верны и на схеме без строк, "+
			"поэтому положительный контроль стоит здесь", canonicalSchemaName)

	// (4) Отставленного имени в базе нет — переименование, а не вторая схема рядом.
	var retiredStillThere bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = $1)`,
		retiredSchemaName).Scan(&retiredStillThere))
	require.Falsef(t, retiredStillThere,
		"схема %q осталась в базе рядом с %q: оба имени резолвятся, и какое читает служба, "+
			"решает порядок search_path — это хуже, чем не переименовать вовсе",
		retiredSchemaName, canonicalSchemaName)

	t.Logf("перепись: схема %q поднята цепью · current_schema()=%q · строк в roles %d · схема %q отсутствует",
		canonicalSchemaName, current, reachable, retiredSchemaName)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// typedict_conversion_integration_test.go — перевод УЖЕ ЗАПИСАННЫХ рёбер в
// словарь модели (миграция 0091) исполняется на строках, а не только читается.
//
// # Зачем отдельная проба
//
// Все прочие прогоны накатывают цепь на ПУСТУЮ базу: перевод там не выполняет
// ничего, самопроверка не находит ничего, и тело миграции остаётся формой без
// содержания. Между тем именно это тело защищает уже поднятый стенд: строка,
// оставшаяся в словаре каталога, — объект без предков, то есть отказ в доступе
// при живой выдаче.
//
// Проба останавливает цепь ПЕРЕД 0091, кладёт строки старого словаря — включая
// двойника, на котором наивный перевод дал бы конфликт первичного ключа, — и
// доводит цепь до конца.
package migrations_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// versionBeforeTypeDictionary — последняя версия ДО перевода. Названа числом
// намеренно: проба обязана встать именно перед 0091, и вывод «предпоследняя»
// сместился бы вместе со следующей миграцией, тихо перестав проверять предмет.
const versionBeforeTypeDictionary = 90

func TestIntegration_TypeDictionaryConversionRewritesStoredEdges(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.UpTo(db, ".", versionBeforeTypeDictionary))

	// Состояние прежнего писателя: объектная сторона — словарь каталога.
	_, err = db.ExecContext(ctx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc.network',      'net-old',  'project',     'prj-1', 1),
		        ('vpc.network',      'net-old',  'account',     'acc-1', 2),
		        -- звено, чей предок тоже назван словарём каталога
		        ('registry.repositories', 'rep-old', 'registry.registries', 'reg-1', 1),
		        -- ДВОЙНИК: тот же объект и глубина уже переписаны исправленным
		        -- писателем; наивный перевод дал бы здесь конфликт ключа
		        ('vpc.network',      'net-twin', 'project',     'prj-OLD', 1),
		        ('vpc_network',      'net-twin', 'project',     'prj-NEW', 1)`)
	require.NoError(t, err, "посев состояния прежнего писателя")

	require.NoError(t, goose.UpTo(db, ".", versionBeforeTypeDictionary+1),
		"перевод не прошёл — на поднятом стенде миграция остановила бы накат")

	// (1) переведено обе стороны.
	var chain []string
	rows, err := db.QueryContext(ctx,
		`SELECT object_type || ' -> ' || parent_type
		   FROM kacho_iam.resource_parent_edge
		  ORDER BY object_type, object_id, depth`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		chain = append(chain, s)
	}
	require.NoError(t, rows.Err())

	require.ElementsMatch(t, []string{
		"registry_repository -> registry_registry",
		"vpc_network -> project",
		"vpc_network -> account",
		"vpc_network -> project", // выживший двойник, ровно один
	}, chain, "перевод не привёл цепь к словарю модели")

	// (2) двойник остался ОДИН, и это тот, что записал исправленный писатель.
	var survivor string
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT parent_id FROM kacho_iam.resource_parent_edge
		  WHERE object_id = 'net-twin'`).Scan(&survivor))
	require.Equal(t, "prj-NEW", survivor,
		"выжил устаревший двойник — перевод затёр точную строку приблизительной")

	// (3) отрицание рядом: строк словаря каталога не осталось ни одной. Без
	// него «перевёл» было бы неотличимо от «добавил вторые имена».
	var leftover int
	require.NoError(t, db.QueryRowContext(ctx,
		`SELECT count(*) FROM kacho_iam.resource_parent_edge
		  WHERE object_type LIKE '%.%' OR parent_type LIKE '%.%'`).Scan(&leftover))
	require.Zero(t, leftover)
}

// Самопроверка миграции ОТКАЗЫВАЕТ накат, если перечень пар чего-то не знал.
//
// Без этой пробы неполный перечень означал бы молча пропущенную строку — объект
// без предков, то есть отказ в доступе при живой выдаче. Инъекция здесь —
// настоящий вход того же вида: тип, которого в перечне нет by construction.
func TestIntegration_TypeDictionaryConversionRefusesAnUnknownDottedType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer func() { _ = db.Close() }()

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.UpTo(db, ".", versionBeforeTypeDictionary))

	_, err = db.ExecContext(ctx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('nosuch.domainResource', 'obj-1', 'project', 'prj-1', 1)`)
	require.NoError(t, err)

	err = goose.UpTo(db, ".", versionBeforeTypeDictionary+1)
	require.Error(t, err, "перевод завершился, оставив строку, которую не прочитает "+
		"ни один вопрос о доступе — молчаливый пропуск здесь дороже отказа")
	require.Contains(t, err.Error(), "nosuch.domainResource",
		"отказ не называет значение, из-за которого он произошёл: оператору нечего чинить")
}

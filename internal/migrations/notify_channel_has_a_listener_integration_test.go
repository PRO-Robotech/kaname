// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// notify_channel_has_a_listener_integration_test.go — канал уведомления читается
// по ЖИВОЙ схеме, а не по тексту миграций.
//
// # Почему по живой схеме
//
// Текстовый предикат по `pg_notify('…')` в файлах миграций считает производителем
// и то объявление, чей предмет уже снят более поздней миграцией. Такая находка
// ложна, а ложная находка выключает проверку быстрее, чем её чинят: перепись
// того же класса по дереву дала три канала без слушателя, и один из трёх
// (`storage_outbox`) оказался именно этим — таблицу сняли, объявление осталось.
//
// Поэтому здесь проигрывается вся цепь миграций и спрашивается ИТОГОВОЕ
// состояние: какие триггеры живы и что делают их функции.
package migrations_test

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

// TestIntegration_SessionRevokedChannelHasNoProducerLeft — регрессия на снятие
// канала, у которого не было и не могло быть потребителя (#755).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт session_revoked» зеленело бы и на пустом ответе — на опечатке в запросе, на
// не накатившейся схеме, на переименованной колонке каталога.
func TestIntegration_SessionRevokedChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #755.
	assert.NotContains(t, channels, "session_revoked",
		"канал снят вместе с триггером: слушателя у него нет и построить его нельзя — "+
			"у края нет драйвера Postgres, а прямое чтение базы iam краем это ban #8")

	// Положительный контроль на том же запросе, в том же прогоне: канал очереди,
	// у которого слушатель ЕСТЬ, производителя сохранил.
	assert.Contains(t, channels, "kacho_iam_subject_outbox_added",
		"рабочий канал очереди обязан остаться — если пропал и он, снято лишнее, "+
			"а не только беспотребительское")
}

// TestIntegration_AuditEventChannelHasNoProducerLeft — регрессия на снятие
// канала журнала аудита (#795).
//
// Отдельной пробой, а не строкой в соседней: предметы РАЗНЫЕ. Там канал сняли,
// потому что его слушателем по замыслу был край, а край слушать не может by
// construction. Здесь — потому что уведомление будило доставку, которой не
// существовало. Доставка появилась (#812), и канал всё равно не вернулся: вывоз
// журнала будится ОПРОСОМ, потому что требования к задержке доставки аудита
// нет, а канал — это ещё одно соединение со своим переподключением и своим
// отказом (решение и предикат пересмотра — в реестре отступлений iam,
// audit-outbox-has-no-receiver.md, имя файла историческое). Свернуть два разных
// основания в одну пробу значило бы оставить в дереве одно из них — и следующий
// читатель применил бы не то.
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт audit_event» зеленело бы и на пустом ответе — на опечатке в запросе, на
// не накатившейся схеме, на переименованной колонке каталога.
func TestIntegration_AuditEventChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #795.
	assert.NotContains(t, channels, "audit_event",
		"канал снят вместе с триггером: вывоз журнала будится опросом, и возвращать "+
			"канал не за чем — задержка доставки аудита ничем не ограничена")

	// Положительный контроль на том же запросе, в том же прогоне.
	assert.Contains(t, channels, "kacho_iam_fga_outbox",
		"рабочий канал очереди tuple'ов обязан остаться — если пропал и он, снято "+
			"лишнее, а не только беспотребительское")

	// И третье, ради чего проба нужна больше двух предыдущих: ТАБЛИЦА цела.
	// Снят был канал, а не журнал; проба, утверждающая только отсутствие канала,
	// зеленела бы и на миграции, снёсшей вместе с ним весь аудит.
	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kacho_iam.audit_outbox') IS NOT NULL`).
		Scan(&exists))
	assert.True(t, exists,
		"журнал аудита обязан остаться: снималось объявление уведомления, а не таблица")
}

// freshIamSchema — пустая БД с целиком накатанной цепью миграций iam.
func freshIamSchema(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(db, "."), "цепь миграций обязана накатиться целиком")
	return db
}

// notifyChannelsProducedBy — каналы, которые шлёт хоть одна функция ЖИВОГО
// триггера схемы kacho_iam.
//
// Читается каталог, а не файлы: функция без триггера ничего не шлёт, и триггер,
// снятый поздней миграцией, производителем не является.
func notifyChannelsProducedBy(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT DISTINCT p.prosrc
		  FROM pg_trigger tg
		  JOIN pg_proc p ON p.oid = tg.tgfoid
		  JOIN pg_class c ON c.oid = tg.tgrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE NOT tg.tgisinternal
		   AND n.nspname = 'kacho_iam'
		   AND p.prosrc ILIKE '%pg_notify%'`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var channels []string
	for rows.Next() {
		var src string
		require.NoError(t, rows.Scan(&src))
		channels = append(channels, notifyChannelLiterals(src)...)
	}
	require.NoError(t, rows.Err())
	return channels
}

// notifyChannelLiterals — имена каналов из тела функции: первый аргумент каждого
// pg_notify, взятый как строковый литерал.
func notifyChannelLiterals(src string) []string {
	var out []string
	rest := src
	for {
		i := strings.Index(rest, "pg_notify(")
		if i < 0 {
			return out
		}
		rest = rest[i+len("pg_notify("):]
		open := strings.Index(rest, "'")
		if open < 0 {
			return out
		}
		close := strings.Index(rest[open+1:], "'")
		if close < 0 {
			return out
		}
		out = append(out, rest[open+1:open+1+close])
		rest = rest[open+1+close:]
	}
}

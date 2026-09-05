// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_delivery_columns_integration_test.go — журнал смены субъекта не
// обещает доставки, которой у него нет (#1396).
//
// # Предмет
//
// `sent_at`, `attempt_count`, `last_error`, `notified_at` — колонки ДОСТАВКИ:
// их объявляет тот, кто обещает доставлять, и объявляет ровно тогда, когда
// обещает. Доставки у журнала не осталось: толчок к краю снят (#1024),
// направление развёрнуто, и потребитель читает журнал КУРСОРОМ (`id > $1`).
//
// Писателя у них нет ни одного:
//
//	вставка         `repo/kacho/pg/access_binding_repo.go` пишет
//	                (subject_id, op, event_type, payload) — и только;
//	дренаж          снят вместе с адресатом (serve.go, #1024): `UPDATE … SET
//	                sent_at` не исполняет никто;
//	сканер          снят там же — величины «возраст самой старой неотправленной»
//	                и «число отравленных» описывали бы не сбой, а устройство;
//	триггер журнала `subject_change_outbox_notify` читает только `NEW.id`.
//
// Читателя — тоже ни одного: проекция чтения выбирает id, subject_id, op и тип
// субъекта из тела, контракт `InternalIAMService.PollSubjectChanges` этих
// величин не выставляет.
//
// # Почему индекс снимается ЯВНО, а не заодно
//
// `subject_change_pending_v2_idx` — частичный по `sent_at IS NULL`. Postgres
// снял бы его сам вместе с колонкой, МОЛЧА: у `DROP COLUMN` это штатное
// поведение, а не оплошность. Молчаливое снятие индекса — не то, что читатель
// миграции должен восстанавливать по памяти о поведении СУБД, поэтому оператор
// стоит в тексте, а эта проба утверждает его исход.
//
// # Почему проба по ЖИВОЙ схеме
//
// Текст миграции говорит, что колонки сняты; живая схема говорит, сняты ли они
// на самом деле — после проигрывания всей цепи, включая любую позднюю миграцию,
// которая могла бы их вернуть. Первое — намерение, второе — исход.
package migrations_test

import (
	"database/sql"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deliveryColumnsOfTheJournal — величины, снимаемые #1396.
var deliveryColumnsOfTheJournal = []string{"sent_at", "attempt_count", "last_error", "notified_at"}

// TestIntegration_SubjectChangeJournalCarriesNoDeliveryColumns — регрессия на
// сужающий шаг расширения-сужения (#1396).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «колонки sent_at
// нет» зеленело бы и на снесённом журнале, и на опечатке в имени таблицы — то
// есть ровно там, где вердикт нужен больше всего.
func TestIntegration_SubjectChangeJournalCarriesNoDeliveryColumns(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	columns := columnsOf(t, db, "kacho_iam", "subject_change_outbox")

	t.Logf("перепись: колонок у kacho_iam.subject_change_outbox — %d (%v)",
		len(columns), columns)

	require.NotEmpty(t, columns,
		"перепись пуста: журнала нет вовсе либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #1396.
	for _, gone := range deliveryColumnsOfTheJournal {
		assert.NotContains(t, columns, gone,
			"колонка доставки %q осталась в журнале, у которого доставки нет: "+
				"её не пишет вставка, не двигает дренаж (снят вместе с адресатом, #1024) "+
				"и не читает потребитель — он идёт по курсору `id > $1`. Колонка, "+
				"которую никто не читает и не пишет, обещает механизм, которого нет", gone)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на том же запросе и в том же прогоне: величины, у
	// которых читатель ЕСТЬ, обязаны остаться. Без него отрицание выше зеленело
	// бы и на миграции, снёсшей журнал целиком, — а его читает край курсором.
	for _, kept := range []string{"id", "subject_id", "op", "event_type", "payload", "created_at"} {
		assert.Contains(t, columns, kept,
			"величина, которую читают, обязана остаться: снималась доставка, "+
				"которой некому доставлять, а не журнал — его читает край курсором "+
				"по id (InternalIAMService.PollSubjectChanges)")
	}
}

// TestIntegration_SubjectChangeJournalKeepsNoUnsentTailIndex — частичный индекс
// по неотправленным строкам уходит вместе с предикатом, который его задавал.
//
// Отдельной пробой, а не строкой предыдущей: колонка и индекс — разные предметы,
// и снятие индекса здесь наступает ДВУМЯ путями (оператор миграции и каскад
// `DROP COLUMN`). Утверждать надо исход, каким бы путём он ни был достигнут.
func TestIntegration_SubjectChangeJournalKeepsNoUnsentTailIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	indexes := indexesOf(t, db, "kacho_iam", "subject_change_outbox")

	t.Logf("перепись: индексов у kacho_iam.subject_change_outbox — %d (%v)",
		len(indexes), indexes)

	require.NotEmpty(t, indexes,
		"перепись пуста: у журнала нет ни одного индекса, включая первичный ключ — "+
			"значит читается не та таблица, и отрицание ниже зеленеет ни на чём")

	assert.NotContains(t, indexes, "subject_change_pending_v2_idx",
		"частичный индекс по неотправленным строкам пережил свой предикат: "+
			"`WHERE sent_at IS NULL` над колонкой, которой больше нет. Он обслуживал "+
			"клейм дренажа, а дренажа у журнала нет (#1024)")

	// Положительный контроль: путь доступа, которым журнал ЧИТАЮТ, остаётся.
	// Выборка идёт `WHERE id > $1 ORDER BY id ASC LIMIT n`, и её обслуживает
	// первичный ключ — снять его вместе с приманкой значило бы разменять один
	// лишний индекс на отсутствие нужного.
	assert.Contains(t, indexes, "subject_change_outbox_pkey",
		"первичный ключ журнала обязан остаться: по нему идёт единственная "+
			"живая выборка — курсор `id > $1 ORDER BY id ASC`")
}

// indexesOf — имена индексов таблицы по ЖИВОЙ схеме, отсортированные.
//
// Читается каталог, а не текст миграций: индекс, снятый каскадом `DROP COLUMN`,
// в тексте создавшей его миграции остался бы, и предикат по файлам объявил бы
// живым снятое — ровно тот класс, ради которого проба и заведена.
func indexesOf(t *testing.T, db *sql.DB, schema, table string) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT i.relname
		  FROM pg_index x
		  JOIN pg_class c ON c.oid = x.indrelid
		  JOIN pg_class i ON i.oid = x.indexrelid
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE n.nspname = $1
		   AND c.relname = $2`, schema, table)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var out []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		out = append(out, name)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_channel_intent_journal_integration_test.go — уведомление журнала
// намерений снято вместе со своим дренажом (#1436).
//
// # Почему отдельным файлом, а не строкой в соседнем
//
// Семейство проб «канал без слушателя» живёт в
// notify_channel_has_a_listener_integration_test.go, и предметы там РАЗНЫЕ: у
// #755 слушателя не было никогда и построить его нельзя; у #795 уведомление
// будило доставку, которой не существовало. Здесь третье основание, и оно не
// сводится к первым двум: слушатель БЫЛ — дренаж применял каждую строку журнала
// к внешнему движку отношений, — и снят вместе с самим движком, а журнал
// остался и остаётся не «на всякий случай». Свернуть разные основания в одну
// пробу значило бы оставить в дереве одно из них.
//
// # Что здесь утверждается сверх отсутствия канала
//
// Журнал и его свёртка ОБЯЗАНЫ уцелеть, и это половина, ради которой проба
// нужна больше самого отрицания. Снималось объявление уведомления, а не
// механизм: из строк `kaname.fga_outbox` триггер `relation_fact_follows_journal`
// (миграция 0098) складывает прямой факт, из которого форма собирает вердикт о
// доступе — В ТОМ ЖЕ КОММИТЕ, синхронно. Проба, утверждающая только отсутствие
// канала, зеленела бы и на миграции, снёсшей вместе с ним источник вердикта, —
// причём МОЛЧА: таблица осталась бы на месте, запросы продолжили бы
// исполняться, а ответы поехали бы в сторону отказа.
package migrations_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIntegration_IntentJournalChannelHasNoProducerLeft — регрессия на снятие
// канала журнала намерений (#1436).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт kaname_fga_outbox» зеленело бы и на пустом ответе — на опечатке в
// запросе, на не накатившейся схеме, на переименованной колонке каталога.
func TestIntegration_IntentJournalChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет #1436.
	assert.NotContains(t, channels, "kaname_fga_outbox",
		"канал снят вместе с триггером: дренаж, который его слушал, убран вместе с "+
			"внешним движком отношений, а прямой факт складывается из этого же журнала "+
			"триггером в ТОМ ЖЕ коммите (0098) — будить уведомлением некого")

	// Положительный контроль на том же запросе, в том же прогоне: канал, чей
	// потребитель ЖИВ и назван прод-кодом
	// (`repo/kaname/pg/reconcile_notify.go`, `LISTEN` на reconcileOutboxChannel).
	assert.Contains(t, channels, "kaname_resource_reconcile_outbox",
		"рабочий канал очереди обязан остаться — если пропал и он, снято лишнее, "+
			"а не только беспотребительское")

	// И третье, ради чего проба нужна больше отрицания: ЖУРНАЛ и его СВЁРТКА целы.
	var journalExists bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.fga_outbox') IS NOT NULL`).Scan(&journalExists))
	assert.True(t, journalExists,
		"журнал намерений обязан остаться: снималось объявление уведомления, а не "+
			"источник прямого факта")

	var foldAlive bool
	require.NoError(t, db.QueryRow(`
		SELECT EXISTS (
			SELECT 1
			  FROM pg_trigger tg
			  JOIN pg_class c ON c.oid = tg.tgrelid
			  JOIN pg_namespace n ON n.oid = c.relnamespace
			 WHERE NOT tg.tgisinternal
			   AND n.nspname = 'kaname'
			   AND c.relname = 'fga_outbox'
			   AND tg.tgname = 'relation_fact_follows_journal')`).Scan(&foldAlive))
	assert.True(t, foldAlive,
		"свёртка журнала в прямой факт обязана остаться: она и есть причина, по "+
			"которой журнал переживает свой дренаж, — сняв её вместе с каналом, "+
			"мы обесточили бы источник вердикта о доступе, и обесточили бы молча")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_compensation_notify_leaves_integration_test.go — уведомление очереди
// компенсаций снято вместе со своим слушателем (kaname#363).
//
// # Почему отдельным файлом, а не строкой в соседнем
//
// Семейство проб «канал без слушателя» живёт в
// notify_channel_has_a_listener_integration_test.go и
// notify_channel_intent_journal_integration_test.go, и основания там разные. Здесь
// четвёртое: слушатель БЫЛ — дренаж компенсаций будился этим каналом и снимал у
// внешнего поставщика клиента, которого откатившаяся сага успела там завести, — и
// снят вместе с административной дорогой к поставщику. Снят и писатель намерения:
// строк в очередь не кладёт ни один путь, и будить уведомлением некого и незачем.
//
// Снятие дренажа оставило триггер на месте, и гейт класса
// [TestIntegration_EveryProducedNotifyChannelIsNamedByAConsumer] назвал канал
// беспотребительским. Эта проба держит предмет снятия ОТДЕЛЬНО от гейта: гейт
// говорит «у каждого производимого канала есть потребитель», а здесь сказано,
// какой именно канал ушёл и что осталось вместо него.
//
// # Что здесь утверждается сверх отсутствия канала
//
// ТАБЛИЦА цела, и это половина, ради которой проба нужна больше отрицания.
// Снимается объявление уведомления, а не очередь: строки, записанные прежней
// посадкой, держит видимыми перепись очереди
// (`cmd/kaname/provider_compensation_wiring.go`), доставленные снимает уборщик
// (`kanamepg.ProviderCompensationSweeper`). Проба, утверждающая только отсутствие
// канала, зеленела бы и на миграции, снёсшей вместе с ним всю очередь, — и
// остаток, который исполнить нечем, стал бы невидимым.
package migrations_test

import (
	"database/sql"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// providerCompensationChannel — канал, который снимается. Выписан литералом в
// ПРОБЕ, а не взят у прод-кода: у прод-кода этого имени больше нет, и именно
// это отсутствие и сделало канал беспотребительским.
const providerCompensationChannel = "kaname_provider_compensation_outbox"

// providerCompensationNotifyLeavesVersion — версия миграции снятия. Откат ниже
// неё обязан вернуть триггер: иначе «после наката канала нет» зеленело бы и на
// схеме, которая его не производила никогда.
const providerCompensationNotifyLeavesVersion int64 = 20260930090111

// providerCompensationNotifyFunctionPresent — жива ли функция триггера. Функция
// без триггера ничего не шлёт, но остаётся в схеме объявлением механизма,
// которого нет, — и следующий читатель построит на ней вывод.
func providerCompensationNotifyFunctionPresent(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var present bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regprocedure('kaname.provider_compensation_outbox_notify()') IS NOT NULL`).
		Scan(&present))
	return present
}

// providerCompensationQueuePresent — цела ли сама очередь.
func providerCompensationQueuePresent(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var present bool
	require.NoError(t, db.QueryRow(
		`SELECT to_regclass('kaname.provider_compensation_outbox') IS NOT NULL`).Scan(&present))
	return present
}

// TestIntegration_ProviderCompensationChannelHasNoProducerLeft — регрессия на
// снятие канала очереди компенсаций (kaname#363).
//
// Утверждается ПАРА, и вторая половина обязательна: без неё «ни один триггер не
// шлёт kaname_provider_compensation_outbox» зеленело бы и на пустом ответе — на
// опечатке в запросе, на не накатившейся схеме, на переименованной колонке
// каталога.
func TestIntegration_ProviderCompensationChannelHasNoProducerLeft(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	channels := notifyChannelsProducedBy(t, db)

	require.NotEmpty(t, channels,
		"перепись пуста: схема не накатилась либо запрос к каталогу читает не то — "+
			"на пустой переписи любое отрицание ниже зеленеет, ничего не проверив")

	// Отрицание — предмет kaname#363.
	assert.NotContains(t, channels, providerCompensationChannel,
		"канал снят вместе с триггером: дренаж, который его слушал, и писатель "+
			"намерения убраны вместе с административной дорогой к поставщику — "+
			"строк в очередь не кладёт никто, будить некого")
	assert.False(t, providerCompensationNotifyFunctionPresent(t, db),
		"функция уведомления осталась без триггера: механизма нет, а его объявление "+
			"в схеме есть")

	// Положительный контроль на том же запросе, в том же прогоне: канал, чей
	// потребитель ЖИВ и назван прод-кодом.
	assert.Contains(t, channels, notifyChannelWithAProvenConsumer,
		"рабочий канал очереди обязан остаться — если пропал и он, снято лишнее, "+
			"а не только беспотребительское")

	// И третье: ОЧЕРЕДЬ цела.
	assert.True(t, providerCompensationQueuePresent(t, db),
		"очередь компенсаций обязана остаться: снималось объявление уведомления, а "+
			"не таблица, чей остаток держат видимым перепись и уборщик")
}

// TestIntegration_ProviderCompensationNotifyRollsBackAndReapplies — откат
// миграции снятия возвращает триггер и его функцию, повторный накат снимает их
// снова.
//
// Без отката «после наката канала нет» было бы неотличимо от «канала не было
// никогда»: утверждение держит только пара, в которой одна сторона ПРОИЗВОДИТ
// канал.
func TestIntegration_ProviderCompensationNotifyRollsBackAndReapplies(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	steps := 0
	for {
		v, err := goose.GetDBVersion(db)
		require.NoError(t, err)
		if v < providerCompensationNotifyLeavesVersion {
			break
		}
		require.NoError(t, goose.Down(db, "."), "откат обязан проходить")
		steps++
	}
	require.Positive(t, steps,
		"откат не сделал ни шага: миграции снятия в цепи нет — утверждения ниже беспредметны")

	assert.Contains(t, notifyChannelsProducedBy(t, db), providerCompensationChannel,
		"после отката канал не производится: откат не вернул триггер")
	assert.True(t, providerCompensationNotifyFunctionPresent(t, db),
		"после отката функции уведомления нет: откат вернул не то строение")

	require.NoError(t, goose.Up(db, "."), "повторный накат обязан проходить")
	assert.NotContains(t, notifyChannelsProducedBy(t, db), providerCompensationChannel,
		"после повторного наката канал производится снова")
	assert.False(t, providerCompensationNotifyFunctionPresent(t, db),
		"после повторного наката функция уведомления осталась")
	assert.True(t, providerCompensationQueuePresent(t, db),
		"повторный накат снял очередь")
}

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

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// providerCompensationChannel — канал, который снимается. Выписан литералом в
// ПРОБЕ, а не взят у прод-кода: у прод-кода этого имени больше нет, и именно
// это отсутствие и сделало канал беспотребительским.
const providerCompensationChannel = "kaname_provider_compensation_outbox"

// providerCompensationNotifyLeavesVersion — версия миграции снятия.
const providerCompensationNotifyLeavesVersion int64 = 20260930090111

// providerCompensationNotifyBelowVersion — граница «до снятия»: подъём до неё и
// откат к ней берут каждую миграцию цепи, чья версия не выше, и ни одной выше.
//
// Граница выписана ЧИСЛОМ, а не взята из имени файла снятия, и это несущее.
// Вычисление из файла падало бы на дереве, где файла ещё нет, строкой «файла в
// цепи нет» — отказом предпосылки, а не утверждения: «проверять нечего» вместо
// «строение стоит». Число же законно на любом дереве: там, где снятия нет, подъём
// до границы и подъём до конца дают одну схему, и проба краснеет на том, что
// утверждает, — строение уведомления после наката стоит.
const providerCompensationNotifyBelowVersion = providerCompensationNotifyLeavesVersion - 1

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

// providerCompensationNotifyStructure — строение уведомления очереди, как его
// печатает каталог: определение каждого пользовательского триггера очереди
// (`pg_get_triggerdef`) и определение функции уведомления (`pg_get_functiondef`)
// — имя, подпись, язык и тело дословно. Пустой перечень — строения нет.
//
// Спрашиваются ВСЕ пользовательские триггеры очереди, а не триггер под прежним
// именем: откат, вернувший триггер под другим именем или на другое событие,
// иначе совпал бы с прежним строением молча.
func providerCompensationNotifyStructure(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`
		SELECT 'trigger ' || pg_get_triggerdef(tg.oid)
		  FROM pg_trigger tg
		 WHERE tg.tgrelid = to_regclass('kaname.provider_compensation_outbox')
		   AND NOT tg.tgisinternal
		UNION ALL
		SELECT 'function ' || pg_get_functiondef(p.oid)
		  FROM pg_proc p
		  JOIN pg_namespace n ON n.oid = p.pronamespace
		 WHERE n.nspname = 'kaname' AND p.proname = 'provider_compensation_outbox_notify'
		 ORDER BY 1`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()

	var facts []string
	for rows.Next() {
		var fact string
		require.NoError(t, rows.Scan(&fact))
		facts = append(facts, fact)
	}
	require.NoError(t, rows.Err())
	return facts
}

// providerCompensationNotifyAt — пустая БД, поднятая по цепи iam до названной
// версии включительно.
func providerCompensationNotifyAt(t *testing.T, version int64) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.UpTo(db, ".", version), "цепь обязана подняться до версии %d", version)
	return db
}

// TestIntegration_ProviderCompensationNotifyRollsBackAndReapplies — после наката
// строения уведомления нет; откат ниже снятия возвращает его ДОСЛОВНО таким,
// каким его оставил свод; повторный накат снимает его снова, не тронув очередь.
//
// Утверждения держатся ПАРОЙ, и ни одно не стоит без другого: «после наката
// строения нет» зеленело бы и на схеме, которая его не производила никогда, а
// «после отката строение прежнее» — на откате, которому нечего было откатывать.
// Вместе они говорят то, что нужно: строение сняла миграция выше границы, и её
// откат вернул его без расхождения.
//
// Эталон берётся у той же цепи, остановленной на границе, а не выписывается
// литералом: сравнение идёт с тем, что оставил свод, в любой редакции свода.
//
// Предпосылок у пробы две, и обе исполнимы на любом дереве, где есть свод:
// эталон непуст и называет канал. Отсутствие миграции снятия предпосылкой НЕ
// является — на таком дереве проба исполняется целиком и краснеет на
// утверждениях о строении после наката.
func TestIntegration_ProviderCompensationNotifyRollsBackAndReapplies(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}

	// Эталон — строение на границе «до снятия».
	below := providerCompensationNotifyAt(t, providerCompensationNotifyBelowVersion)
	want := providerCompensationNotifyStructure(t, below)
	t.Logf("эталон на границе %d: фактов строения %d", providerCompensationNotifyBelowVersion, len(want))
	require.NotEmpty(t, want,
		"эталон пуст: на границе нет ни триггера, ни функции уведомления — сравнивать откат не с чем")
	require.Contains(t, notifyChannelsProducedBy(t, below), providerCompensationChannel,
		"эталон не производит канал: сравнение отката с ним ничего не утверждало бы о канале")

	db := freshIamSchema(t)

	// Утверждение 1 — после наката строения нет.
	assert.Empty(t, providerCompensationNotifyStructure(t, db),
		"после наката строение уведомления стоит: триггер либо функция очереди компенсаций "+
			"пережили снятие (kaname#363)")
	assert.NotContains(t, notifyChannelsProducedBy(t, db), providerCompensationChannel,
		"после наката канал производится")

	// Утверждение 2 — откат к границе возвращает строение дословно.
	require.NoError(t, goose.DownTo(db, ".", providerCompensationNotifyBelowVersion), "откат обязан проходить")
	assert.Equal(t, want, providerCompensationNotifyStructure(t, db),
		"откат обязан вернуть строение уведомления дословно таким, каким его оставил свод")

	// Утверждение 3 — повторный накат снимает строение снова и не трогает очередь.
	require.NoError(t, goose.Up(db, "."), "повторный накат обязан проходить")
	assert.Empty(t, providerCompensationNotifyStructure(t, db),
		"после повторного наката строение уведомления стоит снова")
	assert.NotContains(t, notifyChannelsProducedBy(t, db), providerCompensationChannel,
		"после повторного наката канал производится снова")
	assert.True(t, providerCompensationQueuePresent(t, db),
		"повторный накат снял очередь")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// drain_order_declared_injection_test.go — доказательство, что распознаватель
// дренажа СПОСОБЕН найти и СПОСОБЕН смолчать — по КАЖДОЙ названной форме.
//
// # Почему синтетика, а не настоящее дерево
//
// Ни одну из сторон на настоящем дереве не показать, не сломав его: дефект туда
// пришлось бы внести, а законный близнец там уже стоит и потому ничего не
// доказывает поодиночке. Корпус здесь приходит ЗНАЧЕНИЕМ (`check.TreeCorpus`),
// поэтому обе стороны подаются одному и тому же разбору, каким судит гейт, — не
// копии его предиката.
//
// # Одно-фактность
//
// Мир каждого случая отличается от близнеца РОВНО ОДНИМ названным фактом.
// Инъекция, меняющая два, оставляет неизвестным, какой из них дал находку.
//
// # Что доказывается отдельно от находок
//
// Пустой обход обязан быть ОТКАЗОМ, а не «находок ноль»: гейт, которому нечего
// было читать, зелен по построению и неотличим от исправного.
package check_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// queuesOfFixture — очереди «схемы» синтетического мира.
var queuesOfFixture = []string{"kaname.demo_outbox", "kaname.other_outbox"}

// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА «ПРОВОДКА»

// wiringWithKey — дренаж с ключом порядка.
const wiringWithKey = `package fixture

import "github.com/PRO-Robotech/corelib/outbox/drainer"

func wire() drainer.Config {
	return drainer.Config{
		Table:           "kaname.demo_outbox",
		PartitionColumn: "recipient",
	}
}
`

// wiringWithoutKey — тот же мир БЕЗ одного факта: ключа порядка.
const wiringWithoutKey = `package fixture

import "github.com/PRO-Robotech/corelib/outbox/drainer"

func wire() drainer.Config {
	return drainer.Config{
		Table: "kaname.demo_outbox",
	}
}
`

// scannerOfTheSameQueue — законный близнец: сканер СОСТОЯНИЯ той же очереди.
// Он ничего не двигает, поэтому дренажем не является и вопроса о порядке не
// задаёт. Без него «дренируемых столько-то» зеленело бы на любом месте с полем
// `Table`.
const scannerOfTheSameQueue = `package fixture

import outboxmetrics "github.com/PRO-Robotech/corelib/outbox/metrics"

func scan() outboxmetrics.CollectorConfig {
	return outboxmetrics.CollectorConfig{
		Table: "kaname.demo_outbox",
	}
}
`

// foreignPackageSameTypeName — законный близнец второго рода: тип называется
// так же, а пакет ЧУЖОЙ. Разбор, судящий по имени пакета в месте вызова, принял
// бы его за свой.
const foreignPackageSameTypeName = `package fixture

import drainer "example.com/mailer/drainer"

func wire() drainer.Config {
	return drainer.Config{
		Table: "kaname.demo_outbox",
	}
}
`

// unknownTypeOfTheQueueLibrary — НОВАЯ ФОРМА: тип с полем `Table` из
// пространства машинерии очередей, чья роль не объявлена.
const unknownTypeOfTheQueueLibrary = `package fixture

import "github.com/PRO-Robotech/corelib/outbox/pusher"

func wire() pusher.PushConfig {
	return pusher.PushConfig{
		Table: "kaname.demo_outbox",
	}
}
`

// wiringNamesTheRoster — обоснование пустого ключа СОСЛАЛОСЬ на роспись этого
// дерева.
const wiringNamesTheRoster = `package fixture

import "github.com/PRO-Robotech/corelib/outbox/drainer"

func wire() drainer.Config {
	return drainer.Config{
		Table: "kaname.demo_outbox",
		// Ключа нет: поток коммутативен, обоснование — в commutativeDrainExempt.
	}
}
`

// wiringNamesAForeignRoster — тот же мир, отличается ОДНИМ фактом:
// квалификатором росписи.
const wiringNamesAForeignRoster = `package fixture

import "github.com/PRO-Robotech/corelib/outbox/drainer"

func wire() drainer.Config {
	return drainer.Config{
		Table: "kaname.demo_outbox",
		// Ключа нет: поток коммутативен, обоснование — в repohygiene.commutativeDrainExempt.
	}
}
`

// wiringNamesTableByConstant — очередь названа ИМЕНЕМ КОНСТАНТЫ, а не литералом.
// Вторая законная форма записи; не знай её разбор, очередь выпала бы из переписи
// вместе со своим решением о порядке.
const wiringNamesTableByConstant = `package fixture

import (
	"github.com/PRO-Robotech/corelib/outbox/drainer"

	"example.com/app/clients"
)

func wire() drainer.Config {
	return drainer.Config{
		Table: clients.DemoTable,
	}
}
`

const constDeclaresTheTable = `package clients

const DemoTable = "kaname.demo_outbox"
`

// constClashesOnTheSameName — второй прод-файл называет ТЕМ ЖЕ именем ДРУГУЮ
// таблицу. Резолв неоднозначен, и угадывать нельзя.
const constClashesOnTheSameName = `package other

const DemoTable = "kaname.other_outbox"
`

// ─────────────────────────────────────────────────────────────────────────────
// ФОРМА «СОБСТВЕННЫЙ ОПЕРАТОР»

// operatorClaimsAndMarks — обе половины движителя: клейм неотправленных и
// пометка отправленной.
const operatorClaimsAndMarks = `package fixture

// drain ведёт очередь сам.
func drain(q querier) {
	q.Query(` + "`" + `SELECT id FROM kaname.demo_outbox
		 WHERE sent_at IS NULL
		 ORDER BY id ASC
		 LIMIT $1 FOR UPDATE SKIP LOCKED` + "`" + `)
	q.Exec(` + "`" + `UPDATE kaname.demo_outbox SET sent_at = now() WHERE id = $1` + "`" + `)
}
`

// operatorClaimsOnly — законный близнец: уборка доставленных читает тот же
// признак и НЕ является дренажом, потому что ничего не помечает отправленным.
const operatorClaimsOnly = `package fixture

func sweep(q querier) {
	q.Query(` + "`" + `SELECT id FROM kaname.demo_outbox
		 WHERE sent_at IS NULL
		 ORDER BY id ASC
		 LIMIT $1 FOR UPDATE SKIP LOCKED` + "`" + `)
}
`

// operatorOnAForeignTable — законный близнец: те же обе половины, но таблица не
// принадлежит схеме. Без сужения по схеме распознаватель счёл бы очередью всякое
// имя, попавшее в строку с признаком доставки, — включая образцы в собственном
// исходнике проверок.
const operatorOnAForeignTable = `package fixture

func drain(q querier) {
	q.Query(` + "`" + `SELECT id FROM public.not_a_queue
		 WHERE sent_at IS NULL
		 ORDER BY id ASC
		 LIMIT $1` + "`" + `)
	q.Exec(` + "`" + `UPDATE public.not_a_queue SET sent_at = now() WHERE id = $1` + "`" + `)
}
`

// operatorOrdersByPartition — тот же движитель, отличается ОДНИМ фактом:
// колонкой в `ORDER BY`.
const operatorOrdersByPartition = `package fixture

func drain(q querier) {
	q.Query(` + "`" + `SELECT id FROM kaname.demo_outbox
		 WHERE sent_at IS NULL
		 ORDER BY object_id, id
		 LIMIT $1` + "`" + `)
	q.Exec(` + "`" + `UPDATE kaname.demo_outbox SET sent_at = now() WHERE id = $1` + "`" + `)
}
`

// operatorNamesTheRosterInItsDoc — обоснование стоит в ШАПКЕ движителя, где его
// читают, а не в середине запроса.
const operatorNamesTheRosterInItsDoc = `package fixture

// drain ведёт очередь сам.
//
// Ключа партиции нет: обоснование — в commutativeDrainExempt.
func drain(q querier) {
	q.Query(` + "`" + `SELECT id FROM kaname.demo_outbox
		 WHERE sent_at IS NULL
		 ORDER BY id ASC
		 LIMIT $1` + "`" + `)
	q.Exec(` + "`" + `UPDATE kaname.demo_outbox SET sent_at = now() WHERE id = $1` + "`" + `)
}
`

// invOf — перепись синтетического мира, собранная ТЕМ ЖЕ разбором, каким судит
// гейт.
func invOf(t *testing.T, corpus check.TreeCorpus) check.QueueInventory {
	t.Helper()
	inv, err := check.DrainInventoryOf(corpus, queuesOfFixture)
	if err != nil {
		t.Fatalf("разбор синтетического корпуса: %v", err)
	}
	return inv
}

func TestDrainRecognizer_WiringFormCanFindAndCanStaySilent(t *testing.T) {
	t.Parallel()

	t.Run("ключ порядка задан — очередь найдена С ключом", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": wiringWithKey})
		site, ok := inv.Drained["kaname.demo_outbox"]
		if !ok {
			t.Fatal("дренаж по проводке НЕ распознан — распознаватель слеп к форме")
		}
		if site.Form != check.DrainFormWiring {
			t.Fatalf("форма %q, ожидалась %q", site.Form, check.DrainFormWiring)
		}
		if site.OrderKey != "recipient" {
			t.Fatalf("ключ порядка %q, ожидался %q", site.OrderKey, "recipient")
		}
	})

	t.Run("ключа нет — очередь найдена БЕЗ ключа", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": wiringWithoutKey})
		site, ok := inv.Drained["kaname.demo_outbox"]
		if !ok {
			t.Fatal("дренаж без ключа НЕ распознан — гейт не способен упасть")
		}
		if site.OrderKey != "" {
			t.Fatalf("ключ порядка %q при его отсутствии в проводке", site.OrderKey)
		}
	})

	t.Run("сканер той же очереди — молчание", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": scannerOfTheSameQueue})
		if _, ok := inv.Drained["kaname.demo_outbox"]; ok {
			t.Fatal("сканер СОСТОЯНИЯ принят за дренаж — гейт потребовал бы ключа порядка " +
				"от места, которое строк не двигает")
		}
		if inv.Roles["сканер"] != 1 {
			t.Fatalf("сканер не осмотрен вовсе (роли %v) — молчание означает слепоту, "+
				"а не отсутствие предмета", inv.Roles)
		}
	})

	t.Run("чужой пакет с тем же именем типа — молчание", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": foreignPackageSameTypeName})
		if len(inv.Drained) != 0 {
			t.Fatalf("чужой пакет принят за машинерию очередей: %v — разбор судит имя, "+
				"а не путь импорта", inv.Drained)
		}
		if len(inv.Unclassified) != 0 {
			t.Fatalf("чужой пакет объявлен неизвестной формой: %v — пространство отказа "+
				"шире своего предмета", inv.Unclassified)
		}
	})

	t.Run("неизвестный тип библиотеки очередей — ЯВНЫЙ ОТКАЗ", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": unknownTypeOfTheQueueLibrary})
		if len(inv.Unclassified) != 1 {
			t.Fatalf("новая форма объявления НЕ названа находкой: %v — всё записанное ею "+
				"осталось бы вне наблюдения молча", inv.Unclassified)
		}
		if !strings.Contains(inv.Unclassified[0], "pusher.PushConfig") {
			t.Fatalf("находка не называет тип: %q", inv.Unclassified[0])
		}
	})

	t.Run("роспись названа своя — делегирование засчитано", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": wiringNamesTheRoster})
		site := inv.Drained["kaname.demo_outbox"]
		if site == nil || !site.RosterNamed {
			t.Fatal("ссылка на роспись ЭТОГО дерева не засчитана — гейт требовал бы её " +
				"от места, где она уже стоит")
		}
		if len(site.ForeignRoster) != 0 {
			t.Fatalf("своя роспись объявлена чужой: %v", site.ForeignRoster)
		}
	})

	t.Run("роспись названа чужая — находка, а не делегирование", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": wiringNamesAForeignRoster})
		site := inv.Drained["kaname.demo_outbox"]
		if site == nil {
			t.Fatal("дренаж не распознан")
		}
		if site.RosterNamed {
			t.Fatal("ссылка на роспись ЧУЖОГО репозитория засчитана как делегирование — " +
				"проверка зеленеет ровно на том дефекте, ради которого заведена")
		}
		if len(site.ForeignRoster) != 1 {
			t.Fatalf("чужая роспись не названа находкой: %v", site.ForeignRoster)
		}
	})

	t.Run("очередь названа константой — резолвится", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{
			"a.go":       wiringNamesTableByConstant,
			"clients.go": constDeclaresTheTable,
		})
		if _, ok := inv.Drained["kaname.demo_outbox"]; !ok {
			t.Fatalf("очередь, названная константой, НЕ резолвится (%v) — вторая законная "+
				"форма записи вне наблюдения", inv.Drained)
		}
		if len(inv.Ambiguous) != 0 {
			t.Fatalf("неоднозначность объявлена там, где имя одно: %v", inv.Ambiguous)
		}
	})

	t.Run("константа-тёзка с другим значением — неоднозначность названа", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{
			"a.go":       wiringNamesTableByConstant,
			"clients.go": constDeclaresTheTable,
			"other.go":   constClashesOnTheSameName,
		})
		if len(inv.Ambiguous) != 1 || inv.Ambiguous[0] != "DemoTable" {
			t.Fatalf("неоднозначность резолва НЕ названа: %v — угаданное имя таблицы "+
				"означало бы вердикт о чужой очереди", inv.Ambiguous)
		}
	})

	t.Run("константа-тёзка, которой никто не назвал очередь, — молчание", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{
			"a.go":       wiringWithKey,
			"clients.go": constDeclaresTheTable,
			"other.go":   constClashesOnTheSameName,
		})
		if len(inv.Ambiguous) != 0 {
			t.Fatalf("неоднозначность объявлена вхолостую: %v — перечень, полный "+
				"безразличных имён, перестают читать", inv.Ambiguous)
		}
	})
}

func TestDrainRecognizer_OperatorFormCanFindAndCanStaySilent(t *testing.T) {
	t.Parallel()

	t.Run("клейм и пометка — дренаж найден", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": operatorClaimsAndMarks})
		site, ok := inv.Drained["kaname.demo_outbox"]
		if !ok {
			t.Fatal("форма «собственный оператор» НЕ распознана — ровно та слепота, ради " +
				"которой заведён гейт: очередь осталась бы вне переписи дренируемых")
		}
		if site.Form != check.DrainFormOperator {
			t.Fatalf("форма %q, ожидалась %q", site.Form, check.DrainFormOperator)
		}
		if site.OrderKey != "" {
			t.Fatalf("ключ порядка %q при `ORDER BY id` — колонки машинерии очереди "+
				"приняты за партицию", site.OrderKey)
		}
	})

	t.Run("только клейм, без пометки — молчание", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": operatorClaimsOnly})
		if _, ok := inv.Drained["kaname.demo_outbox"]; ok {
			t.Fatal("уборка принята за дренаж: она читает тот же признак и ничего не " +
				"применяет — гейт потребовал бы от неё ключа порядка")
		}
		if inv.LiteralsRead == 0 {
			t.Fatal("строковых литералов осмотрено ноль — молчание означает слепоту")
		}
	})

	t.Run("обе половины над таблицей вне схемы — молчание", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": operatorOnAForeignTable})
		if len(inv.Drained) != 0 {
			t.Fatalf("имя вне схемы принято за очередь: %v", inv.Drained)
		}
	})

	t.Run("ORDER BY по партиции — ключ найден", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": operatorOrdersByPartition})
		site, ok := inv.Drained["kaname.demo_outbox"]
		if !ok {
			t.Fatal("дренаж не распознан")
		}
		if site.OrderKey != "object_id" {
			t.Fatalf("ключ порядка %q, ожидался %q — разбор `ORDER BY` слеп к партиции",
				site.OrderKey, "object_id")
		}
	})

	t.Run("роспись названа в шапке движителя — делегирование засчитано", func(t *testing.T) {
		inv := invOf(t, check.TreeCorpus{"a.go": operatorNamesTheRosterInItsDoc})
		site := inv.Drained["kaname.demo_outbox"]
		if site == nil || !site.RosterNamed {
			t.Fatal("ссылка из ШАПКИ движителя не засчитана — обоснование пришлось бы " +
				"прятать в середину запроса, где его никто не читает")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// СХЕМА

const migrationDeclaresAQueue = `
CREATE TABLE kaname.demo_outbox (
    id bigint NOT NULL,
    sent_at timestamp with time zone
);
`

// Отличается ОДНИМ фактом: колонки-признака доставки нет.
const migrationDeclaresAQueueWithoutMarker = `
CREATE TABLE kaname.demo_outbox (
    id bigint NOT NULL
);
`

// Отличается ОДНИМ фактом: объявление стоит в КОММЕНТАРИИ.
const migrationMentionsAQueueInAComment = `
-- CREATE TABLE kaname.demo_outbox (id bigint, sent_at timestamptz);
CREATE TABLE kaname.plain_table (id bigint NOT NULL);
`

const migrationDropsTheQueue = `
DROP TABLE IF EXISTS kaname.demo_outbox;
`

func TestQueuesOfSchema_CanFindAndCanStaySilent(t *testing.T) {
	t.Parallel()

	t.Run("очередь заведена — видна обоими признаками", func(t *testing.T) {
		q, err := check.QueuesOfSchema(check.TreeCorpus{"0001.sql": migrationDeclaresAQueue})
		if err != nil {
			t.Fatalf("разбор схемы: %v", err)
		}
		if len(q.ByName) != 1 || len(q.ByMarker) != 1 {
			t.Fatalf("по имени %v, по признаку доставки %v — один из двух признаков слеп",
				q.ByName, q.ByMarker)
		}
	})

	t.Run("колонки доставки нет — признак ИМЕНИ всё равно видит", func(t *testing.T) {
		q, err := check.QueuesOfSchema(check.TreeCorpus{"0001.sql": migrationDeclaresAQueueWithoutMarker})
		if err != nil {
			t.Fatalf("разбор схемы: %v", err)
		}
		if len(q.ByName) != 1 || len(q.ByMarker) != 0 {
			t.Fatalf("по имени %v, по признаку доставки %v — признаки перестали "+
				"различаться, и расхождение между ними больше не видно", q.ByName, q.ByMarker)
		}
		if len(q.Live()) != 1 {
			t.Fatalf("живых очередей %v — объединение признаков потеряло очередь", q.Live())
		}
	})

	t.Run("объявление в комментарии — молчание", func(t *testing.T) {
		q, err := check.QueuesOfSchema(check.TreeCorpus{"0001.sql": migrationMentionsAQueueInAComment})
		if err != nil {
			t.Fatalf("разбор схемы: %v", err)
		}
		if len(q.Live()) != 0 {
			t.Fatalf("объяснение принято за объявление: %v — гейт судит текст, а не "+
				"исполняемое", q.Live())
		}
		if q.TablesRead != 1 {
			t.Fatalf("объявлений таблиц осмотрено %d, ожидалось 1 — молчание означало бы "+
				"слепоту, а не отсутствие предмета", q.TablesRead)
		}
	})

	t.Run("очередь снята более поздней миграцией — не живая", func(t *testing.T) {
		q, err := check.QueuesOfSchema(check.TreeCorpus{
			"0001.sql": migrationDeclaresAQueue,
			"0002.sql": migrationDropsTheQueue,
		})
		if err != nil {
			t.Fatalf("разбор схемы: %v", err)
		}
		if len(q.Live()) != 0 {
			t.Fatalf("снятая таблица объявлена живой очередью: %v — ложная находка "+
				"выключает проверку быстрее, чем её чинят", q.Live())
		}
	})
}

// TestDrainRecognizer_EmptyTraversalIsRefused — «ноль находок» обязано быть
// отличимо от «ноль прочитанного», и доказано это ИСПОЛНЕНИЕМ, а не чтением
// ветки отказа.
func TestDrainRecognizer_EmptyTraversalIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := check.DrainInventoryOf(check.TreeCorpus{}, queuesOfFixture); !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой корпус Go принят за чистое дерево: %v", err)
	}
	if _, err := check.QueuesOfSchema(check.TreeCorpus{}); !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("пустой корпус миграций принят за схему без очередей: %v", err)
	}
	// КОНТРОЛЬ: на непустом корпусе тот же разбор отказа НЕ даёт — иначе
	// доказанным оказался бы разбор, отказывающий всегда.
	if _, err := check.DrainInventoryOf(check.TreeCorpus{"a.go": wiringWithKey}, queuesOfFixture); err != nil {
		t.Fatalf("КОНТРОЛЬ: непустой корпус объявлен пустым: %v", err)
	}
	if _, err := check.QueuesOfSchema(check.TreeCorpus{"0001.sql": migrationDeclaresAQueue}); err != nil {
		t.Fatalf("КОНТРОЛЬ: непустой корпус миграций объявлен пустым: %v", err)
	}
}

// TestQueuesOfSchema_RefusesWhenNothingParsed — корпус непуст, а объявлений
// таблиц в нём ноль: это слепота разбора, а не схема без очередей.
func TestQueuesOfSchema_RefusesWhenNothingParsed(t *testing.T) {
	t.Parallel()

	_, err := check.QueuesOfSchema(check.TreeCorpus{"0001.sql": "-- одни комментарии\n"})
	if !errors.Is(err, check.ErrEmptyTraversal) {
		t.Fatalf("корпус без единого объявления таблицы принят за схему: %v — признак, "+
			"разъехавшийся со схемой, молчал бы «чисто»", err)
	}
}

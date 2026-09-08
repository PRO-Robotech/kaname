// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// migration_0064_fga_outbox_autoanalyze_integration_test.go
//
// Pins the per-table autovacuum settings migration 0064 put on
// kaname.fga_outbox.
//
// ЗДЕСЬ ЖИЛА ВТОРАЯ ПРОБА — «журнал несёт ОБА индекса клейма»
// (TestMigration0063_FGAOutbox_CarriesBothClaimIndexes). Она снята вместе со
// своим предметом (kacho#1042): оба индекса были ЧАСТИЧНЫМИ по `sent_at IS NULL`
// и существовали ради клейма дренажа. Дренажа не стало вместе с внешним движком
// отношений (стадия S6 эпика #747, `a4b6cfba9`), а колонки доставки и все четыре
// частичных индекса сняла миграция 20260822160000 (kacho#917). Единственным
// утверждением той пробы было существование снятого — то есть она утверждала
// несуществующее.
//
// ЧТО ОСТАЁТСЯ ПРЕДМЕТОМ ЭТОГО ФАЙЛА. Настройки 0064 стоят на таблице и сегодня:
// журнал append-mostly, его пишет КАЖДАЯ выдача и КАЖДЫЙ отзыв, и замороженная
// статистика на нём — по-прежнему замороженная статистика. Проба закрепляет
// ровно то, что миграция объявила, и ничего сверх.
//
// РЕШЕНИЕ ПРИНЯТО (kacho#1049): НАСТРОЙКИ ОСТАЮТСЯ, ПРОБА ОСТАЁТСЯ — с причиной,
// а не по умолчанию. Прежняя редакция называла это открытым вопросом «отдельной
// задачи»; задача пришла и требует записать исход, потому что вопрос, у которого
// нет ни срока, ни держателя, переживает своё основание.
//
// Довод, по которому выбрано «оставить», а не «снять миграцией»:
//
//  1. СНЯТИЕ СТОИТ МИГРАЦИИ И НЕ ПОКУПАЕТ НИЧЕГО. Применённую миграцию править
//     нельзя (ban #5), значит отзыв — новая миграция и новый перекат. Взамен не
//     возвращается ни строка ёмкости, ни миллисекунда: настройка меняет только
//     ЧАСТОТУ анализа и уборки этой одной таблицы;
//  2. ПРЕДМЕТ У НАСТРОЙКИ ОСТАЛСЯ, ХОТЯ И НЕ ТОТ. Ушёл план клейма; остался сам
//     журнал — append-mostly, его пишет КАЖДАЯ выдача и КАЖДЫЙ отзыв, и
//     замороженная статистика на нём остаётся замороженной статистикой для
//     всякого, кто по нему пойдёт;
//  3. СНЯТИЕ БЫЛО БЫ НЕОБРАТИМЫМ ПО ЦЕНЕ ОШИБКИ. Вернуть настройку — третья
//     миграция; ошибиться здесь дороже, чем оставить применённое.
//
// ЧТО ЭТО РЕШЕНИЕ НЕ УТВЕРЖДАЕТ — сказано, чтобы его не читали шире. Оно не
// утверждает, что настройка сегодня что-то ускоряет: единственный читатель
// журнала в прод-коде — де-дуп загрузочного добора
// (`services/iam/internal/apps/kaname/seed/migrate_backfill.go`), одноразовый и на
// пути запроса не стоящий. Появится читатель на пути запроса — довод 2 станет
// измеримым; исчезнет журнал — настройка уйдёт вместе с таблицей. Ни одно из
// двух не требует новой задачи: предикат назван здесь.

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// TestMigration0064_FGAOutbox_KeepsStatisticsFresh закрепляет per-table настройки
// автовакуума, которые миграция 0064 поставила на kaname.fga_outbox.
//
// Настройки заведены под план клейма дренажа: оценка по `sent_at IS NULL` бралась
// из последнего ANALYZE, очередь почти всегда пуста, поэтому во всплеск въезжала
// оценка `rows=1`, планировщик отбрасывал оба частичных индекса и брал вложенный
// цикл. Замер на живом стенде тогда: 4488 мс против 3.6 мс сразу после ANALYZE —
// на БОЛЬШЕЙ глубине. Умолчание автовакуума (50 + 0.1 * n_live_tup ≈ 21751 строк)
// больше целого всплеска, поэтому без этих настроек статистика замерзала ровно на
// том окне, где план и решает.
//
// Ни клейма, ни частичных индексов, ни `sent_at` больше нет (см. шапку файла).
// Проба закрепляет то, что миграция 0064 ПРИМЕНИЛА и что снимается только новой
// миграцией; довод выше сохранён как история решения, а не как описание
// сегодняшнего плана. Решение «оставить» записано в шапке файла (kacho#1049).
func TestMigration0064_FGAOutbox_KeepsStatisticsFresh(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var reloptions []string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(c.reloptions, '{}')
		   FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		  WHERE n.nspname = 'kaname' AND c.relname = 'fga_outbox'`,
	).Scan(&reloptions))

	// reloptions come back as "key=value" strings; compare NUMERICALLY so the
	// assertion does not depend on how a given Postgres spells the stored float
	// ("0" vs "0.0").
	opts := make(map[string]float64, len(reloptions))
	for _, kv := range reloptions {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		f, err := strconv.ParseFloat(v, 64)
		if err != nil {
			continue
		}
		opts[k] = f
	}

	// scale_factor=0 decouples the trigger from table SIZE (an append-mostly outbox
	// outgrows any percentage-based threshold); the fixed threshold ties it to
	// absolute churn instead. The threshold is asserted as an upper bound, not an
	// exact value — tuning it DOWN keeps the guarantee, raising it past a burst's
	// worth of churn silently restores the stale-statistics plan.
	for _, want := range []struct {
		key    string
		atMost float64
	}{
		{"autovacuum_analyze_scale_factor", 0},
		{"autovacuum_analyze_threshold", 1000},
		{"autovacuum_vacuum_scale_factor", 0},
		{"autovacuum_vacuum_threshold", 1000},
	} {
		got, ok := opts[want.key]
		require.True(t, ok,
			"kaname.fga_outbox обязан нести %s — это то, что применила миграция 0064: "+
				"статистика append-mostly журнала не должна замерзать между всплесками записи. "+
				"got reloptions=%v", want.key, reloptions)
		require.LessOrEqual(t, got, want.atMost,
			"kaname.fga_outbox %s=%v выше порога миграции 0064: статистика уходила бы в "+
				"устаревание больше чем на всплеск записи.", want.key, got)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// migration_0064_fga_outbox_autoanalyze_integration_test.go
//
// Pins the per-table autovacuum settings migration 0064 put on
// kacho_iam.fga_outbox.
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
// ОТКРЫТЫЙ ВОПРОС, НАЗВАННЫЙ ПРЯМО, А НЕ УМОЛЧАННЫЙ: план, ради которого 0064
// писалась, — клейм дренажа — больше не существует, поэтому обоснование самой
// НАСТРОЙКИ пережило свой предмет, хотя настройка применена и снимается только
// новой миграцией (ban #5). Это предмет отдельной задачи, не этой. Предикат, по
// которому его решать: если у журнала не появится читателя, идущего по
// статистике, настройки снимаются; сегодняшний единственный читатель в
// прод-коде — де-дуп загрузочного добора
// (`services/iam/internal/apps/kacho/seed/migrate_backfill.go`), одноразовый и
// на пути запроса не стоящий.

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
)

// TestMigration0064_FGAOutbox_KeepsStatisticsFresh закрепляет per-table настройки
// автовакуума, которые миграция 0064 поставила на kacho_iam.fga_outbox.
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
// сегодняшнего плана.
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
		  WHERE n.nspname = 'kacho_iam' AND c.relname = 'fga_outbox'`,
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
			"kacho_iam.fga_outbox обязан нести %s — это то, что применила миграция 0064: "+
				"статистика append-mostly журнала не должна замерзать между всплесками записи. "+
				"got reloptions=%v", want.key, reloptions)
		require.LessOrEqual(t, got, want.atMost,
			"kacho_iam.fga_outbox %s=%v выше порога миграции 0064: статистика уходила бы в "+
				"устаревание больше чем на всплеск записи.", want.key, got)
	}
}

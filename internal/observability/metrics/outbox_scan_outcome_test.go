// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// outbox_scan_outcome_test.go — задача #2062: «скан не отработал ни разу» и
// «наблюдения нет» обязаны выглядеть ПО-РАЗНОМУ.
//
// # Предмет
//
// Состояние очередей снимается периодическим сканом. Измерители размечены
// меткой таблицы, а измеритель без детей семейства не отдаёт вовсе — значит до
// первого УДАЧНОГО скана рядов нет. Отказ скана (неверные права, сломанный
// запрос, недоступная база) давал строку в журнале и ничего больше, поэтому
// картина наблюдаемых величин у отказавшего сканера была ПУСТОЙ — ровно как у
// сканера, которого не провязали вовсе. Мёртвый контроль невидим
// (`security.md` §Hardening п. 8в).
//
// # Почему нельзя было просто завести измеритель возраста нулём
//
// Ноль возраста означает «очередь пуста», то есть ложь до первого скана.
// Поэтому исход другой: СЧЁТЧИКИ исходов скана, у которых ноль — законное
// значение, а отсутствие ряда невозможно by construction (клетки заводятся при
// провязке).
//
// # Две пробы, и они спрашивают разное
//
//  1. отказавший скан ОСТАВЛЯЕТ след — спрашивается без базы, потому что отказ
//     производится настоящим сканером детерминированно;
//  2. исправный скан пустой очереди даёт ДРУГУЮ картину, чем отказавший, —
//     спрашивается на живой базе настоящим сканером, иначе «различаются» было
//     бы свойством дублёра.

import (
	"context"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

// probedOutboxTable — очередь, на которой снимается картина. Любая очередь
// сервиса подошла бы: решение объявлено одним для всех, и проба обязана быть
// про решение, а не про конкретную таблицу.
const probedOutboxTable = "kacho_iam.provider_compensation_outbox"

// outboxPicture — наблюдаемая картина ЭТОЙ таблицы: ряды семейств очереди с их
// значениями, в устойчивом порядке.
//
// Читается из реестра целиком, а не по именам, которые проба ожидает: перечень
// имён в пробе стал бы вторым местом об одном предмете и умолчал бы о ряде,
// который перестали публиковать.
func outboxPicture(t *testing.T, r *Registry, table string) []string {
	t.Helper()

	families, err := r.reg.Gather()
	require.NoError(t, err)

	var out []string
	for _, fam := range families {
		if !strings.HasPrefix(fam.GetName(), "kacho_iam_outbox_") {
			continue
		}
		for _, m := range fam.GetMetric() {
			mine := false
			var labels []string
			for _, lp := range m.GetLabel() {
				if lp.GetName() == "table" && lp.GetValue() == table {
					mine = true
				}
				labels = append(labels, lp.GetName()+"="+lp.GetValue())
			}
			if !mine {
				continue
			}
			sort.Strings(labels)
			out = append(out, fam.GetName()+"{"+strings.Join(labels, ",")+"}="+valueOf(m))
		}
	}
	sort.Strings(out)
	return out
}

func valueOf(m *dto.Metric) string {
	switch {
	case m.GetGauge() != nil:
		return formatFloat(m.GetGauge().GetValue())
	case m.GetCounter() != nil:
		return formatFloat(m.GetCounter().GetValue())
	default:
		return "?"
	}
}

func formatFloat(v float64) string { return strconv.FormatFloat(v, 'g', -1, 64) }

// TestOutboxScanFailure_LeavesATraceOfItsOwn — отказавший скан обязан оставить
// след, отличимый от «наблюдения нет».
func TestOutboxScanFailure_LeavesATraceOfItsOwn(t *testing.T) {
	t.Parallel()

	// Сканер БЕЗ пула отказывает детерминированно и делает это НАСТОЯЩИМ кодом
	// сканера — не дублёром, который «изображает отказ».
	failing := NewRegistry()
	rec := failing.OutboxRecorder()
	observer := OutboxScanObserver(rec, probedOutboxTable, slog.New(slog.DiscardHandler), "scan failed")

	col := outboxmetrics.NewCollector(nil, rec, outboxmetrics.CollectorConfig{
		Table:       probedOutboxTable,
		MaxAttempts: 5,
		Interval:    time.Hour,
	})
	for i := 0; i < 3; i++ {
		err := col.Scan(context.Background())
		require.Error(t, err, "сканер без пула обязан отказать — иначе проба меряет не отказ")
		observer(err)
	}

	picture := outboxPicture(t, failing, probedOutboxTable)
	t.Logf("перепись: рядов у отказавшего сканера %d: %s", len(picture), strings.Join(picture, " · "))

	require.NotEmpty(t, picture,
		"отказавший скан не оставил НИ ОДНОГО ряда: «скан не работал ни разу» неотличимо от «наблюдения нет»")

	// Ряд обязан НАЗЫВАТЬ число отказов, а не только существовать: ряд,
	// заведённый нулём и не двигающийся, о работе сканера не говорит ничего.
	require.Contains(t, strings.Join(picture, " "), "scan_failures_total",
		"среди рядов нет счётчика отказов скана: %v", picture)
	require.Contains(t, strings.Join(picture, " "), "=3",
		"счётчик отказов не назвал их число (было три отказа): %v", picture)
}

// TestOutboxScan_HealthyEmptyQueueDiffersFromAFailingScan — контроль: исправный
// скан ПУСТОЙ очереди даёт другую картину.
func TestOutboxScan_HealthyEmptyQueueDiffersFromAFailingScan(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var rows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM `+probedOutboxTable).Scan(&rows))
	require.Zero(t, rows, "очередь не пуста — контроль спрашивал бы не о том состоянии")

	healthyReg := NewRegistry()
	healthyRec := healthyReg.OutboxRecorder()
	_ = OutboxScanObserver(healthyRec, probedOutboxTable, slog.New(slog.DiscardHandler), "scan failed")
	healthyCol := outboxmetrics.NewCollector(pool, healthyRec, outboxmetrics.CollectorConfig{
		Table:       probedOutboxTable,
		MaxAttempts: 5,
		Interval:    time.Hour,
	})
	require.NoError(t, healthyCol.Scan(ctx), "исправный скан пустой очереди обязан пройти")

	failingReg := NewRegistry()
	failingRec := failingReg.OutboxRecorder()
	failingObserver := OutboxScanObserver(failingRec, probedOutboxTable, slog.New(slog.DiscardHandler), "scan failed")
	failingCol := outboxmetrics.NewCollector(nil, failingRec, outboxmetrics.CollectorConfig{
		Table:       probedOutboxTable,
		MaxAttempts: 5,
		Interval:    time.Hour,
	})
	failingObserver(failingCol.Scan(ctx))

	healthy := outboxPicture(t, healthyReg, probedOutboxTable)
	broken := outboxPicture(t, failingReg, probedOutboxTable)
	t.Logf("перепись: рядов у исправного скана %d, у отказавшего %d", len(healthy), len(broken))

	require.NotEmpty(t, healthy, "исправный скан пустой очереди не оставил рядов — контроль беспредметен")
	require.NotEmpty(t, broken, "отказавший скан не оставил рядов")
	require.NotEqual(t, healthy, broken,
		"исправный скан ПУСТОЙ очереди и всегда отказывающий дают ОДНУ картину:\nисправный: %v\nотказавший: %v",
		healthy, broken)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// outbox_metrics_wiring.go — сканеры СОСТОЯНИЯ очередей kacho-iam.
//
// # Что производит дренаж и чего он не производит
//
// Дренаж сообщает о СОБЫТИЯХ: строка применилась, строка отравилась, голова
// партиции висит дольше порога. Всё это уходит в лог. «В очереди лежит N строк,
// старейшей M секунд, из них K отравлено» — это СОСТОЯНИЕ, и его не производит
// никто, кроме периодического скана таблицы. Без него застрявшая очередь
// неотличима от пустой: обе молчат одинаково.
//
// # Почему именно эти две очереди и почему это не «на всякий случай»
//
// `kacho_iam.fga_outbox` — та самая очередь, через которую физически уходит
// КАЖДЫЙ отзыв прав: снятие привязки, удаление члена группы, delete-stale
// реконсайлера. Её собственная конфигурация дренажа подробно объясняет, почему
// запись и удаление одного tuple не коммутируют и чем грозит их перестановка —
// то есть утверждение о ПОРЯДКЕ там уже есть. Утверждения о ДОСТАВКЕ не было ни
// одного, и сводные величины его дать не могут: выдачи идут непрерывно, поэтому
// глубина мала и голова молода, что бы ни происходило со снятием. Различает их
// только `delivered_total{direction="withdrawal"}`.
//
// `kacho_iam.subject_change_outbox` доставляет инвалидацию кэша решений о
// доступе на шлюз. Недоставленная строка означает, что край продолжает отвечать
// по устаревшему вердикту — ровно тот эффект, ради предотвращения которого
// очередь и заведена. Разложение по направлению к ней не применяется; ПОЧЕМУ —
// сказано один раз в записи repohygiene.outboxDirectionSplitExempt, где перечень
// видов события машинно сверяется со словарём, закрытым миграцией. Здесь оно не
// пересказывается намеренно: пересказ того же вывода у соседней очереди уже
// пережил свой предмет и стал ложным, когда приехал второй вид события.
//
// # Что скан НЕ делает
//
// Не мутирует таблицу, не участвует в пути запроса и не может уронить под:
// ошибки скана логируются и цикл продолжается. Наблюдаемость — не гейт.
package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"
)

// outboxMetricsInterval — период скана. Совпадает с остальными сервисами
// платформы: одна и та же величина у всех очередей, чтобы порог тревоги,
// написанный по одной, читался одинаково на любой.
const outboxMetricsInterval = 15 * time.Second

// runFGAOutboxMetrics — скан очереди tuple'ов, сводно и по направлению.
//
// Порог отравления берётся из той же конфигурации, что исполняет дренаж, а не
// повторяется числом: это одна величина, и разойдись эти два места, гейдж
// отравленных считал бы не то, что дренаж отравляет. Имя таблицы, наоборот,
// названо КОНСТАНТОЙ, а не полем чужой структуры: гейт
// repohygiene.TestEveryDrainedOutboxIsObserved резолвит координату очереди
// разбором исходника, и адрес, вычисляемый в рантайме, для него неотличим от
// отсутствующего. Это та же константа, что стоит в конфигурации дренажа, —
// расхождению взяться неоткуда.
func runFGAOutboxMetrics(ctx context.Context, pool *pgxpool.Pool, rec outboxmetrics.Recorder, logger *slog.Logger) {
	collector := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       fgaOutboxTable,
		MaxAttempts: fgaOutboxDrainerConfig().MaxAttempts,
		Interval:    outboxMetricsInterval,
		Directions:  outboxmetrics.TupleOutboxDirections(),
	})
	collector.Run(ctx, func(err error) {
		logger.Warn("fga outbox metrics scan failed", "table", fgaOutboxTable, "err", err)
	})
}

// runSubjectChangeOutboxMetrics — скан очереди инвалидаций кэша вердиктов.
func runSubjectChangeOutboxMetrics(ctx context.Context, pool *pgxpool.Pool, rec outboxmetrics.Recorder, logger *slog.Logger) {
	collector := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       subjectChangeOutboxTable,
		MaxAttempts: subjectChangeMaxAttempts,
		Interval:    outboxMetricsInterval,
	})
	collector.Run(ctx, func(err error) {
		logger.Warn("subject_change outbox metrics scan failed", "table", subjectChangeOutboxTable, "err", err)
	})
}

// auditOutboxTable — журнал аудита control-plane.
//
// Константой, а не полем чужой структуры, по той же причине, что и у соседей:
// гейт repohygiene резолвит координату очереди разбором исходника, и адрес,
// вычисляемый в рантайме, для него неотличим от отсутствующего.
const auditOutboxTable = "kacho_iam.audit_outbox"

// auditOutboxMaxAttempts — порог отравления.
//
// Здесь он объявлен ЗДЕСЬ, а не взят из конфигурации дренажа, ровно потому, что
// дренажа НЕТ. Значение совпадает с умолчанием пакета дренажа: гейдж отравленных
// обязан считать по тому же порогу, по которому будет травить будущий дренаж, —
// иначе в день его появления величина сменит смысл молча.
const auditOutboxMaxAttempts = 10

// runAuditOutboxMetrics — скан журнала аудита, У КОТОРОГО ДРЕНАЖА НЕТ.
//
// # Почему сканер есть, а дренажа нет
//
// Приёмника аудита в продукте не существует (предикат: ни одного не-тестового
// файла Go, объявляющего приёмник/экспортёр/отправитель аудита). Дренаж некуда
// вести, и построить его — отдельная под-фаза со своей приёмкой, а не побочный
// эффект наблюдаемости. Снять очередь тоже нельзя: это журнал аудита
// control-plane, и его снятие — решение уровня требований, а не уборка кода.
//
// # Что тогда делает этот сканер
//
// Делает МОЛЧАНИЕ СЛЫШИМЫМ. `data-integrity.md` требует, чтобы «ноль
// доставленных строк за всю жизнь очереди» было заметно; до этого сканера
// заметить это было нечем — величины не существовало вовсе. Он НЕ изображает
// доставку: `outbox_backlog_depth` растёт монотонно, `oldest_pending_age_seconds`
// равен возрасту стенда, `poisoned` остаётся нулём (попыток не было). Именно
// такая картина и есть верное описание положения дел.
//
// Замер на стенде kind-kacho 2026-08-20: строк 29 446, все недоставленные,
// max(attempts)=0, старейшей 2 д 21 ч — ровно возраст стенда.
//
// # Почему форма объявляется
//
// Эта очередь помечает доставленность СОСТОЯНИЕМ (`status`), а не отметкой
// времени. Пока форма подразумевалась, сканер над ней падал бы на первом же
// скане («колонки sent_at нет») — то есть очередь была ненаблюдаема by
// construction, и её ненаблюдаемость выглядела как ненужность наблюдения.
//
// Решение и предикат его пересмотра:
// services/iam/docs/engineering/architecture/audit-outbox-has-no-receiver.md
func runAuditOutboxMetrics(ctx context.Context, pool *pgxpool.Pool, rec outboxmetrics.Recorder, logger *slog.Logger) {
	collector := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       auditOutboxTable,
		MaxAttempts: auditOutboxMaxAttempts,
		Interval:    outboxMetricsInterval,
		Shape:       outboxmetrics.ShapeStatus,
	})
	collector.Run(ctx, func(err error) {
		logger.Warn("audit outbox metrics scan failed", "table", auditOutboxTable, "err", err)
	})
}

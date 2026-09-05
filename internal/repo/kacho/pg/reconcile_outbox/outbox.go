// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package reconcile_outbox — emit + drain helpers for
// kacho_iam.resource_reconcile_outbox.
//
// RegisterResource/UnregisterResource enqueues an event HERE in the SAME
// writer-tx as the resource_mirror UPSERT/DELETE (atomic co-commit, ban #10).
// The reconciler-worker claims unsent events and re-evaluates every
// access_binding_target_member that references the changed object. The event is
// a "this object's mirror state changed, recompute" signal — the reconciler
// recomputes from the LIVE resource_mirror, so a delete event simply finds the
// row gone.
package reconcile_outbox

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const (
	// EventUpsert / EventDelete — the two mirror-change event types.
	EventUpsert = "mirror.upsert"
	EventDelete = "mirror.delete"

	// MaxAttempts — порог отсечки: строка, которой дренаж отказал столько раз
	// подряд, из клейма ВЫПАДАЕТ и повторяться перестаёт.
	//
	// Величина совпадает с умолчанием прочих очередей дерева, чтобы порог
	// тревоги, написанный по одной, читался одинаково на любой.
	//
	// ПОЧЕМУ ОТСЕЧКА, А НЕ ВЕЧНЫЙ ПОВТОР. Постоянно падающее событие до #2050
	// повторялось бессрочно, не двигая ни `attempt_count`, ни `last_error`:
	// столбцы были объявлены схемой и не писались никем, то есть создавали ВИД
	// учёта попыток. Читатель схемы заключал, что отсечка есть.
	//
	// РАДИУС ОТСЕЧКИ — ОДНО СОБЫТИЕ, А НЕ ОЧЕРЕДЬ. События здесь коммутативны:
	// каждое означает «состояние зеркала этого объекта изменилось, пересчитай»,
	// а пересчёт идёт от ЖИВОГО зеркала, поэтому порядок между объектами не
	// значим и отсечённая строка не запирает соседей. Клейма по голове партиции
	// (как у очереди кортежей) здесь не требуется by construction.
	//
	// ЧТО ОТСЕЧКА НЕ ДЕЛАЕТ: она не отменяет сверку. Периодический проход
	// (`sweep`) пересчитывает каждую выдачу с отбором независимо от очереди,
	// поэтому отсечённое событие означает отложенную, а не потерянную сходимость.
	MaxAttempts = 10
)

// DrainedRetention — сколько дренированная строка живёт после применения.
//
// ПОРОГ ЕСТЬ ФУНКЦИЯ ПРЕДИКАТА ЧИТАТЕЛЯ, и у этой таблицы читатель ровно один —
// дренаж, который берёт НЕотправленные. Дренированной строки не читает НИКТО:
// сверка идёт от живого зеркала, а не от истории событий. Значит порог не
// выводится из чужой политики и не может быть у неё позаимствован — он
// объявляется здесь и означает окно, в котором оператор ещё видит, что дренаж
// применил.
//
// Ноль здесь был бы неверен: снятие в той же транзакции, что и пометка,
// оставило бы очередь без единого следа применения, и разбор «событие пришло и
// сошлось» стал бы невозможен. Сутки выбраны как окно одной смены дежурства.
const DrainedRetention = 24 * time.Hour

// Event — a claimed reconcile event.
type Event struct {
	ID         int64
	ObjectType string
	ObjectID   string
	EventType  string
}

// EmitTx enqueues a reconcile event on the caller tx (atomic co-commit with the
// resource_mirror change). objectType/objectID identify the changed object.
func EmitTx(ctx context.Context, tx pgx.Tx, eventType, objectType, objectID string) error {
	if tx == nil {
		return fmt.Errorf("reconcile_outbox: tx must not be nil")
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kacho_iam.resource_reconcile_outbox (object_type, object_id, event_type)
		 VALUES ($1, $2, $3)`,
		objectType, objectID, eventType,
	); err != nil {
		return fmt.Errorf("reconcile_outbox: emit %s: %w", eventType, err)
	}
	return nil
}

// querier — pool/tx surface for the claim scan.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// execQuerier — pool/tx surface для учёта попытки и уборки.
type execQuerier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// ClaimBatch reads the next unsent events (ordered by id) up to `limit`. It does
// NOT mark them sent — the caller marks each sent only after a successful
// reconcile (MarkSent), so a crash mid-reconcile re-delivers the event
// (at-least-once; the reconcile is idempotent). FOR UPDATE SKIP LOCKED lets
// multiple worker replicas claim disjoint batches without blocking.
//
// ОТРАВЛЕННЫЕ СТРОКИ ИЗ КЛЕЙМА ИСКЛЮЧЕНЫ (`attempt_count < MaxAttempts`).
// Строка, которой дренаж отказал столько раз подряд, не применится и на
// следующем проходе — повторять её значит тратить каждый проход на заведомый
// отказ и прятать за ним живые события. Она остаётся в таблице (её видит скан
// состояния как `poisoned`), но клеймом больше не берётся.
func ClaimBatch(ctx context.Context, q querier, limit int) ([]Event, error) {
	rows, err := q.Query(ctx,
		`SELECT id, object_type, object_id, event_type
		   FROM kacho_iam.resource_reconcile_outbox
		  WHERE sent_at IS NULL
		    AND attempt_count < $2
		  ORDER BY id ASC
		  LIMIT $1
		  FOR UPDATE SKIP LOCKED`,
		limit, MaxAttempts)
	if err != nil {
		return nil, fmt.Errorf("reconcile_outbox: claim batch: %w", err)
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(&e.ID, &e.ObjectType, &e.ObjectID, &e.EventType); err != nil {
			return nil, fmt.Errorf("reconcile_outbox: scan: %w", err)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RecordFailure учитывает ОДИН отказ дренажа по строке: увеличивает счётчик
// попыток и записывает причину.
//
// Пишется ОТДЕЛЬНОЙ короткой транзакцией, а не той, в которой сверка упала:
// упавшая откатывается целиком, и учёт попытки откатился бы вместе с ней — то
// есть счётчик не двигался бы НИКОГДА, а отсечка была бы недостижима by
// construction. Ровно этим и объяснялось, что столбцы стояли пустыми.
//
// Причина пишется как есть: таблица внутренняя, наружу её текст не уезжает
// ничем, кроме журнала оператора, — а без причины «отравлено» не отличить от
// «отравлено чем».
//
// Возвращает число попыток ПОСЛЕ учёта: вызывающему нужно знать, пересекла ли
// строка порог именно этим отказом, иначе он либо промолчит о переходе, либо
// повторит жалобу на каждом проходе.
func RecordFailure(ctx context.Context, q execQuerier, id int64, cause string) (int, error) {
	var attempts int
	if err := q.QueryRow(ctx,
		`UPDATE kacho_iam.resource_reconcile_outbox
		    SET attempt_count = attempt_count + 1,
		        last_error    = $2
		  WHERE id = $1
		RETURNING attempt_count`,
		id, cause,
	).Scan(&attempts); err != nil {
		return 0, fmt.Errorf("reconcile_outbox: record failure: %w", err)
	}
	return attempts, nil
}

// SweepDrained снимает ДРЕНИРОВАННЫЕ строки старше порога.
//
// Порог — по `sent_at`, а не по `created_at`: строка перестаёт быть нужной с
// момента, когда её применили, а не когда завели. Часы — БАЗЫ, те же, которыми
// умолчание колонки ставит время; момент времени входом не приходит (идиома
// уборки этого дерева).
//
// Неотправленные и отравленные НЕ ТРОГАЮТСЯ: первые ещё ждут применения, вторые
// суть след неприменимого события, и снятие его следа означало бы потерять
// единственное свидетельство о нём.
//
// Возвращает число снятых строк и признак «партия ушла полной». Признак — не
// удобство: без него проход не отличает «убрал всё, что было» от «упёрся в
// партию», и уборка со скоростью одна партия за тик не догоняла бы внешний темп
// НИКОГДА, оставаясь зелёной по всякой проверке «вызвался ли».
func SweepDrained(ctx context.Context, q execQuerier, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, fmt.Errorf("reconcile_outbox: batch must be positive, got %d", batch)
	}
	tag, err := q.Exec(ctx,
		`DELETE FROM kacho_iam.resource_reconcile_outbox
		  WHERE id IN (
		        SELECT id
		          FROM kacho_iam.resource_reconcile_outbox
		         WHERE sent_at IS NOT NULL
		           AND sent_at < now() - make_interval(secs => $1)
		         ORDER BY id
		         LIMIT $2
		  )`,
		grace.Seconds(), batch)
	if err != nil {
		return 0, false, fmt.Errorf("reconcile_outbox: sweep drained: %w", err)
	}
	removed := tag.RowsAffected()
	return removed, removed >= int64(batch), nil
}

// MarkSentTx marks an event drained on the caller tx (same tx as the reconcile
// writes, so the event is consumed iff the reconcile commits).
func MarkSentTx(ctx context.Context, tx pgx.Tx, id int64) error {
	if _, err := tx.Exec(ctx,
		`UPDATE kacho_iam.resource_reconcile_outbox SET sent_at = now() WHERE id = $1`,
		id,
	); err != nil {
		return fmt.Errorf("reconcile_outbox: mark sent: %w", err)
	}
	return nil
}

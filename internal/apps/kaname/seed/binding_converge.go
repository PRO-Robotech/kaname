// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// binding_converge.go — сводящий проход по выдачам как ПУТЬ ОТЗЫВА: срок
// выдачи, исход по выдаче, перепись и повтор по такту (kaname#1006).
//
// # Почему проход больше не разовый
//
// У выдачи одному субъекту лишний кортеж (например, `v_delete`, который роль
// модуля больше не получает к правке) снимает только сводящий проход: обход по
// таймеру реконсайлера, проход по объекту и правка роли читают реестр лишь у
// выдачи с двумя и более субъектами (reconcile/emitted_completion.go). Разовый
// проход при старте оставлял два окна:
//
//   - перекрытие выкатки. Реплика прежней версии, живая после прохода новой,
//     материализует новый член по прежнему вычислению (регистрация объекта →
//     проход по объекту) — с лишним кортежем. Для нового кода этот член
//     «неизменен», и до следующего старта его не сводил никто;
//   - замок-одиночка. Он общий для всех версий: держи его реплика прежней
//     версии в момент старта новой — новая пропускала проход целиком.
//
// Повтор по такту (`RunEvery`) закрывает оба: лишнее, записанное прежней
// версией, живёт не дольше интервала после её ухода плюс длительность прохода;
// пропущенный из-за чужого замка проход исполняет следующий такт. Он же —
// повтор выдачи, отказавшей в прошлом проходе, без перезапуска процесса.
//
// # Цена
//
// Проход читает реестр каждой действующей выдачи одним обращением по префиксу
// первичного ключа (`binding_id`), то есть всю таблицу
// `access_binding_emitted_tuples` за проход, под замком выдачи. У сошедшейся
// выдачи он ничего не пишет. Такт исполняет одна реплика (замок-одиночка);
// интервал назначает ручка посадки (`cmd/kaname/binding_converge_wiring.go`).

import (
	"context"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// DefaultBindingConvergeTimeout — срок одного вызова сведения выдачи по
// умолчанию. Срок ограничивает ожидание замка выдачи и саму сверку; выдача, не
// уложившаяся в него, считается отказавшей, называется в переписи и
// повторяется следующим тактом, а не держит замок-одиночку бессрочно.
const DefaultBindingConvergeTimeout = 5 * time.Minute

// failedBindingsLogged — сколько id отказавших выдач печатает перепись; полный
// перечень несёт BackfillResult.FailedBindings.
const failedBindingsLogged = 20

// Исходы сведения одной выдачи — закрытый набор, приходит из констант этого
// пакета и никогда из запроса, поэтому кардинальность метки не растёт с
// трафиком.
const (
	// BindingConvergeOutcomeConverged — выдача сведена (с первой попытки либо
	// повтором в том же проходе).
	BindingConvergeOutcomeConverged = "converged"
	// BindingConvergeOutcomeFailed — выдача не сведена и после повтора.
	BindingConvergeOutcomeFailed = "failed"
)

// BindingConvergeObserver — куда проход сообщает исход по каждой выдаче.
//
// Успехи считаются наравне с отказами: счётчик одних отказов не отличает
// «отказов не было» от «прохода не было вовсе».
type BindingConvergeObserver interface {
	IncBindingConverge(outcome string)
}

// bindingFailure — отказ сведения одной выдачи.
type bindingFailure struct {
	id  domain.AccessBindingID
	err error
}

// convergeOne сводит одну выдачу в её собственный срок.
func (r *BackfillRunner) convergeOne(ctx context.Context, id domain.AccessBindingID) error {
	cctx, cancel := context.WithTimeout(ctx, r.bindingTimeout)
	defer cancel()
	return r.engine.ConvergeBinding(cctx, id)
}

func (r *BackfillRunner) observe(outcome string) {
	if r.observer != nil {
		r.observer.IncBindingConverge(outcome)
	}
}

// logCensus печатает перепись исполненного прохода на любом исходе.
func (r *BackfillRunner) logCensus(ctx context.Context, res BackfillResult, err error) {
	shown := res.FailedBindings
	if len(shown) > failedBindingsLogged {
		shown = shown[:failedBindingsLogged]
	}
	attrs := []any{
		slog.Int("bindings_examined", res.BindingsExamined),
		slog.Int("bindings_reconciled", res.BindingsReconciled),
		slog.Int("bindings_failed", res.BindingsFailed),
		slog.Int("chunks", res.Chunks),
		slog.Any("failed_bindings", shown),
	}
	if err != nil {
		r.logger.ErrorContext(ctx, "перепись сводящего прохода по выдачам: свёл не все — "+
			"отказавшие повторит следующий такт",
			append(attrs, slog.Any("err", err))...)
		return
	}
	r.logger.InfoContext(ctx, "перепись сводящего прохода по выдачам", attrs...)
}

// RunEvery повторяет сводящий проход каждые interval, пока ctx не отменён.
// Перепись каждого исполненного прохода печатает RunOnce; здесь — только отказ
// самого прохода до обхода (замок-одиночка не взят).
func (r *BackfillRunner) RunEvery(ctx context.Context, interval time.Duration) {
	tick := time.NewTicker(interval)
	defer tick.Stop()
	r.convergeOn(ctx, tick.C)
}

// convergeOn — цикл повтора над источником тактов (проба подаёт такты сама).
func (r *BackfillRunner) convergeOn(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			res, err := r.RunOnce(ctx)
			if err != nil && !res.Executed && ctx.Err() == nil {
				r.logger.ErrorContext(ctx, "сводящий проход по выдачам не исполнен — повторит следующий такт",
					slog.Any("err", err))
			}
		}
	}
}

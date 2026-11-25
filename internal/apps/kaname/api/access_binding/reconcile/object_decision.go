// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// ObjectDecisionRoute сохраняет три существующих способа сведения объекта.
// Значение выбирает сценарий, но не передаёт доказательство допуска или тело TX.
type ObjectDecisionRoute uint8

const (
	ObjectDecisionFull ObjectDecisionRoute = iota + 1
	ObjectDecisionForward
	ObjectDecisionForwardNoStale
)

// Размеры относятся к желаемому набору одной выдачи, а не к числу изменённых
// строк. Runner возвращает их только после успешного Commit всей попытки.
type ObjectDecisionSize struct{ Objects, Tuples int }

type ObjectDecisionRunner interface {
	RunObjectDecision(context.Context, string, string, ObjectDecisionRoute) ([]ObjectDecisionSize, error)
}

// Участник FULL берёт событие группы только при открытом поколении самой группы.
type groupGenerationRunner interface {
	RunPendingGroupGeneration(context.Context, string) ([]ObjectDecisionSize, bool, error)
}

var errObjectDecisionOnly = errors.New("object decision runner rejects binding callbacks")

// Новый engine предоставляет только закрытые object routes. Общий TxRunner
// намеренно отказывает до callback: он не заменяет binding participant.
func NewObjectDecisionReconciler(runner ObjectDecisionRunner, logger *slog.Logger, cat catalog.Source) (*Reconciler, error) {
	if runner == nil || cat == nil || cat.Facts() == nil {
		return nil, errObjectParticipantAbsent
	}
	r := New(objectDecisionOnlyTx{}, logger, cat)
	r.objectDecisions = runner
	return r, nil
}

type objectDecisionOnlyTx struct{}

func (objectDecisionOnlyTx) WithTx(ctx context.Context, _ func(context.Context, ReconcileStore) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return errObjectDecisionOnly
}

// Recorder не пересекает repo boundary. Используется текущий экземпляр
// внешнего engine, в том числе nil у асинхронного пути; не мутируем общий engine.
func (r *Reconciler) runObjectDecision(ctx context.Context, typ, id string, route ObjectDecisionRoute, recorder SizeRecorder) error {
	if r == nil || r.objectDecisions == nil {
		return errObjectParticipantAbsent
	}
	sizes, err := r.objectDecisions.RunObjectDecision(ctx, typ, id, route)
	if err != nil {
		return err
	}
	recordObjectDecisionSizes(recorder, sizes)
	return nil
}

func recordObjectDecisionSizes(recorder SizeRecorder, sizes []ObjectDecisionSize) {
	if recorder != nil {
		for _, size := range sizes {
			recorder.ObserveBindingMaterialization(size.Objects, size.Tuples)
		}
	}
}

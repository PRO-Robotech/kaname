// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
)

// ObjectTxRunner получает identity объекта ДО первого чтения/старого lock.
// kaname#1034: runner не является разрешением на полный inventory scan.
type ObjectTxRunner interface {
	WithObjectTx(context.Context, string, string, func(context.Context, ReconcileStore) error) error
}

func (r *Reconciler) withObjectTx(ctx context.Context, typ, id string, fn func(context.Context, ReconcileStore) error) error {
	if tx, ok := r.tx.(ObjectTxRunner); ok {
		return tx.WithObjectTx(ctx, typ, id, fn)
	}
	return r.tx.WithTx(ctx, fn)
}

// WithGroupObjectReconciler настраивается composition root до запуска workers.
// Отдельный engine держит catalog того же immutable bundle, что и его writer.
func (r *Reconciler) WithGroupObjectReconciler(group *Reconciler) error {
	if r == nil || group == nil || group == r || group.groupObjects != nil || group.objectConfigured {
		return errors.New("invalid group object reconciler")
	}
	r.groupObjects = group
	return nil
}

var errObjectParticipantAbsent = errors.New("object participant is absent")

// WithObjectReconciler подключает общий одиночный путь до запуска workers.
// Специализированный group route сохраняет приоритет. Явный nil закрывает
// общий путь даже при ошибочно проигнорированной ошибке настройки.
func (r *Reconciler) WithObjectReconciler(object *Reconciler) error {
	if r == nil {
		return errObjectParticipantAbsent
	}
	r.objectConfigured = true
	r.objectObjects = nil
	if object == nil || object == r || object.objectConfigured || object.groupObjects != nil {
		return errObjectParticipantAbsent
	}
	r.objectObjects = object
	return nil
}

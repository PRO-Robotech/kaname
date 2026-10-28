// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// Сборщики реконсайлера привязки — по одному на ПОЛОСУ наблюдения размера
// материализации (kaname#157).
//
// Экземпляров в корне два, и оба законны: путь запроса (`wiring.go`) и фоновый
// обход (`serve.go`) — у второго своё имя в журнале и свой жизненный цикл.
// Приёмник размера прежде нёс только первый, и гистограмма, читавшаяся как
// «размер материализации привязки», означала «размер на пути запроса»: полоса
// вне наблюдения выглядит ровно как полоса без трафика, и по числам этого не
// различить.
//
// Решение: обход входит в ту же гистограмму, полосы разведены меткой `lane`.
// Полоса закрепляется ЗДЕСЬ, при сборке экземпляра, а не у места вызова: построить
// реконсайлер без полосы корень не может мимо этих двух функций — это держит
// гейт дерева `TestEveryBindingReconcilerIsBuiltWithALane`.

// newRequestBindingReconciler — реконсайлер привязки ПУТИ ЗАПРОСА: выдача,
// разнос членства при правке роли, привязка владельца, первый вход.
func newRequestBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source,
	reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, logger, cat).
		WithSizeRecorder(reg.BindingMaterializationRecorder().RequestLane())
}

// newSweepBindingReconciler — реконсайлер привязки ФОНОВОГО ОБХОДА: воркер
// очереди реконсайла, периодическая подмётка, истечение срока, а также догон и
// проверка материализации на старте — все они водят этот экземпляр.
func newSweepBindingReconciler(tx reconcileapp.TxRunner, logger *slog.Logger, cat catalog.Source,
	reg *metrics.Registry) *reconcileapp.Reconciler {
	return reconcileapp.New(tx, logger, cat).
		WithSizeRecorder(reg.BindingMaterializationRecorder().SweepLane())
}

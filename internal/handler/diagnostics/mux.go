// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package diagnostics — живость и готовность пода на диагностической
// поверхности службы.
//
// Endpoints:
//
//	GET  /healthz  — liveness probe: жив ли процесс; от зависимостей не зависит.
//	GET  /readyz   — readiness probe: готов ли обслуживать (база, версия схемы,
//	                 обработчик операций); 503 с именами упавших зависимостей.
//
// Скрейп (`/metrics`) на тот же мультиплексор кладёт композиционный корень: он
// один знает, какой реестр величин скребут.
//
// # Почему живость и готовность здесь, а не на слушателе вебхуков (kaname#360)
//
// Они жили на слушателе вебхуков поставщика личности, и из-за этого слушатель
// нельзя было снять под посадкой `own`, где поставщика нет: пробы пода шли в
// его порт. Эта поверхность поднимается при ЛЮБОЙ посадке — поэтому на ней.
// Тело готовности называет только ИМЕНА зависимостей и их состояние, без
// текста ошибок: это та же внутренняя кардинальность, что уже зеркалится
// величиной готовности в скрейп (#2494).
//
// # Живость и готовность строит ОБЪЯВЛЕННЫЙ носитель, а не этот пакет (#1752)
//
// Носитель `corelib/observability/health` уже решил срок на чекер, различение
// «носитель не провязан»/«носитель ответил», перевод в 503 на гашении и
// зеркало результата. ЧТО проверяется, знает композиционный корень; этот пакет
// только монтирует.
package diagnostics

import (
	"context"
	"errors"
	"net/http"

	"github.com/PRO-Robotech/corelib/observability/health"
)

// errHealthCarrierNotWired — носитель готовности не передан композиционным
// корнем. Это ошибка сборки, а не состояние среды, и ответ на неё —
// fail-closed: под объявляет себя НЕ готовым и называет причину.
var errHealthCarrierNotWired = errors.New("readiness carrier not wired by the composition root")

// Handlers — то, что монтирует диагностическая поверхность.
type Handlers struct {
	// Health — объявленный носитель разведённых живости и готовности. nil
	// означает «корень не провязал» и даёт fail-closed готовность, а не
	// молчаливые 200 (см. errHealthCarrierNotWired).
	Health *health.Aggregator
}

// NewMux — мультиплексор диагностической поверхности с живостью и готовностью.
func NewMux(h Handlers) *http.ServeMux {
	mux := http.NewServeMux()
	agg := h.Health
	if agg == nil {
		agg = health.New([]health.Checker{{
			Name:  "readiness-carrier",
			Check: func(context.Context) error { return errHealthCarrierNotWired },
		}})
	}
	// Образец с методом (`GET /healthz`): не-GET получает 405 от самого
	// маршрутизатора, и отдельная ветка в обработчике не нужна.
	mux.Handle("GET /healthz", agg.LiveHandler())
	mux.Handle("GET /readyz", agg.ReadyHandler())
	return mux
}

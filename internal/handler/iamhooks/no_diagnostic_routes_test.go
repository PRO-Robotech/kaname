// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks

// no_diagnostic_routes_test.go — СЛУШАТЕЛЬ ВЕБХУКОВ НЕ НЕСЁТ ЖИВОСТИ И
// ГОТОВНОСТИ (kaname#360).
//
// Готовность пода жила здесь, и из-за этого слушатель вебхуков нельзя было
// снять под посадкой `own`, где поставщика нет: пробы пода шли в его порт.
// Живость и готовность переехали на диагностическую поверхность
// (`internal/handler/diagnostics`), которая есть при любой посадке. Второй
// копии здесь не остаётся: два места, отвечающих «готов ли под», разошлись бы
// молча — одно из них гасилось бы на остановке, другое нет.

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHooksListenerCarriesNoDiagnosticRoutes(t *testing.T) {
	answered := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux := NewMux(Handlers{
		TokenHook: answered, RefreshHook: answered, ProvisionHook: answered, RecoveryHook: answered,
	})

	for _, route := range []string{"/healthz", "/readyz"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, route, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("слушатель вебхуков ответил %d на %s: готовность пода осталась на поверхности, "+
				"которой под посадкой own нет", rec.Code, route)
		}
	}

	// Законный близнец: каждый маршрут полосы по-прежнему отвечает — иначе
	// утверждение выше зеленело бы на мультиплексоре, не отвечающем ничем.
	routes := 0
	for _, r := range Routes() {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/"+r, nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("маршрут полосы /iam/v1/hooks/%s ответил %d, а не своим обработчиком", r, rec.Code)
		}
		routes++
	}
	if routes == 0 {
		t.Fatal("производитель перечня маршрутов пуст — утверждать нечего")
	}
	t.Logf("перепись: маршрутов полосы %d · диагностических путей проверено 2", routes)
}

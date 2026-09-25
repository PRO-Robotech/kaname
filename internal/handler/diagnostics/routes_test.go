// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package diagnostics

// routes_test.go — что диагностическая поверхность монтирует сверх поведения
// носителя: только свои пути, и отказ готовности там, где носитель не провязан.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Диагностическая поверхность отвечает ТОЛЬКО своими путями: путь полосы
// хуков на ней не отвечает. Близнец — объявленный путь живости отвечает.
func TestDiagnosticSurfaceAnswersOnlyItsOwnRoutes(t *testing.T) {
	mux := NewMux(Handlers{Health: nil})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/token", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("диагностическая поверхность ответила %d на путь полосы хуков, которого не объявляет", rec.Code)
	}
	got, answered := ask(t, mux, "/healthz")
	if !answered || got.code != http.StatusOK {
		t.Fatalf("объявленный путь живости обязан отвечать 200, получено %d (ответ получен: %v)", got.code, answered)
	}
}

// Непровязанный носитель — ОТКАЗ готовности с названной причиной, а не
// молчаливые 200 и не отсутствие маршрута: kubelet, получивший 404, читает его
// как неготовность без причины, и дежурному нечего искать.
func TestReadinessRefusesWhenTheCarrierIsNotWired(t *testing.T) {
	mux := NewMux(Handlers{})

	got, answered := ask(t, mux, "/readyz")
	if !answered {
		t.Fatalf("готовность не ответила за %s без носителя", readinessBudget)
	}
	if got.code != http.StatusServiceUnavailable || !strings.Contains(got.body, "readiness-carrier") {
		t.Fatalf("без носителя готовность обязана отказывать (%d) и называть причину, получено %d: %s",
			http.StatusServiceUnavailable, got.code, got.body)
	}
}

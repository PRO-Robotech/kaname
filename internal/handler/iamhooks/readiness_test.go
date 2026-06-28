// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package iamhooks

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReadinessHandler — /readyz отражает здоровье зависимостей (503 при падении
// любой, с ее именем), а /healthz остается чистым liveness (защита от
// restart-storm: деградация зависимости не убивает под).
func TestReadinessHandler(t *testing.T) {
	okCheck := ReadinessChecker{Name: "database", Check: func(context.Context) error { return nil }}
	failCheck := ReadinessChecker{Name: "lro-worker", Check: func(context.Context) error { return errors.New("worker down") }}

	t.Run("all healthy → 200", func(t *testing.T) {
		mux := NewMux(Handlers{Readiness: []ReadinessChecker{okCheck}})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})

	t.Run("a dependency down → 503 with its name", func(t *testing.T) {
		mux := NewMux(Handlers{Readiness: []ReadinessChecker{okCheck, failCheck}})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "lro-worker")
	})

	t.Run("healthz stays pure liveness even when a dependency is down", func(t *testing.T) {
		mux := NewMux(Handlers{Readiness: []ReadinessChecker{failCheck}})
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		require.Equal(t, http.StatusOK, rec.Code)
	})
}

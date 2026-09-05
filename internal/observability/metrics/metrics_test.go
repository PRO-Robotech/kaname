// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"

	"github.com/PRO-Robotech/kacho-iam/internal/observability/metrics"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

// TestNewRegistry_HandlerServesMetrics — /metrics endpoint serves the
// registry in the Prometheus text exposition format (RED: no metrics package).
func TestNewRegistry_HandlerServesMetrics(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	srv := httptest.NewServer(reg.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL) //nolint:noctx // test
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	// The Prometheus default process/go collectors are registered, so the body
	// must be non-empty exposition text.
	if len(body) == 0 {
		t.Fatal("metrics body is empty")
	}
}

// TestAuthzCheck_ObservesHistogramSample — after observing a CheckRelation, the
// authz duration histogram has exactly one sample labelled
// rpc=CheckRelation,allowed=true (RED: no instrumentation).
func TestAuthzCheck_ObservesHistogramSample(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	reg.ObserveAuthz(metrics.AuthzObservation{
		RPC:      "CheckRelation",
		Allowed:  true,
		Err:      false,
		Duration: 0.005,
	})

	const want = `kacho_iam_authz_check_duration_seconds_count{allowed="true",rpc="CheckRelation"} 1`
	got := dumpMetrics(t, reg)
	if !strings.Contains(got, want) {
		t.Fatalf("histogram sample missing.\nwant substring: %s\ngot:\n%s", want, got)
	}
}

// TestAuthzCheck_DenyCounter — a denied Check increments the deny counter.
func TestAuthzCheck_DenyCounter(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	reg.ObserveAuthz(metrics.AuthzObservation{RPC: "Check", Allowed: false, Err: false, Duration: 0.002})

	const want = `kacho_iam_authz_check_decisions_total{decision="deny",rpc="Check"} 1`
	got := dumpMetrics(t, reg)
	if !strings.Contains(got, want) {
		t.Fatalf("deny counter missing.\nwant substring: %s\ngot:\n%s", want, got)
	}
}

// TestAuthzCheck_ErrorCounter — an errored Check increments the error counter.
func TestAuthzCheck_ErrorCounter(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	reg.ObserveAuthz(metrics.AuthzObservation{RPC: "Check", Allowed: false, Err: true, Duration: 0.001})

	const want = `kacho_iam_authz_check_decisions_total{decision="error",rpc="Check"} 1`
	got := dumpMetrics(t, reg)
	if !strings.Contains(got, want) {
		t.Fatalf("error counter missing.\nwant substring: %s\ngot:\n%s", want, got)
	}
}

// TestRegistererWindowCarriesThePlatformLatencySeries — окно регистрации
// ДЕЙСТВИТЕЛЬНО принимает платформенный измеритель задержки.
//
// # Что здесь предмет, а что нет
//
// Поведение самого измерителя (ряды, метки, сетка корзин, разделение отказа и
// успеха) принадлежит `pkg/grpcsrv` и проверяется там — одиннадцатью пробами.
// Здесь предмет ровно один: `Registerer()` отдаёт тот же реестр, который
// скребут, поэтому серии, заведённые сквозь это окно, доезжают до выгрузки.
//
// # Почему проба осталась, хотя интерсептор из этого пакета ушёл
//
// Прежде здесь стояла своя пара серий со своим интерсептором; она снята как
// второе место об одном предмете. Но если бы вместе с ней ушла и проба, то у
// провязки iam не осталось бы ЛОКАЛЬНОГО доказательства: «окно есть» и «окно
// ведёт в скребомый реестр» — разные факты, и второй виден только выгрузкой.
func TestRegistererWindowCarriesThePlatformLatencySeries(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()

	lat, err := grpcsrv.NewServerLatency(reg.Registerer())
	if err != nil {
		t.Fatalf("измеритель не заводится в реестре iam: %v", err)
	}
	intr := lat.UnaryServerInterceptor(grpcsrv.ListenerInternal)
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.InternalIAMService/Check"}
	if _, err := intr(context.Background(), nil, info,
		func(context.Context, any) (any, error) { return "ok", nil }); err != nil {
		t.Fatalf("интерсептор вернул ошибку: %v", err)
	}

	got := dumpMetrics(t, reg)
	wantCount := `kacho_grpc_server_handled_total{grpc_code="OK",grpc_method="Check",` +
		`grpc_service="kacho.cloud.iam.v1.InternalIAMService",listener="internal"} 1`
	if !strings.Contains(got, wantCount) {
		t.Fatalf("счётчика обслуженных нет в выгрузке iam.\nожидалась подстрока: %s\nполучено:\n%s",
			wantCount, got)
	}
	if !strings.Contains(got, "kacho_grpc_server_handling_seconds_count{") {
		t.Fatalf("гистограммы задержки нет в выгрузке iam.\nполучено:\n%s", got)
	}
	// Зеркало: прежней пары серий больше нет. Две серии об одном предмете
	// разъезжаются, и оставленная про запас читалась бы панелями как живая.
	if strings.Contains(got, "kacho_iam_grpc_server_") {
		t.Fatalf("прежняя пара серий пережила свою замену — два места об одном предмете:\n%s", got)
	}
}

// dumpMetrics scrapes the registry's /metrics handler and returns the body.
func dumpMetrics(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reg.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics handler status = %d", rec.Code)
	}
	return rec.Body.String()
}

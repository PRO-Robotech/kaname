// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
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

// TestUnaryServerInterceptor_RecordsRequest — the gRPC server interceptor
// records a request count + latency sample with the grpc_code label.
func TestUnaryServerInterceptor_RecordsRequest(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	intr := reg.UnaryServerInterceptor()

	okHandler := func(ctx context.Context, req any) (any, error) { return "ok", nil }
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.InternalIAMService/Check"}
	if _, err := intr(context.Background(), nil, info, okHandler); err != nil {
		t.Fatalf("interceptor returned err: %v", err)
	}

	got := dumpMetrics(t, reg)
	wantCount := `kacho_iam_grpc_server_handled_total{grpc_code="OK",grpc_method="Check",grpc_service="kacho.cloud.iam.v1.InternalIAMService"} 1`
	if !strings.Contains(got, wantCount) {
		t.Fatalf("grpc handled counter missing.\nwant substring: %s\ngot:\n%s", wantCount, got)
	}
	if !strings.Contains(got, "kacho_iam_grpc_server_handling_seconds_count{") {
		t.Fatalf("grpc latency histogram missing.\ngot:\n%s", got)
	}
}

// TestUnaryServerInterceptor_RecordsErrorCode — a failed RPC records the
// gRPC status code.
func TestUnaryServerInterceptor_RecordsErrorCode(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	intr := reg.UnaryServerInterceptor()

	failHandler := func(ctx context.Context, req any) (any, error) {
		return nil, status.Error(codes.PermissionDenied, "denied")
	}
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.InternalIAMService/Check"}
	_, err := intr(context.Background(), nil, info, failHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("err code = %v, want PermissionDenied", status.Code(err))
	}

	got := dumpMetrics(t, reg)
	want := `grpc_code="PermissionDenied"`
	if !strings.Contains(got, want) {
		t.Fatalf("grpc error code label missing.\nwant substring: %s\ngot:\n%s", want, got)
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

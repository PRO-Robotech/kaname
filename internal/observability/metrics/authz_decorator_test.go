// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeAuthorizer — stub implementing the relation-native check the decorator
// wraps. Drives allowed / deny / error paths.
type fakeAuthorizer struct {
	allowed bool
	err     error
}

func (f fakeAuthorizer) CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &service.CheckResult{Allowed: f.allowed}, nil
}

// TestInstrumentedAuthorizer_AllowSamplesHistogram — the decorator delegates to
// the wrapped authorizer and records an allowed=true histogram sample, leaving
// the result untouched (clean-arch: instrumentation at the adapter boundary,
// not in the use-case).
func TestInstrumentedAuthorizer_AllowSamplesHistogram(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	dec := metrics.NewInstrumentedAuthorizer(fakeAuthorizer{allowed: true}, reg)

	res, err := dec.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "user:usr_x", Relation: "viewer", Object: "vpc_network:vpcn_y",
	})
	if err != nil {
		t.Fatalf("CheckRelation err: %v", err)
	}
	if !res.Allowed {
		t.Fatal("result Allowed = false, want true (decorator must not alter result)")
	}

	got := dumpMetrics(t, reg)
	const want = `kacho_iam_authz_check_duration_seconds_count{allowed="true",rpc="CheckRelation"} 1`
	if !strings.Contains(got, want) {
		t.Fatalf("histogram sample missing.\nwant: %s\ngot:\n%s", want, got)
	}
}

// TestInstrumentedAuthorizer_DenyCounter — a deny decision increments the deny
// counter and records allowed=false.
func TestInstrumentedAuthorizer_DenyCounter(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	dec := metrics.NewInstrumentedAuthorizer(fakeAuthorizer{allowed: false}, reg)

	if _, err := dec.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "user:usr_x", Relation: "editor", Object: "vpc_network:vpcn_y",
	}); err != nil {
		t.Fatalf("CheckRelation err: %v", err)
	}

	got := dumpMetrics(t, reg)
	const want = `kacho_iam_authz_check_decisions_total{decision="deny",rpc="CheckRelation"} 1`
	if !strings.Contains(got, want) {
		t.Fatalf("deny counter missing.\nwant: %s\ngot:\n%s", want, got)
	}
}

// TestInstrumentedAuthorizer_ErrorPropagatesAndCounts — a backend error is
// returned verbatim and increments the error counter.
func TestInstrumentedAuthorizer_ErrorPropagatesAndCounts(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	sentinel := errors.New("authz unavailable: boom")
	dec := metrics.NewInstrumentedAuthorizer(fakeAuthorizer{err: sentinel}, reg)

	_, err := dec.CheckRelation(context.Background(), service.CheckRelationRequest{
		Subject: "user:usr_x", Relation: "viewer", Object: "vpc_network:vpcn_y",
	})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want sentinel propagated verbatim", err)
	}

	got := dumpMetrics(t, reg)
	const want = `kacho_iam_authz_check_decisions_total{decision="error",rpc="CheckRelation"} 1`
	if !strings.Contains(got, want) {
		t.Fatalf("error counter missing.\nwant: %s\ngot:\n%s", want, got)
	}
}

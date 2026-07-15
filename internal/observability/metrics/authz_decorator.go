// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package metrics

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// relationAuthorizer is the relation-native authz port the InternalIAMService
// gate depends on (matches internal_iam.authorizer). Declared here so the
// metrics decorator can wrap it without the use-case importing prometheus
// (Clean Architecture: instrumentation stays at the adapter boundary). The
// concrete *service.AuthorizeService satisfies it.
type relationAuthorizer interface {
	CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error)
}

// InstrumentedAuthorizer decorates a relationAuthorizer, recording the authz
// Check hot-path histogram + decision counter for every CheckRelation call. It
// is a pass-through: the wrapped result/error are returned verbatim, so the
// decision logic in the use-case is unaffected.
type InstrumentedAuthorizer struct {
	inner relationAuthorizer
	reg   *Registry
}

// NewInstrumentedAuthorizer wraps inner with metrics recording onto reg. Wire it
// in the composition root so the InternalIAMService gate (the documented ≤30ms
// p95 hot path) is observed without the use-case knowing about prometheus.
func NewInstrumentedAuthorizer(inner relationAuthorizer, reg *Registry) *InstrumentedAuthorizer {
	return &InstrumentedAuthorizer{inner: inner, reg: reg}
}

// CheckRelation delegates to the wrapped authorizer and records the outcome.
func (d *InstrumentedAuthorizer) CheckRelation(ctx context.Context, req service.CheckRelationRequest) (*service.CheckResult, error) {
	start := time.Now()
	res, err := d.inner.CheckRelation(ctx, req)
	allowed := err == nil && res != nil && res.Allowed
	d.reg.ObserveAuthz(AuthzObservation{
		RPC:      "CheckRelation",
		Allowed:  allowed,
		Err:      err != nil,
		Duration: time.Since(start).Seconds(),
	})
	return res, err
}

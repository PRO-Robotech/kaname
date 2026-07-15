// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard

// cluster_admin_shortcircuit.go — RBAC explicit-model 2026 P5 (D-9 / КФ-2).
//
// IsClusterAdmin is the FLAT cluster-admin super-gate shared by EVERY authz
// decision site (authorize_service.Check + InternalIAMService.Check + all
// write-authz gates: requireGrantAuthority / fgaHoldsAdmin). It answers ONE
// question with ONE relation Check:
//
//	cluster:cluster_kacho_root # system_admin @ <subject>
//
// This is a plain super-gate ("is the subject cluster-admin?"), NOT a hierarchical
// `<rel> from cluster` cascade — exactly one tuple = one fact = one audit row. The
// derivation cascade (`system_admin from cluster`) is removed in the contract
// phase, so after contraction this short-circuit is the SOLE carrier of
// cluster-admin authority; applying it additively in the expand phase keeps the
// cascade and the short-circuit in lockstep (no access-loss window).
//
// Fail-closed on every degraded mode: nil checker (unwired gate), anonymous /
// empty principal, or a Check transport error → false (never fail-open).

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// IsClusterAdmin reports whether the ctx principal holds the flat cluster
// super-admin relation. fail-closed: nil checker / anonymous / empty id / Check
// error → false.
func IsClusterAdmin(ctx context.Context, checker RelationChecker) bool {
	if checker == nil {
		return false
	}
	subject, ok := PrincipalSubject(ctx) // fail-closed: anon / empty / unknown type → ""
	if !ok {
		return false
	}
	return SubjectIsClusterAdmin(ctx, checker, subject)
}

// SubjectIsClusterAdmin is the subject-string variant of IsClusterAdmin — used by
// authorize_service.Check, whose request already carries a pre-formatted FGA
// subject ("user:usr_xxx" / "service_account:sva_xxx") rather than a ctx
// principal. fail-closed: nil checker / empty subject / Check error → false.
func SubjectIsClusterAdmin(ctx context.Context, checker RelationChecker, subject string) bool {
	if checker == nil || subject == "" {
		return false
	}
	allowed, err := checker.Check(ctx, subject, "system_admin", "cluster:"+domain.ClusterSingletonID)
	return err == nil && allowed
}

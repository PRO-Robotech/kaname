// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster

// admin_authz.go — defense-in-depth in-iam authZ gate for the highest-blast
// cluster-admin RPCs (GrantAdmin / RevokeAdmin), per the authN+authZ-everywhere invariant.
//
// Background. The cluster-internal listener (:9091) already runs a per-RPC
// CALLER policy (authzguard.CallerPolicy): GrantAdmin / RevokeAdmin are
// gateway-only — only the api-gateway SA may call them. That gate proves WHO
// dialed :9091, NOT that the forwarded END USER is a cluster admin. Relying on
// it alone means any caller the gateway lets through could mint a cluster-admin
// grant. Per the invariant, EVERY RPC (internal included) must run its own
// per-RPC ReBAC Check.
//
// This gate is ADDITIVE (defense-in-depth) — it does not replace the gateway
// caller-policy. It requires:
//   1. a non-empty AUTHENTICATED principal in ctx (anonymous → deny; NOT
//      coerced to 'bootstrap' — the legitimate bootstrap startup grant runs via
//      seed.RunBootstrapAdmin with its own DB-direct path, never through this
//      use-case), AND
//   2. that principal holds `system_admin` on `cluster:<singleton>` in ReBAC.
//
// Fail-closed everywhere: nil checker, checker error, or not-allowed → deny.
// acr step-up (`required_acr_min`) is enforced separately by the
// internal acr-floor (authzguard.ACRFloor) chained on the :9091 listener BEFORE
// this handler: a gateway-fronted RPC whose catalog acr_min>0 (GrantAdmin /
// RevokeAdmin carry acr_min=2) is rejected with a step-up signal when the
// trusted forwarded acr (corelib grpcsrv x-kacho-token-acr) is insufficient.
// This in-handler gate stays the per-user ReBAC Check; acr is no longer a gap.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// adminChecker — narrow ReBAC port (Check(subject, relation, object)) satisfied
// by clients.RelationStore directly (Interface Segregation). Aliased to the
// package-level authzguard.RelationChecker so the same fake works across gates.
type adminChecker = authzguard.RelationChecker

// requireClusterSystemAdmin enforces the defense-in-depth gate. Returns
// PermissionDenied (verbatim, non-leaking) on every failure mode.
func requireClusterSystemAdmin(ctx context.Context, checker adminChecker) error {
	// 1. authenticated principal required (anonymous / empty ctx → deny).
	principal := authzguard.PrincipalUserID(ctx)
	if principal == "" || authzguard.IsAnonymous(ctx) {
		return authzguard.PermissionDenied()
	}
	// 2. nil checker → fail closed (never silently allow an unwired gate).
	if checker == nil {
		return authzguard.PermissionDenied()
	}
	allowed, err := checker.Check(ctx,
		"user:"+principal,
		"system_admin",
		"cluster:"+domain.ClusterSingletonID,
	)
	if err != nil || !allowed {
		// Backend error OR explicit deny → fail-closed PermissionDenied. (Unlike
		// the fga-proxy gate, which surfaces backend outages as Unavailable for a
		// retryable owner-tuple drainer, this is an interactive admin mutation:
		// fail-closed deny is the safe default — no false-allow.)
		return authzguard.PermissionDenied()
	}
	return nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// Fail-closed everywhere — the mutation never runs unless the model said yes.
// The ANSWER, however, distinguishes what happened: an unnameable principal, an
// unwired checker or an explicit deny is PermissionDenied; a checker that could
// not be reached is Unavailable, because nothing was decided and the same
// question a moment later gets an answer.
// acr step-up (`required_acr_min`) is enforced separately by the
// internal acr-floor (authzguard.ACRFloor) chained on the :9091 listener BEFORE
// this handler: a gateway-fronted RPC whose catalog acr_min>0 (GrantAdmin /
// RevokeAdmin carry acr_min=2) is rejected with a step-up signal when the
// trusted forwarded acr (corelib grpcsrv x-kacho-token-acr) is insufficient.
// This in-handler gate stays the per-user ReBAC Check; acr is no longer a gap.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// adminChecker — narrow ReBAC port (Check(subject, relation, object)) satisfied
// by clients.RelationStore directly (Interface Segregation). Aliased to the
// package-level authzguard.RelationChecker so the same fake works across gates.
type adminChecker = authzguard.RelationChecker

// requireClusterSystemAdmin enforces the defense-in-depth gate. Every failure
// mode is non-leaking and verbatim: PermissionDenied when the model decided (or
// there was no nameable principal / no wired checker), Unavailable when it could
// not be asked.
func requireClusterSystemAdmin(ctx context.Context, checker adminChecker) error {
	// 1. authenticated principal required, and it must be NAMEABLE (anonymous /
	//    empty ctx / unknown principal type / an id carrying an FGA separator →
	//    deny).
	//
	//    The subject was previously spelled as "user:" joined to the principal id.
	//    That is a string, not a policy: a machine granted cluster administration
	//    holds `service_account:<id>`, so asking about `user:<id>` named nobody and
	//    the grant could be issued and never used. PrincipalSubject resolves the
	//    principal to its own type, and fails closed on anything it cannot name.
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return authzguard.PermissionDenied()
	}
	// 2. nil checker → fail closed (never silently allow an unwired gate).
	if checker == nil {
		return authzguard.PermissionDenied()
	}
	allowed, err := checker.Check(ctx,
		subject,
		"system_admin",
		"cluster:"+domain.ClusterSingletonID,
	)
	if err != nil {
		// Backend outage — NOT an authorization decision. Fail-closed either way
		// (the mutation does not run), but the caller is told "I could not ask",
		// not "you may not": the latter means an identical retry is pointless, and
		// a cluster admin locked out by a two-second FGA flap would read it as a
		// revoked grant. Same answer the sibling gates in this service already give
		// (RelationWriteGate, SystemViewerFloor, scope).
		//
		// The previous edition collapsed this into the refusal below and justified
		// it as "fail-closed deny is the safe default — no false-allow". That
		// justification does not distinguish the two: Unavailable is equally
		// fail-closed and equally free of false-allows. What it did distinguish was
		// how long the outage lasts in the caller's eyes — forever.
		return authzguard.AuthzBackendUnavailable()
	}
	if !allowed {
		// Explicit deny: the Check succeeded and answered no.
		return authzguard.PermissionDenied()
	}
	return nil
}

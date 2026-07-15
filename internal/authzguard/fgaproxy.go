// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fgaproxy.go — the FGA-proxy authz gate.
//
// RegisterResource / UnregisterResource carry `permission = "<exempt>"` in the
// proto catalog (like every Internal IAM RPC), so least-privilege is NOT
// expressed as a flat permission-string. It is enforced HERE as ReBAC:
//
//  1. The mTLS client-cert SAN (SPIRE format
//     spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>, extracted by SEC-B's
//     grpcsrv.CertIdentityFromContext) is mapped to a deterministic
//     ServiceAccount id (`'sva' || substr(md5('kacho-<svc>'),1,17)`).
//  2. A ReBAC Check `service_account:<sva>#fga_writer@iam_fgaproxy:system` is
//     issued. ALLOW → the RPC proceeds; DENY → PermissionDenied.
//
// Fail-closed: an unverified peer, a malformed / foreign-trust-domain SAN, an
// unknown SA, or a denied relation all collapse to PermissionDenied. The
// service→service (mTLS-SA) path never consults `required_acr_min` — ACR-floor
// is a user-token concern only; the gate decides purely on the
// ReBAC relation.
package authzguard

import (
	"context"
	"crypto/md5" // #nosec G501 -- deterministic id derivation (must match Postgres md5() in migration 0009), not a security primitive
	"encoding/hex"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

const (
	// fgaProxyRelation — ReBAC relation a module SA must hold to use the proxy.
	fgaProxyRelation = "fga_writer"
	// fgaProxyObject — the system object the relation is checked against.
	fgaProxyObject = "iam_fgaproxy:system"

	// sanTrustPrefix — the only accepted SPIFFE trust domain (SEC-B extractor
	// already filters foreign domains; this is a defensive re-check).
	sanTrustPrefix = "spiffe://kacho.cloud/ns/"
	// sanSAInfix — the path segment that precedes the service-account name.
	sanSAInfix = "/sa/"
	// svcNamePrefix — module SAN service segment is always `kacho-<svc>`.
	svcNamePrefix = "kacho-"
)

// RelationWriteGate authorizes RegisterResource / UnregisterResource via ReBAC.
// It reuses the package RelationChecker port (scope.go) — the same FGA
// `Check(subject, relation, object)` surface used by the scope guard, satisfied
// directly by clients.RelationStore (no extra adapter at the composition root).
type RelationWriteGate struct {
	checker RelationChecker
	// prodMode = production AuthN mode. In dev-mode (false) an insecure peer
	// with no verified client-cert is allowed (backward-compat);
	// in production-mode (true) the gate is strictly fail-closed.
	prodMode bool
}

// NewRelationWriteGate — constructor. Defaults to dev-mode (backward-compat); use
// WithProductionMode to enable strict fail-closed enforcement.
func NewRelationWriteGate(checker RelationChecker) *RelationWriteGate {
	return &RelationWriteGate{checker: checker}
}

// WithProductionMode toggles strict fail-closed enforcement (production AuthN).
func (g *RelationWriteGate) WithProductionMode(prod bool) *RelationWriteGate {
	g.prodMode = prod
	return g
}

// Authorize returns nil iff the verified mTLS client-cert resolves to a module
// ServiceAccount holding `fga_writer` on `iam_fgaproxy:system`. Every other
// outcome is PermissionDenied (fail-closed). Message text is the fixed,
// non-leaking `"permission denied"`.
// Authorize проверяет, что caller — модульная SA с `fga_writer@iam_fgaproxy:system`,
// и возвращает ее домен (vpc/compute/nlb) для object-type binding на write-path.
// Dev-mode без cert → ("", nil): домен неизвестен, domain-binding в ValidateProxyTuple
// отключается, но relation-allowlist и forbidden-object-type там действуют всегда.
func (g *RelationWriteGate) Authorize(ctx context.Context) (string, error) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		if !g.prodMode {
			// Dev-mode backward-compat: insecure listener, no mTLS cert,
			// anonymous → allow. Production-mode is strictly fail-closed.
			return "", nil
		}
		// Production-mode: unverified peer or no module identity → never trusted.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	domain, ok := SANToServiceDomain(san)
	if !ok {
		// Malformed / foreign-trust-domain SAN → not a module identity.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	if g.checker == nil {
		// ReBAC backend not wired → fail-closed (never silently allow).
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	allowed, err := g.checker.Check(ctx, "service_account:"+ServiceAccountIDForService(domain), fgaProxyRelation, fgaProxyObject)
	if err != nil {
		// Backend failure (FGA 5xx / network drop / ErrNotConfigured) is NOT an
		// authorization decision — it is a transient outage. Surfacing it as
		// Unavailable (retryable, fail-closed) lets the caller retry; collapsing
		// it to PermissionDenied would make the drainer poison a legitimate
		// owner-tuple intent. The raw backend error is logged-not-leaked.
		return "", status.Error(codes.Unavailable, "authz backend unavailable")
	}
	if !allowed {
		// Explicit deny: Check succeeded and returned allowed==false (the SA holds
		// no fga_writer relation). Genuine authorization decision → fail-closed.
		return "", status.Error(codes.PermissionDenied, "permission denied")
	}
	return domain, nil
}

// SANToServiceDomain maps a verified SPIRE SAN to the module service short-name
// (the domain: `vpc`/`compute`/`nlb`). Accepts only
// `spiffe://kacho.cloud/ns/<ns>/sa/kacho-<svc>` with a non-empty <svc>; any other
// shape returns ("", false). The domain drives object-type binding in
// ValidateProxyTuple (a vpc module may only register `vpc_*` objects).
func SANToServiceDomain(san string) (string, bool) {
	if !strings.HasPrefix(san, sanTrustPrefix) {
		return "", false
	}
	idx := strings.LastIndex(san, sanSAInfix)
	if idx < 0 {
		return "", false
	}
	saName := san[idx+len(sanSAInfix):]
	if !strings.HasPrefix(saName, svcNamePrefix) {
		return "", false
	}
	svc := strings.TrimPrefix(saName, svcNamePrefix)
	if svc == "" {
		return "", false
	}
	// The <ns> segment must be non-empty (rejects ns//sa/…).
	ns := san[len(sanTrustPrefix):idx]
	if ns == "" || strings.HasPrefix(ns, "/") {
		return "", false
	}
	return svc, true
}

// SANToServiceAccountID maps a verified SPIRE SAN to the deterministic module
// ServiceAccount id.
func SANToServiceAccountID(san string) (string, bool) {
	svc, ok := SANToServiceDomain(san)
	if !ok {
		return "", false
	}
	return ServiceAccountIDForService(svc), true
}

// ServiceAccountIDForService derives the deterministic module SA id from a
// service short-name (`'sva' || substr(md5('kacho-<svc>'),1,17)`). Single
// source of truth shared by the gate and the seed migration helper.
func ServiceAccountIDForService(svc string) string {
	sum := md5.Sum([]byte(svcNamePrefix + svc)) // #nosec G401 -- deterministic id (must match Postgres md5()), not a security primitive
	return "sva" + hex.EncodeToString(sum[:])[:17]
}

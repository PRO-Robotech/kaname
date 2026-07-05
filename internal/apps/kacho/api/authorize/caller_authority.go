// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// caller_authority.go — inner defense-in-depth authority gate for
// AuthorizeService.{Check,BatchCheck,ListObjects,ListSubjects,ExpandRelations}.
//
// The api-gateway is the OUTER gate: it enforces that a tenant caller may only
// query authz decisions about itself or about subjects/resources it holds the
// `iam.subjects.checkAuthorization` authority on. This file adds the INNER
// gate the rest of the codebase already applies to read paths (read_authz.go /
// account.List re-Check the FGA relation even though the gateway did), so a
// gateway bug or a confused-deputy caller cannot enumerate the cluster
// authorization graph for an arbitrary subject (CWE-863 / CWE-862).
//
// Scope of the gate — only TENANT-facing principals (user / service_account)
// are gated. Anonymous / system principals are the cluster-internal
// verified-mTLS module PDP peer calls (kacho-vpc / kacho-compute / kacho-nlb
// on :9091): their authz contract is "a verified module MAY query authz
// decisions" (NOT "the module has access to the objects"), gated by the
// internal listener's CallerPolicy verified-cert floor — see
// cmd/kacho-iam/grpc_register.go. Gating them here would break every peer PDP
// query, so they pass through and the outer cert floor governs them.

package authorize

import (
	"context"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho-proto/gen/go/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
)

// callerAuthorityRelations — FGA relations on the queried resource that grant a
// tenant caller the authority to ask authz questions about OTHER subjects on
// that resource (delegated administration). `admin` is the canonical resource
// authority; `checkAuthorization` mirrors the gateway's documented relation
// (an unknown relation simply Check-errors and is skipped — never fail-open).
var callerAuthorityRelations = []string{"admin", "checkAuthorization"}

// authorizeCaller is the inner defense-in-depth gate. It returns nil (allow) when:
//
//   - the ctx principal is anonymous / system (module PDP peer call — outer
//     cert floor governs); OR
//   - the ctx principal (a user / service_account) IS the queried `subject`
//     (self-query); OR
//   - the ctx principal is a cluster-admin (flat super-gate); OR
//   - the ctx principal holds a resource-authority relation on `res`.
//
// Otherwise it returns PermissionDenied with a fixed, redacted message. `subject`
// may be "" (ListSubjects / ExpandRelations carry no subject arg — then only the
// cluster-admin / resource-authority arms apply). `res` may be nil (ListObjects
// has no single resource — then only self-query / cluster-admin apply).
//
// Fail-closed on every degraded mode (nil checker, Check transport error): a
// tenant principal that cannot prove authority is denied, never allowed.
func (h *Handler) authorizeCaller(ctx context.Context, subject string, res *iamv1.ResourceRef) error {
	callerSubject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		// Anonymous / system / unknown-type principal → cluster-internal module
		// PDP path (or an unauthenticated read on a suffix-whitelisted RPC). The
		// verified-cert floor on the internal listener is the governing gate.
		return nil
	}
	// Self-query: a tenant may always ask authz questions about itself.
	if subject != "" && callerSubject == subject {
		return nil
	}
	// Cluster-admin flat super-gate (fail-closed: nil checker / Check error → false).
	if authzguard.SubjectIsClusterAdmin(ctx, h.authority, callerSubject) {
		return nil
	}
	// Delegated authority on the specific queried resource.
	if h.authority != nil && res != nil {
		rType, rID := strings.ToLower(res.GetType()), res.GetId()
		if rType != "" && rID != "" && rID != "*" {
			object := rType + ":" + rID
			for _, rel := range callerAuthorityRelations {
				if allowed, err := h.authority.Check(ctx, callerSubject, rel, object); err == nil && allowed {
					return nil
				}
			}
		}
	}
	return status.Error(codes.PermissionDenied, "permission denied")
}

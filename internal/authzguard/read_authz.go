// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// read_authz.go — verb-bearing read-authorization guard for the IAM read
// use-cases (Account/Project/User/Group/ServiceAccount .Get).
//
// Background: the legacy read gate was owner-only identity-equality
// (`IsSelf(resource.OwnerUserID)`). On the flat explicit model (Design B) that
// is wrong — it denies a caller who was explicitly granted `iam.<res>.get` (a
// per-object `v_get` tuple), and it denies a cluster-admin (no per-object tuple
// after the access-cascade is contracted), producing the live "granted invitee
// → GET 404" bug. The gateway already Check's `v_get` BEFORE iam, but the iam
// use-case re-ran its own owner-only gate and overrode the ALLOW.
//
// AllowsVGet replaces the owner-only gate with a relation Check on the SAME
// verb-bearing relation the gateway enforces, plus the flat cluster-admin
// super-gate (D-9). It is defense-in-depth on top of the gateway Check, NOT a
// conflicting second gate: a caller who passes the gateway (`v_get` granted, or
// cluster-admin) passes here too; a caller who would be denied at the gateway is
// denied here as well. The caller maps a `false` to NotFound (hide existence,
// never PermissionDenied — no enumeration / existence leak).
//
// Fail-closed on every degraded mode: anonymous / empty principal, a nil FGA
// port (unit tests / unwired) → (false, nil). The resource body is returned by
// the caller ONLY on (true, nil).
//
// A Check that could NOT BE ASKED (transport error) is reported as an error, not
// as a denial. "The store said no" and "the store did not answer" are different
// facts and must not share one return value: a denial is hidden behind NotFound
// (existence-hiding), so folding an outage into it makes every iam read a
// terminal 404 for the whole cluster — the owner included — for as long as the
// store is down, and a 404 is a claim the client acts on (cache eviction,
// cleanup, "it is gone, recreate it"). The neighbouring page-filter
// (internal/authzfilter) draws the same line explicitly; this gate now matches
// it. Callers map the error to UNAVAILABLE.

import "context"

// AllowsVGet reports whether the ctx principal may read the object
// `<fgaType>:<id>`: it is a cluster-admin (flat super-gate, D-9) OR it holds the
// `v_get` relation on the object (owner-binding materializes it for the owner; an
// explicit `iam.<res>.get` grant materializes it for a delegate).
//
// (false, nil) is a decision (hide existence); (false, err) means the decision
// could not be made (map to UNAVAILABLE, never to NotFound).
//
// fgaType is the rights-model object_type (e.g. "account", "project", "iam_user");
// id is the bare resource id (no type prefix). The object string is composed as
// `<fgaType>:<id>` — the SAME object the reconciler materializes and the gateway
// Check's against.
func AllowsVGet(ctx context.Context, checker RelationChecker, fgaType, id string) (bool, error) {
	return AllowsVerb(ctx, checker, "v_get", fgaType, id)
}

// AllowsVerb is the generic verb-bearing read-authorization gate: cluster-admin
// super-gate OR the ctx principal holds `relation` on `<fgaType>:<id>`. AllowsVGet
// is the get-specialization (relation == "v_get"). Kept generic so a future read
// path (e.g. a v_list object-existence probe) reuses the same fail-closed posture.
//
// An allow is returned as soon as ONE question answers yes, even if the other
// failed — an allow needs no second opinion. A non-allow is only reported as a
// decision when EVERY question this gate asked was actually answered; otherwise
// the error of the unanswered one is returned.
func AllowsVerb(ctx context.Context, checker RelationChecker, relation, fgaType, id string) (bool, error) {
	if checker == nil {
		return false, nil
	}
	subject, ok := PrincipalSubject(ctx) // fail-closed: anon / empty / unknown type → ""
	if !ok {
		return false, nil
	}
	// Cluster-admin short-circuit (D-9): a cluster-admin reads ANY object even
	// without a per-object tuple.
	admin, adminErr := SubjectIsClusterAdminPlainE(ctx, checker, subject)
	if admin {
		return true, nil
	}
	allowed, err := checker.Check(ctx, subject, relation, fgaType+":"+id)
	if err != nil {
		return false, err
	}
	if allowed {
		return true, nil
	}
	// The verb question answered "no". If the super-gate probe never answered,
	// this is not a complete denial — report the outage.
	if adminErr != nil {
		return false, adminErr
	}
	return false, nil
}

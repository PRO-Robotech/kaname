// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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
// port (unit tests / unwired), or a Check transport error → false (never
// fail-open). The resource body is returned by the caller ONLY when this returns
// true.

import "context"

// AllowsVGet reports whether the ctx principal may read the object
// `<fgaType>:<id>`: it is a cluster-admin (flat super-gate, D-9) OR it holds the
// `v_get` relation on the object (owner-binding materializes it for the owner; an
// explicit `iam.<res>.get` grant materializes it for a delegate). Fail-closed:
// anonymous / empty subject / nil checker / Check error → false.
//
// fgaType is the OpenFGA object_type (e.g. "account", "project", "iam_user");
// id is the bare resource id (no type prefix). The object string is composed as
// `<fgaType>:<id>` — the SAME object the reconciler materializes and the gateway
// Check's against.
func AllowsVGet(ctx context.Context, checker RelationChecker, fgaType, id string) bool {
	return AllowsVerb(ctx, checker, "v_get", fgaType, id)
}

// AllowsVerb is the generic verb-bearing read-authorization gate: cluster-admin
// super-gate OR the ctx principal holds `relation` on `<fgaType>:<id>`. AllowsVGet
// is the get-specialization (relation == "v_get"). Kept generic so a future read
// path (e.g. a v_list object-existence probe) reuses the same fail-closed posture.
func AllowsVerb(ctx context.Context, checker RelationChecker, relation, fgaType, id string) bool {
	if checker == nil {
		return false
	}
	subject, ok := PrincipalSubject(ctx) // fail-closed: anon / empty / unknown type → ""
	if !ok {
		return false
	}
	// Cluster-admin short-circuit (D-9): a cluster-admin reads ANY object even
	// without a per-object tuple. SubjectIsClusterAdmin is itself fail-closed.
	if SubjectIsClusterAdmin(ctx, checker, subject) {
		return true
	}
	allowed, err := checker.Check(ctx, subject, relation, fgaType+":"+id)
	return err == nil && allowed
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package relationhook — shared OpenFGA hierarchy-tuple write helper for IAM
// resource Create use-cases.
//
// When an IAM resource (Group / ServiceAccount / Role / AccessBinding) is
// created, the api-gateway per-RPC authz middleware resolves the request
// scope to a per-resource FGA object (`iam_group:<id>` / `iam_role:<id>` /
// ...) via the permission-catalog `scope_extractor`. For the FGA cascade
// `<rel> from account` (resp. `from project`) to resolve, the parent-pointer
// tuple must exist:
//
//	iam_group:<id>           #account  @account:<account_id>
//	iam_service_account:<id> #account  @account:<account_id>
//	iam_role:<id>            #account  @account:<account_id>
//	iam_access_binding:<id>  #project  @project:<project_id>
//
// Without this tuple the middleware can never authorise a per-resource
// Get/Update/Delete — the cascade has no path to the account/project where
// the principal's role binding lives. This helper writes that tuple.
//
// The write is best-effort and non-fatal: the resource row is already
// committed when this runs; a tuple-write failure is logged for the operator
// and surfaced through metrics, never rolled back (parity with the
// project→account and account-owner hierarchy writers).
package relationhook

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// WriteHierarchyTuple writes a single parent-pointer tuple
// `<childType>:<childID>#<relation>@<parentType>:<parentID>`.
//
// Parameters mirror the FGA tuple shape used by the existing
// project→account writer (clients.RelationTuple{User, Relation, Object}):
//
//	parentType / parentID — the FGA object the child cascades FROM
//	                        (e.g. "account" / "acc_xxx").
//	relation              — the child's parent-pointer relation name
//	                        (e.g. "account" / "project").
//	childType / childID   — the freshly-created resource FGA object
//	                        (e.g. "iam_group" / "grp_xxx").
//
// relations == nil is a defensive no-op. In production the composition root fails
// fast without OpenFGA, so the client is always wired (see cmd/kacho-iam);
// the guard keeps the helper safe for unit tests that pass a nil writer.
func WriteHierarchyTuple(
	ctx context.Context,
	relations clients.RelationStore,
	logger *slog.Logger,
	parentType, parentID, relation, childType, childID string,
) {
	if relations == nil {
		return
	}
	if parentID == "" || childID == "" {
		// Defensive: never emit a tuple with an empty id — it would create a
		// dangling `<type>:` object in the store.
		if logger != nil {
			logger.Warn("openfga hierarchy-tuple skipped: empty id",
				"parent_type", parentType, "parent_id", parentID,
				"child_type", childType, "child_id", childID)
		}
		return
	}
	tup := clients.RelationTuple{
		User:     fmt.Sprintf("%s:%s", parentType, parentID),
		Relation: relation,
		Object:   fmt.Sprintf("%s:%s", childType, childID),
	}
	if err := relations.WriteTuples(ctx, []clients.RelationTuple{tup}); err != nil {
		if logger != nil {
			logger.Warn("openfga hierarchy-tuple write failed",
				"err", err, "object", tup.Object, "relation", tup.Relation, "user", tup.User)
		}
		return
	}
	if logger != nil {
		logger.Info("openfga hierarchy-tuple written",
			"object", tup.Object, "relation", tup.Relation, "user", tup.User)
	}
}

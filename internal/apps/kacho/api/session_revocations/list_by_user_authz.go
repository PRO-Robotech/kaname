// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package session_revocations

// list_by_user_authz.go — who may read the session history of the user named in
// a ListByUser request.
//
// The response is entirely about ONE user the CALLER NAMED: which of their
// sessions were torn down, when, and why. So there is a single object the
// question can be asked about — `iam_user:<user_id>` — and the shape is the
// per-object one, not the page-filtered one that resources with individual
// owners need.
//
// The relation is the READ TIER on that user (`viewer`), not a `v_*` verb: `v_*`
// is object-level access to the USER RECORD ITSELF, whereas a session history is
// that user's CONTENTS — the distinction the platform already draws between a
// project's own `v_list` and the listing of what is inside it. `iam_user.viewer`
// admits the user themselves structurally (`subject`) and anyone holding
// editor/admin over them, and no wildcard tuple satisfies it, so it narrows for
// real. It is the SAME relation the catalog record for this RPC declares —
// the record and the code must not be able to drift into describing different
// lanes.
//
// The listener in front of this RPC does not answer it. Its two gates narrow the
// CALLING MODULE — a verified mTLS certificate, and `system_viewer@cluster` held
// by that module's own service account — and SystemViewerFloor says so in its own
// doc: the subject of its Check is the caller module, never the forwarded end
// user. Neither reads `user_id`. That is the whole gap this file closes.
//
// Order of refusals, and why each is where it is:
//
//  1. an unnamed caller is refused UNCONDITIONALLY, before anything else and
//     whether or not the relation port is wired. Behind this RPC there is no
//     per-RPC Check to fall back on, so making the cut conditional on the port
//     would hand every user's history to everyone the day the port is absent;
//  2. self is served without asking the model. A user reading their own logout
//     history is an identity fact, and it must not depend on a materialisation
//     having caught up;
//  3. a wired model with no answer for the caller is a DENIAL, reported as the
//     owner's own miss, verbatim, so the refusal cannot be told apart from the
//     user simply not existing;
//  4. a model that could not be ASKED is neither a denial nor an allow. It is an
//     outage, and it is reported as one — folding it into the 404 would make an
//     unreachable store read as "this user does not exist", which is a claim the
//     caller acts on;
//  5. no model wired at all is a fact about the DEPLOYMENT, not an answer from
//     the model, and it is refused under its own name. Reported as a denial like
//     (3) it would read as a correct empty model, and the next person to "fix"
//     that reads the gate as the thing in the way.

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// listByUserRelation — the read tier on `iam_user`. Kept next to the decision so
// the one place that asks and the catalog record that declares it stay legible as
// one statement.
const listByUserRelation = "viewer"

// errModelNotConfigured — the refusal for a deployment that wired no rights
// model. It names the missing piece because the only reader of this text is an
// operator whose stand will not serve the RPC until they wire it.
var errModelNotConfigured = iamerr.Wrapf(iamerr.ErrPermissionDenied,
	"list session revocations: the rights model is not configured for this deployment")

// authorizeListByUser decides whether the ctx principal may read the session
// history of `userID`.
//
// A nil error means "serve it". Every other outcome is already the gRPC status
// the caller returns unchanged — the denial deliberately carries the byte for
// byte text of the owning service's own miss (`UserService.Get`), so a caller who
// is refused learns nothing about whether the user exists.
func authorizeListByUser(ctx context.Context, relations authzguard.RelationChecker, userID string) error {
	// (1) Nobody named — refuse, regardless of what is or is not wired.
	if authzguard.IsAnonymous(ctx) {
		return userNotFound(userID)
	}
	// (2) Self reads self.
	if authzguard.IsSelf(ctx, userID) {
		return nil
	}
	// (5) No model to ask. Checked before the call so an unconfigured deployment
	// is distinguishable from one whose model answered "no".
	if relations == nil {
		return shared.MapRepoErr(errModelNotConfigured)
	}
	// (3)/(4) The model decides: the read tier on the user, or cluster-admin.
	allowed, err := authzguard.AllowsVerb(ctx, relations, listByUserRelation, "iam_user", userID)
	if err != nil {
		return shared.MapRepoErr(iamerr.ErrUnavailable)
	}
	if !allowed {
		return userNotFound(userID)
	}
	return nil
}

// userNotFound is the denial, in the owning read's exact words.
func userNotFound(userID string) error {
	return shared.MapRepoErr(iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", userID))
}

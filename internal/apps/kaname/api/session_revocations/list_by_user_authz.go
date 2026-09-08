// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// The relation is `session_reader` — the person themselves plus cloud oversight,
// and nobody else (#1140). It is the SAME relation the catalog record for this
// RPC declares; the record and the code must not be able to drift into
// describing different lanes.
//
// It used to be the READ TIER `viewer`, and that was too wide by five: the model
// compiler expands `iam_user.viewer` into SEVEN sources (the person, the three
// directly-assignable tiers viewer/editor/admin, the delegated account steward,
// the account owner, cloud oversight) against `session_reader`'s two. A session
// history is information ABOUT A PERSON, not a right over an account — identity
// is global in this tree, one `iam_user` row across all of a person's accounts,
// with the identity→account link taken from membership, so a right held inside
// ONE account disclosed the person's whole history, sessions in unrelated
// accounts included. Fourth side of the owner's directive of 2026-08-23 that
// #1086, #1102 and #1133 closed on their own subjects.
//
// Narrowing the READ takes nothing away from TERMINATION, and that is measured
// rather than assumed: `Revoke` and `ForceLogout` sit in the catalog as
// `<exempt>`/`INTERNAL_LISTENER` with no relation on the identity row at all,
// so they were never gated by this one. A rights-holder inside the account did
// not lose the ability to end someone's session — they never had it.
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

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// listByUserRelation — the narrow read relation on `iam_user`. Kept next to the
// decision so the one place that asks and the catalog record that declares it
// stay legible as one statement; that the two agree is asserted by
// `authzmap/reading_a_persons_session_history_test.go`, which reads the relation
// out of the catalog rather than out of this literal.
const listByUserRelation = "session_reader"

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

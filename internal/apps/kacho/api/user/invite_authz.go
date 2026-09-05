// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// invite_authz.go — invite-flow grant-authority cascade. The cascade decision
// belongs to the InviteUserUseCase, so it lives here (the use-case package),
// not in internal/clients (which is limited to raw transport Check /
// RelationStore). Depends only on the narrow AuthzChecker port (ISP).
//
// Cascade `admin > editor > viewer → member` is evaluated client-side in Go
// (the ReBAC backend holds DIRECT tuples; cascade-traversal lives in code).

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
)

// AuthzChecker — narrow port for cascade-traversal Check (same signature as
// clients.RelationStore.Check). InviteUserUseCase depends on this narrow iface,
// not the full RelationStore (Interface Segregation).
type AuthzChecker interface {
	Check(ctx context.Context, subject, relation, object string) (allowed bool, err error)
}

// relationsImplying — relations implication-stronger than the given one (if the
// user holds any of them, the given relation is guaranteed).
//
// Cascade:
//   - admin  ⊋ editor ⊋ viewer ⊋ member
//   - owner  ⊋ admin
//
// Evaluated client-side; the FGA model stays flat (no union/computed_subjectset).
func relationsImplying(rel string) []string {
	switch rel {
	case "viewer":
		return []string{"viewer", "editor", "admin", "owner"}
	case "editor":
		return []string{"editor", "admin", "owner"}
	case "admin":
		return []string{"admin", "owner"}
	case "owner":
		return []string{"owner"}
	case "member":
		return []string{"member", "viewer", "editor", "admin", "owner"}
	default:
		return []string{rel}
	}
}

// cascadeCheck — sequential Check over relationsImplying(rel). Returns
// (true, nil) on the first allowed; (false, nil) if none matched; an error is
// propagated as-is.
func cascadeCheck(ctx context.Context, c AuthzChecker, subject, rel, object string) (bool, error) {
	for _, r := range relationsImplying(rel) {
		allowed, err := c.Check(ctx, subject, r, object)
		if err != nil {
			return false, err
		}
		if allowed {
			return true, nil
		}
	}
	return false, nil
}

// canInviteUsers — one Check(editor) via cascade-traversal
// covers {editor, admin, owner}. A viewer cannot invite (no cascade above
// editor). Returns (true, nil) if the CALLER holds editor/admin/owner on the
// target Account.
//
// The subject is named by `authzguard.SubjectFromPrincipal` — the single source of
// truth for spelling a principal as an FGA subject — and NOT by joining "user:" to
// the id. The difference is not cosmetic:
//
//   - Spelled "user:"+id, a SERVICE ACCOUNT was asked about under a subject that
//     cannot exist. The store answered a well-formed "no", so the account's own
//     administrator was refused whenever the caller was non-interactive — which on a
//     production-posture stand is every caller, since tokens there are issued to
//     service accounts. `security.md` is explicit that a service account is a
//     first-class principal, not an exception.
//   - The same spelling ADMITTED an unknown principal type, because it produced a
//     "user:" subject for it regardless. That is the latent over-grant
//     SubjectFromPrincipal documents in its own comment; here it is closed by
//     construction, since an unnameable principal never reaches the store.
//
// `ok == false` is a refusal, not an error: a caller we cannot name is a caller we
// cannot authorize, and asking about a subject we invented would decide access on
// somebody else's grants.
func canInviteUsers(ctx context.Context, c AuthzChecker, accountID string) (bool, error) {
	subject, ok := authzguard.PrincipalSubject(ctx)
	if !ok {
		return false, nil
	}
	object := "account:" + accountID
	return cascadeCheck(ctx, c, subject, "editor", object)
}

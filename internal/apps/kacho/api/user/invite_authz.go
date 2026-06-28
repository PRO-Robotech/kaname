// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// invite_authz.go — invite-flow grant-authority cascade. The cascade decision
// belongs to the InviteUserUseCase, so it lives here (the use-case package),
// not in internal/clients (which is limited to raw transport Check /
// RelationStore). Depends only on the narrow AuthzChecker port (ISP).
//
// Cascade `admin > editor > viewer → member` is evaluated client-side in Go
// (the ReBAC backend holds DIRECT tuples; cascade-traversal lives in code).

import "context"

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
// editor). Returns (true, nil) if principal holds editor/admin/owner on the
// target Account.
func canInviteUsers(ctx context.Context, c AuthzChecker, principalID, accountID string) (bool, error) {
	subject := "user:" + principalID
	object := "account:" + accountID
	return cascadeCheck(ctx, c, subject, "editor", object)
}

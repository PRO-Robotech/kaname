// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_subject_privileges.go — ListSubjectPrivilegesUseCase for
// RPC AccessBindingService.ListSubjectPrivileges.
//
// Sync, enriched read of a subject's DIRECT privileges with server-resolved
// role names (JOIN in the repo). Authz is BROADER than ListBySubject:
// "self OR account-admin of the subject's home Account" — mirrors the
// established requireGrantAuthority pattern but the scope object is the
// SUBJECT's home Account (account:<subject.account_id>), not a binding's scope.
//
// Order of sync steps (api-conventions):
//  1. subject_type whitelist  → InvalidArgument (user | service_account | group;
//     group resolution is DIRECT-derived bindings whose
//     subject_type=group, no via-group/transitive resolution).
//  2. prefix↔type validation  → InvalidArgument FIRST statement (before repo).
//  3. anti-anonymous guard    → PermissionDenied (catalog is cluster-floor;
//     the precise self/account-admin policy is authoritative here).
//  4. subject existence resolve (Users().Get / ServiceAccounts().Get) →
//     NotFound for a well-formed-but-nonexistent subject; also yields the
//     home account_id needed for the authz check.
//  5. authz: IsSelf OR account-admin (owner of home Account OR FGA admin) →
//     PermissionDenied on cross-account.
//  6. repo JOIN read (access_bindings ⋈ roles), keyset paginated.

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListSubjectPrivilegesUseCase struct {
	repo      Repo
	relations clients.RelationStore
	logger    *slog.Logger
}

func NewListSubjectPrivilegesUseCase(r Repo) *ListSubjectPrivilegesUseCase {
	return &ListSubjectPrivilegesUseCase{repo: r}
}

// WithRelationStore wires the FGA client so the account-admin authz path
// (FGA `admin` on the subject's home Account) can resolve delegated
// admins who are not the account owner. When unset (nil) the use-case falls
// back to owner-only authority and denies delegated admins.
func (u *ListSubjectPrivilegesUseCase) WithRelationStore(relations clients.RelationStore, logger *slog.Logger) *ListSubjectPrivilegesUseCase {
	u.relations = relations
	u.logger = logger
	return u
}

func (u *ListSubjectPrivilegesUseCase) Execute(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f repoab.PageFilter) ([]domain.SubjectPrivilege, string, error) {
	// 1. subject_type whitelist (user | service_account | group; group is
	// DIRECT-only).
	expectedPrefix, resName, err := subjectPrefixAndName(subjectType)
	if err != nil {
		return nil, "", err
	}

	// 2. prefix↔type validation — FIRST statement touching the id.
	// shared.ValidateResourceID checks prefix == expectedPrefix AND exact
	// length, so a well-formed sva-id passed as subject_type=user is rejected
	// (prefix mismatch) → InvalidArgument "invalid user id '<X>'".
	if err := shared.ValidateResourceID(string(subjectID), expectedPrefix, resName); err != nil {
		return nil, "", err
	}

	// 3. Anti-anonymous guard (catalog entry is cluster-floor; handler is the
	// authoritative policy — same pattern as ListBySubject / Create).
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}

	// 4. Resolve subject existence + home account (NotFound; yields account_id for authz).
	homeAccountID, err := u.resolveSubjectHomeAccount(ctx, subjectType, subjectID)
	if err != nil {
		return nil, "", err
	}

	// 5. AuthZ — self OR account-admin of the subject's home Account.
	if !authzguard.IsSelf(ctx, string(subjectID)) {
		if err := u.requireAccountViewAuthority(ctx, homeAccountID); err != nil {
			return nil, "", err
		}
	}

	// 6. Enriched repo read (JOIN role_name, keyset paginated).
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	out, next, err := rd.AccessBindings().ListSubjectPrivileges(ctx, subjectType, subjectID, f)
	if err != nil {
		return nil, "", shared.MapRepoErr(err)
	}
	return out, next, nil
}

// subjectPrefixAndName maps a subject_type to its id-prefix + human resource
// name (used in the malformed-id error text). user | service_account | group are
// in scope; anything else (garbage) → InvalidArgument.
func subjectPrefixAndName(subjectType domain.SubjectType) (prefix, resName string, err error) {
	switch subjectType {
	case domain.SubjectTypeUser:
		return domain.PrefixUser, "user", nil
	case domain.SubjectTypeServiceAccount:
		return domain.PrefixServiceAccount, "service account", nil
	case domain.SubjectTypeGroup:
		return domain.PrefixGroup, "group", nil
	default:
		return "", "", status.Error(codes.InvalidArgument,
			"Illegal argument subject_type (allowed: user|service_account|group)")
	}
}

// resolveSubjectHomeAccount reads the subject (User / ServiceAccount / Group) to
// (a) prove it exists (well-formed-but-nonexistent → NotFound) and (b)
// return its home account_id for the authz check. All reads are within
// kacho_iam, same-schema — NOT a cross-domain edge.
func (u *ListSubjectPrivilegesUseCase) resolveSubjectHomeAccount(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID) (domain.AccountID, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return "", shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	switch subjectType {
	case domain.SubjectTypeUser:
		usr, gerr := rd.Users().Get(ctx, domain.UserID(subjectID))
		if gerr != nil {
			return "", shared.MapRepoErr(gerr)
		}
		return usr.AccountID, nil
	case domain.SubjectTypeServiceAccount:
		sa, gerr := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(subjectID))
		if gerr != nil {
			return "", shared.MapRepoErr(gerr)
		}
		return sa.AccountID, nil
	case domain.SubjectTypeGroup:
		// A Group is Account-scoped (groups.account_id FK), so its
		// home account is the gate scope — same self/account-admin policy as User
		// / SA. Group has no "self" caller, so authority is always the
		// owner/account-admin path.
		grp, gerr := rd.Groups().Get(ctx, domain.GroupID(subjectID))
		if gerr != nil {
			return "", shared.MapRepoErr(gerr)
		}
		return grp.AccountID, nil
	default:
		// Unreachable — subjectPrefixAndName already rejected other types.
		return "", authzguard.PermissionDenied()
	}
}

// requireAccountViewAuthority — the caller may view another
// subject's privileges iff they administer the subject's home Account. Authority
// holds when EITHER:
//   - the caller owns the home Account (DB owner_user_id == principal), OR
//   - the caller holds an FGA `admin` relation on account:<homeAccountID>
//     (delegated admin who is not the owner).
//
// This is the read-side mirror of requireGrantAuthority on the SUBJECT's home
// account (so "who may grant" == "who may view"). A non-existent
// account (dangling home account) surfaces as PermissionDenied (no leak), not
// NotFound — existence of the SUBJECT was already proven in step 4.
func (u *ListSubjectPrivilegesUseCase) requireAccountViewAuthority(ctx context.Context, accountID domain.AccountID) error {
	if accountID == "" {
		return authzguard.PermissionDenied()
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Path 1 — owner of the home Account.
	acct, gerr := rd.Accounts().Get(ctx, accountID)
	if gerr == nil && acct.OwnerUserID != "" && authzguard.IsSelf(ctx, string(acct.OwnerUserID)) {
		return nil
	}
	// A missing account row is treated as "no owner-path" — fall through to the
	// FGA delegated-admin path; ultimately PermissionDenied if neither holds.
	if gerr != nil && !errors.Is(gerr, iamerr.ErrNotFound) {
		return shared.MapRepoErr(gerr)
	}

	// Path 2 — delegated admin: principal holds `admin` on account:<id> in FGA
	// (shared predicate — the single fgaHoldsAdmin used by every authority gate).
	if fgaHoldsAdmin(ctx, u.relations, "account", string(accountID)) {
		return nil
	}

	return authzguard.PermissionDenied()
}

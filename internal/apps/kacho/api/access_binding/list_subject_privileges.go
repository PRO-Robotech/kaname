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
//  4. subject resolve (Users().Get / ServiceAccounts().Get / Groups().Get) —
//     yields the home account_id the authz check needs. A subject that does not
//     resolve does NOT answer here: its NotFound is HELD BACK (step 6).
//  5. authz: IsSelf OR account-admin (owner of home Account OR FGA admin) OR
//     cluster-admin → PermissionDenied otherwise. Decided BEFORE existence is
//     allowed to shape the reply.
//  6. only now, for a caller who may read the subject: a subject that did not
//     resolve → NotFound.
//  7. repo JOIN read (access_bindings ⋈ roles), keyset paginated.
//
// Why authority precedes existence (and not the other way round): the subject id
// is caller-supplied and every id in the cluster is a legal probe. Answering
// "no such subject" before deciding whether the caller may read it makes the RPC
// an enumeration oracle over every user, service account and group — the caller
// separates "exists, not yours" from "does not exist" by the reply alone. So a
// caller without authority gets ONE answer for both, and only self /
// account-admin / cluster-admin are told that the subject is missing.

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

	// 4. Resolve the subject: yields the home account_id the authz check needs.
	// A subject that does not resolve is NOT reported here — res.miss is carried
	// to step 6 and only surfaces to a caller who may read the subject.
	res, err := u.resolveSubject(ctx, subjectType, subjectID)
	if err != nil {
		// A store failure is not a verdict about the subject — surface it as such.
		return nil, "", err
	}

	// 5. AuthZ — self OR account-admin of the subject's home Account OR
	// cluster-admin. Decided before existence is allowed to shape the reply.
	if !authzguard.IsSelf(ctx, string(subjectID)) {
		authorized := false
		if res.found {
			ok, aerr := u.hasAccountViewAuthority(ctx, res.accountID)
			if aerr != nil {
				return nil, "", aerr
			}
			authorized = ok
		} else {
			// An id that belongs to nobody has no home Account to administer, so
			// the only authority that can exist over it is the flat cluster-admin
			// super-gate. Everyone else is refused with the SAME answer they would
			// get for a subject in a foreign account — that identity of answers is
			// what closes the oracle.
			//
			// E-форма обязательна: за этой ветвью НЕТ пообъектной полосы, которая
			// сообщила бы о неполадке сама. Проглоченный отказ хранилища прав стал
			// бы здесь отказом В ПРАВАХ — то есть тем же ответом, что и настоящий
			// deny, и вызывающий не узнал бы, что повтор осмыслен.
			ok, aerr := authzguard.IsClusterAdminE(ctx, u.relations)
			if aerr != nil {
				return nil, "", authzguard.AuthzBackendUnavailable()
			}
			authorized = ok
		}
		if !authorized {
			return nil, "", authzguard.PermissionDenied()
		}
	}

	// 6. Authorized caller, unresolvable subject → the owner's own NotFound.
	if !res.found {
		return nil, "", res.miss
	}

	// 7. Enriched repo read (JOIN role_name, keyset paginated).
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

// subjectResolution — outcome of the subject lookup, with the absence answer
// held back. `miss` carries the owning repo's OWN NotFound (contract tone
// "<Resource> <id> not found", never re-composed here — re-composing it is how
// the hide-existence texts drift apart), and it is returned to the caller only
// after authority has been established.
type subjectResolution struct {
	accountID domain.AccountID
	found     bool
	miss      error
}

// resolveSubject reads the subject (User / ServiceAccount / Group) to return its
// home account_id for the authz check. All reads are within kacho_iam,
// same-schema — NOT a cross-domain edge.
//
// Three outcomes, deliberately distinct: resolved (found, account id); absent
// (found=false, miss holds the mapped NotFound — NOT returned as an error here,
// see the Execute step order); store failure (err — never a statement about the
// subject).
func (u *ListSubjectPrivilegesUseCase) resolveSubject(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID) (subjectResolution, error) {
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return subjectResolution{}, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	resolved := func(accountID domain.AccountID) (subjectResolution, error) {
		return subjectResolution{accountID: accountID, found: true}, nil
	}
	// classify splits "no such row" (deferred answer) from a real store failure.
	classify := func(gerr error) (subjectResolution, error) {
		if errors.Is(gerr, iamerr.ErrNotFound) {
			return subjectResolution{miss: shared.MapRepoErr(gerr)}, nil
		}
		return subjectResolution{}, shared.MapRepoErr(gerr)
	}

	switch subjectType {
	case domain.SubjectTypeUser:
		usr, gerr := rd.Users().Get(ctx, domain.UserID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(usr.AccountID)
	case domain.SubjectTypeServiceAccount:
		sa, gerr := rd.ServiceAccounts().Get(ctx, domain.ServiceAccountID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(sa.AccountID)
	case domain.SubjectTypeGroup:
		// A Group is Account-scoped (groups.account_id FK), so its
		// home account is the gate scope — same self/account-admin policy as User
		// / SA. Group has no "self" caller, so authority is always the
		// owner/account-admin path.
		grp, gerr := rd.Groups().Get(ctx, domain.GroupID(subjectID))
		if gerr != nil {
			return classify(gerr)
		}
		return resolved(grp.AccountID)
	default:
		// Unreachable — subjectPrefixAndName already rejected other types.
		return subjectResolution{}, authzguard.PermissionDenied()
	}
}

// hasAccountViewAuthority — the caller may view another
// subject's privileges iff they administer the subject's home Account. Authority
// holds when EITHER:
//   - the caller owns the home Account (DB owner_user_id == principal), OR
//   - the caller holds an FGA `admin` relation on account:<homeAccountID>
//     (delegated admin who is not the owner; fgaHoldsAdmin short-circuits the
//     flat cluster-admin super-gate).
//
// This is the read-side mirror of requireGrantAuthority on the SUBJECT's home
// account (so "who may grant" == "who may view"). A dangling home account is
// simply "no owner-path" — false, never a statement about the subject.
//
// Returns (false, nil) for "no authority" and (false, err) only for a store
// failure: the caller must not read an unreachable store as a denial.
func (u *ListSubjectPrivilegesUseCase) hasAccountViewAuthority(ctx context.Context, accountID domain.AccountID) (bool, error) {
	if accountID == "" {
		return false, nil
	}

	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return false, shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()

	// Path 1 — owner of the home Account.
	acct, gerr := rd.Accounts().Get(ctx, accountID)
	if gerr == nil && acct.OwnerUserID != "" && authzguard.IsSelf(ctx, string(acct.OwnerUserID)) {
		return true, nil
	}
	// A missing account row is treated as "no owner-path" — fall through to the
	// FGA delegated-admin path; ultimately unauthorized if neither holds.
	if gerr != nil && !errors.Is(gerr, iamerr.ErrNotFound) {
		return false, shared.MapRepoErr(gerr)
	}

	// Path 2 — delegated admin: principal holds `admin` on account:<id> in FGA
	// (shared predicate — the single authority gate used by every site).
	//
	// E-форма обязательна: этот путь строит СТРАНИЦУ видимого. Проглотив
	// неполадку хранилища прав, он вернул бы well-formed `200` с молча суженным
	// набором, который вызывающий не отличит от отзыва прав.
	return fgaHoldsAdminE(ctx, u.relations, "account", string(accountID))
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package access_binding

// list_by_subject.go — ListAccessBindingsBySubjectUseCase.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	repoab "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
)

type ListBySubjectUseCase struct {
	repo Repo
}

func NewListBySubjectUseCase(r Repo) *ListBySubjectUseCase {
	return &ListBySubjectUseCase{repo: r}
}

func (u *ListBySubjectUseCase) Execute(ctx context.Context, subjectType domain.SubjectType, subjectID domain.SubjectID, f repoab.PageFilter) ([]domain.AccessBinding, string, error) {
	// Handler-level anti-anonymous guard. Catalog is <exempt> so gateway
	// passes all authenticated callers; handler rejects anonymous.
	if err := authzguard.RequireAuthenticated(ctx); err != nil {
		return nil, "", err
	}
	// Self-only enforcement applies to ALL subject types (information
	// disclosure prevention).
	//
	// For user / service_account subjects: caller must be the subject.
	// For group subjects: caller must be a member of the group.
	// Membership is checked via group.IsMember; only user / service_account
	// principals can be members (per group_members_member_exists_trg in
	// 0001_initial.sql).
	switch string(subjectType) {
	case "user", "service_account":
		if !authzguard.IsSelf(ctx, string(subjectID)) {
			return nil, "", authzguard.PermissionDenied()
		}
	case "group":
		if err := u.requireGroupMembership(ctx, domain.GroupID(subjectID)); err != nil {
			return nil, "", err
		}
	default:
		// Unknown subject_type — conservatively deny.
		return nil, "", authzguard.PermissionDenied()
	}
	return readBindingsWithSubjects(ctx, u.repo, func(rd Reader) ([]domain.AccessBinding, string, error) {
		return rd.AccessBindings().ListBySubject(ctx, subjectType, subjectID, f)
	})
}

// requireGroupMembership — enforce group-membership guard for ListBySubject.
//
// The caller (principal from ctx) must be a member of `groupID` to enumerate
// its AccessBindings via the public ListBySubject path. Only user and
// service_account principals can be members (group_members.member_type CHECK
// constraint); other principal kinds — `system`, `bootstrap`, anonymous —
// are denied outright (anon already filtered by RequireAuthenticated above).
//
// Lookup goes through a fresh Reader transaction (Read-Committed) — a missing
// member triple resolves PermissionDenied; transport-layer errors propagate as
// Unavailable/Internal via mapRepoErr.
func (u *ListBySubjectUseCase) requireGroupMembership(ctx context.Context, groupID domain.GroupID) error {
	p := operations.PrincipalFromContext(ctx)
	switch p.Type {
	case "user", "service_account":
		// fall through
	default:
		// system / bootstrap / unknown — no DB membership row exists for these.
		return authzguard.PermissionDenied()
	}
	rd, err := u.repo.Reader(ctx)
	if err != nil {
		return shared.MapRepoErr(err)
	}
	defer func() { _ = rd.Rollback(ctx) }()
	isMember, err := rd.Groups().IsMember(ctx, groupID,
		domain.SubjectType(p.Type), domain.SubjectID(p.ID))
	if err != nil {
		return shared.MapRepoErr(err)
	}
	if !isMember {
		return authzguard.PermissionDenied()
	}
	return nil
}

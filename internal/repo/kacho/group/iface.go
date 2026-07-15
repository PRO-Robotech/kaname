// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package group — CQRS port-iface'ы для kacho_iam.groups + group_members.
package group

import (
	"context"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

type ReaderIface interface {
	Get(ctx context.Context, id domain.GroupID) (domain.Group, error)
	List(ctx context.Context, filter ListFilter) ([]domain.Group, string, error)
	ListMembers(ctx context.Context, groupID domain.GroupID) ([]domain.GroupMember, error)
	// IsMember — single-row EXISTS lookup against group_members for the
	// (groupID, memberType, memberID) triple. Used by
	// ListAccessBindingsBySubject to authorise group-subject queries: the
	// caller is allowed to enumerate bindings on a group iff they belong
	// to it.
	//
	// Returns false (no error) when the group does not exist OR the caller
	// is not a member. Backend errors (DB-unavailable / SQL syntax) surface
	// as ErrInternal / ErrUnavailable via the standard mapErr.
	IsMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) (bool, error)
}

type WriterIface interface {
	Insert(ctx context.Context, g domain.Group) (domain.Group, error)
	Update(ctx context.Context, g domain.Group, updateMask []string) (domain.Group, error)
	Delete(ctx context.Context, id domain.GroupID) error
	// AddMember — INSERT в group_members. DB-триггер
	// group_members_member_exists_trg проверяет существование member_id в
	// users / service_accounts → SQLSTATE 23503 → ErrFailedPrecondition.
	AddMember(ctx context.Context, m domain.GroupMember) error
	// RemoveMember — DELETE. Идемпотентен (повторное удаление участника).
	RemoveMember(ctx context.Context, groupID domain.GroupID, memberType domain.SubjectType, memberID domain.SubjectID) error
}

type ListFilter struct {
	PageSize  int32
	PageToken string
	Filter    string
	AccountID domain.AccountID
}

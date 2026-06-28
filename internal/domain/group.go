// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"time"

	"go.uber.org/multierr"
)

// Group — Account-scoped (account_id FK ON DELETE RESTRICT), имеет members
// (User или ServiceAccount — полиморфно через `group_members.member_type`).
// Используется в AccessBinding для упрощения раздачи прав.
type Group struct {
	ID          GroupID
	AccountID   AccountID
	Name        GroupName
	Description Description
	Labels      Labels
	CreatedAt   time.Time
}

func (g Group) Validate() error {
	var errs error
	errs = multierr.Append(errs, g.Name.Validate())
	errs = multierr.Append(errs, g.Description.Validate())
	errs = multierr.Append(errs, g.Labels.Validate())
	if g.AccountID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	return errs
}

// GroupMember — связка group_id ↔ (member_type, member_id).
// Целостность member_id обеспечивается DB-триггером
// `group_members_member_exists_trg` (нет полиморфного FK в Postgres).
type GroupMember struct {
	GroupID    GroupID
	MemberType SubjectType // user | service_account (group из enum'а исключен)
	MemberID   SubjectID
	AddedAt    time.Time
}

func (m GroupMember) Validate() error {
	var errs error
	if m.GroupID == "" || m.MemberID == "" {
		errs = multierr.Append(errs, ErrEmpty)
	}
	// member_type для GroupMember — только user / service_account (group из
	// enum'а исключен, в БД CHECK `group_members_type_check`).
	switch m.MemberType {
	case SubjectTypeUser, SubjectTypeServiceAccount:
		// OK
	default:
		errs = multierr.Append(errs, m.MemberType.Validate())
	}
	return errs
}

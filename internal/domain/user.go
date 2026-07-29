// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// InviteStatus — invite-flow state for a User row.
//
// PENDING — created via `UserService.Invite`, external_id="" until first
// login; the invitee has not yet confirmed identity through Kratos.
// ACTIVE  — either self-signup via `UpsertFromIdentity` without a pending
// invite, or a PENDING row activated on first-login (matched by email).
// BLOCKED — административный запрет на членство в Account'е. Продуктового пути,
// который его СТАВИТ, сегодня нет ни одного (проверяется гейтом
// blocked_state_reachability_test.go): запрет ставится прямым вмешательством
// оператора в базу, и у него же есть обратное утверждение.
//
// Снимать запрет самостоятельным действием нельзя: восстановление пароля
// доказывает владение почтовым ящиком — ровно то, чего администратор, ставя
// запрет, под сомнение не ставил (см. internal_on_recovery.go). Поэтому день,
// когда путь блокировки появится, обязан быть и днём, когда появится
// административный путь снятия — иначе заблокированный окажется заперт
// навсегда. Гейт делает это упавшей сборкой, а не открытием.
type InviteStatus string

const (
	InviteStatusPending InviteStatus = "PENDING"
	InviteStatusActive  InviteStatus = "ACTIVE"
	InviteStatusBlocked InviteStatus = "BLOCKED"
)

// MayAuthenticate reports whether a user in this state may be issued a token.
//
// This is the VERDICT both token hooks ask for, and the reason it exists as a
// predicate rather than as a WHERE clause: the hooks used to resolve the
// identity through an ACTIVE-only query, which turns "blocked" into "absent" —
// and then read absence in opposite directions. One refused; the other took it
// for "the mirror has not committed yet" and issued the reduced claim set to a
// blocked user. A filter cannot be asked "why"; a verdict can.
//
// Only ACTIVE authenticates. PENDING is an invitee who has not confirmed an
// identity yet (the DB CHECK users_invite_status_consistency keeps such a row
// from carrying an external id at all, so it is a floor rather than a live
// path), and an unset state is not an authorisation.
func (s InviteStatus) MayAuthenticate() bool {
	return s == InviteStatusActive
}

func (s InviteStatus) Validate() error {
	switch s {
	case InviteStatusPending, InviteStatusActive, InviteStatusBlocked:
		return nil
	default:
		return fmt.Errorf("Illegal argument invite_status %q (allowed: PENDING|ACTIVE|BLOCKED)", string(s))
	}
}

// User — mirror identity from Kratos, scoped per-Account.
//
// One Kratos identity → N User rows (one per Account: invited or owner).
// external_id (the Kratos `sub`) is unique per-Account only among ACTIVE
// rows; PENDING rows hold external_id="" until first login (see partial
// UNIQUE `users_account_external_id_unique WHERE external_id <> ""`).
type User struct {
	ID           UserID
	AccountID    AccountID
	ExternalID   ExternalSubject
	Email        Email
	DisplayName  DisplayName
	InviteStatus InviteStatus
	InvitedBy    UserID // user.id of admin who invoked Invite; "" if self-signup
	CreatedAt    time.Time
	// Labels — tenant-facing метки. Делают User label-selectable наравне с
	// account/project: ARM_LABELS-грант на iam.user материализует v_list по
	// `labels @> matchLabels`, а List фильтрует через viewer ∪ v_list.
	Labels Labels
}

// Validate — fields + invite-status consistency.
//
// PENDING ⇔ external_id="" ; ACTIVE/BLOCKED ⇔ external_id<>""
// (matches DB CHECK users_invite_status_consistency).
func (u User) Validate() error {
	var errs error
	// AccountID — required: every User belongs to exactly one Account (NOT NULL
	// account_id + FK). Domain enforces non-emptiness here, consistent with the
	// sibling self-validating types (Project/Group/ServiceAccount.Validate). The
	// full id-prefix/length format check stays centralized at the use-case layer
	// (shared.ValidateResourceID) — the domain gate is "the invariant holds",
	// not the transport-format validation.
	if u.AccountID == "" {
		errs = multierr.Append(errs, fmt.Errorf("Illegal argument account_id: required"))
	}
	errs = multierr.Append(errs, u.Email.Validate())
	errs = multierr.Append(errs, u.Labels.Validate())
	if u.DisplayName != "" {
		errs = multierr.Append(errs, u.DisplayName.Validate())
	}
	if u.InviteStatus != "" {
		errs = multierr.Append(errs, u.InviteStatus.Validate())
	}
	// Consistency: PENDING ⇔ external_id='' ; ACTIVE/BLOCKED ⇔ external_id<>''.
	switch u.InviteStatus {
	case InviteStatusPending:
		if u.ExternalID != "" {
			errs = multierr.Append(errs,
				fmt.Errorf("Illegal argument external_id: must be empty for PENDING invite"))
		}
	case InviteStatusActive, InviteStatusBlocked:
		if err := u.ExternalID.Validate(); err != nil {
			errs = multierr.Append(errs, err)
		}
	default:
		// invite_status empty — pre-validation path (e.g. inside the repo layer).
		if u.ExternalID != "" {
			if err := u.ExternalID.Validate(); err != nil {
				errs = multierr.Append(errs, err)
			}
		}
	}
	return errs
}

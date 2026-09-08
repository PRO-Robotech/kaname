// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// BLOCKED — административный запрет на членство в Account'е. Ставится и снимается
// ДЕЙСТВИЯМИ `UserService.Block` / `Unblock` (право `identity_suspender@iam_user`
// = админ аккаунта плюс каскад облака; `v_update` с этого типа снят, #1128);
// писатель — `userWriter.SetInviteStatus`.
//
// Состояние принадлежит СТРОКЕ ЧЛЕНСТВА, а не человеку. Одна личность держит по
// строке на каждый Account, поэтому запрет принадлежит тому аккаунту, который его
// наложил, и не отключает личность там, где она законно активна: выдача токена
// перебирает набор членств и обслуживает первое аутентифицирующееся, отказывая
// лишь когда ни одно не может (token_enrichment_service.go, iamhooks).
//
// Снимать запрет самостоятельным действием нельзя: восстановление пароля
// доказывает владение почтовым ящиком — ровно то, чего администратор, ставя
// запрет, под сомнение не ставил (см. internal_on_recovery.go). Поэтому у пути
// блокировки ОБЯЗАН быть административный путь снятия, иначе заблокированный
// окажется заперт навсегда. Гейт blocked_state_reachability_test.go требует,
// чтобы каждый писатель этого состояния был объявлен вместе со ссылкой на
// снятие, — и делает появление одностороннего пути упавшей сборкой, а не
// открытием.
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

// User — зеркало личности из внешнего провайдера. Одна личность — ОДНА строка,
// сколько бы аккаунтов её ни пригласило.
//
// Принадлежность аккаунту здесь НЕ живёт: её выражает строка
// `kaname.memberships` (одна на пару «человек × аккаунт»), и членств у одного
// человека бывает несколько. Ключ идентичности — глобальный:
// `users_identity_email_uniq` и `users_identity_external_id_uniq`
// (`20260823050000_users_identity_uniqueness_goes_global.sql`, стадия S4-expand
// перехода IAM-ID-1). PENDING-строка держит external_id="" до первого входа.
//
// Поле AccountID — ЛЕГАСИ-колонка перехода: она жива и `NOT NULL` до стадии S4,
// но «его аккаунт» из неё не читается — у человека их несколько.
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
	// AccountID здесь НАМЕРЕННО не проверяется (IAM-ID-1-58, стадия S2).
	// Человек больше не «человек в аккаунте»: принадлежность выражает строка
	// memberships, и членств у него бывает несколько — значит требование
	// непустоты сделало бы целевую форму невыразимой в домене. Инвариант
	// колонки при этом держит СХЕМА (`users.account_id NOT NULL` + FK, жив до
	// стадии S4), а не software-проверка (ban #10).
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

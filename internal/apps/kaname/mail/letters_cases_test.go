// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail_test

// letters_cases_test.go — по одному ряду на шаблон каталога feedgen: законные
// значения каждого атрибута, конструктор и тип атрибутов feedgen (для пробы
// полноты). Ряды выписаны по одному на шаблон — их число сверяет с каталогом
// TestLetterCasesCoverTheCatalog.

import (
	"time"

	"github.com/PRO-Robotech/corelib/notify/address"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"
)

func letterCases(to address.Normalized, at time.Time) []letterCase {
	return []letterCase{
		{
			template: "access-key-changed",
			subject:  true,
			feedgen:  feedgen.AccessKeyChangedAttrs{},
			valid: mail.AccessKeyChangedAttrs{
				AccessKeyID: "access-key-id-value",
				Change:      "change-value",
				OccurredAt:  at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.AccessKeyChanged(r, attrs.(mail.AccessKeyChangedAttrs))
			},
		},
		{
			template: "account-deleted",
			subject:  true,
			feedgen:  feedgen.AccountDeletedAttrs{},
			valid: mail.AccountDeletedAttrs{
				AccountID:  "account-id-value",
				OccurredAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.AccountDeleted(r, attrs.(mail.AccountDeletedAttrs))
			},
		},
		{
			template: "backup-codes-regenerated",
			subject:  true,
			feedgen:  feedgen.BackupCodesRegeneratedAttrs{},
			valid: mail.BackupCodesRegeneratedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.BackupCodesRegenerated(r, attrs.(mail.BackupCodesRegeneratedAttrs))
			},
		},
		{
			template: "cluster-admin-granted",
			subject:  true,
			feedgen:  feedgen.ClusterAdminGrantedAttrs{},
			valid: mail.ClusterAdminGrantedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.ClusterAdminGranted(r, attrs.(mail.ClusterAdminGrantedAttrs))
			},
		},
		{
			template: "cluster-admin-revoked",
			subject:  true,
			feedgen:  feedgen.ClusterAdminRevokedAttrs{},
			valid: mail.ClusterAdminRevokedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.ClusterAdminRevoked(r, attrs.(mail.ClusterAdminRevokedAttrs))
			},
		},
		{
			template: "invite",
			subject:  false,
			feedgen:  feedgen.InviteAttrs{},
			valid: mail.InviteAttrs{
				AccountID:      "account-id-value",
				ExpiresAt:      at,
				InviterAddress: mail.Present("inviter-address-value"),
				Token:          "tok_0123456789abcdefXYZ",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.Invite(r, attrs.(mail.InviteAttrs))
			},
		},
		{
			template: "mail-throttled",
			subject:  false,
			feedgen:  feedgen.MailThrottledAttrs{},
			valid: mail.MailThrottledAttrs{
				RequestedAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.MailThrottled(r, attrs.(mail.MailThrottledAttrs))
			},
		},
		{
			template: "new-device-login",
			subject:  true,
			feedgen:  feedgen.NewDeviceLoginAttrs{},
			valid: mail.NewDeviceLoginAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.NewDeviceLogin(r, attrs.(mail.NewDeviceLoginAttrs))
			},
		},
		{
			template: "password-changed",
			subject:  true,
			feedgen:  feedgen.PasswordChangedAttrs{},
			valid: mail.PasswordChangedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.PasswordChanged(r, attrs.(mail.PasswordChangedAttrs))
			},
		},
		{
			template: "project-deleted",
			subject:  true,
			feedgen:  feedgen.ProjectDeletedAttrs{},
			valid: mail.ProjectDeletedAttrs{
				AccountID:  "account-id-value",
				OccurredAt: at,
				ProjectID:  "project-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.ProjectDeleted(r, attrs.(mail.ProjectDeletedAttrs))
			},
		},
		{
			template: "recovery-completed",
			subject:  true,
			feedgen:  feedgen.RecoveryCompletedAttrs{},
			valid: mail.RecoveryCompletedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.RecoveryCompleted(r, attrs.(mail.RecoveryCompletedAttrs))
			},
		},
		{
			template: "recovery",
			subject:  false,
			feedgen:  feedgen.RecoveryAttrs{},
			valid: mail.RecoveryAttrs{
				Code:        "482913",
				RequestedAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.Recovery(r, attrs.(mail.RecoveryAttrs))
			},
		},
		{
			template: "registration-existing",
			subject:  false,
			feedgen:  feedgen.RegistrationExistingAttrs{},
			valid: mail.RegistrationExistingAttrs{
				RequestedAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.RegistrationExisting(r, attrs.(mail.RegistrationExistingAttrs))
			},
		},
		{
			template: "registration",
			subject:  false,
			feedgen:  feedgen.RegistrationAttrs{},
			valid: mail.RegistrationAttrs{
				Code:        "482913",
				RequestedAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.Registration(r, attrs.(mail.RegistrationAttrs))
			},
		},
		{
			template: "removed-from-account",
			subject:  true,
			feedgen:  feedgen.RemovedFromAccountAttrs{},
			valid: mail.RemovedFromAccountAttrs{
				AccountID:  "account-id-value",
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.RemovedFromAccount(r, attrs.(mail.RemovedFromAccountAttrs))
			},
		},
		{
			template: "role-granted",
			subject:  true,
			feedgen:  feedgen.RoleGrantedAttrs{},
			valid: mail.RoleGrantedAttrs{
				OccurredAt: at,
				ResourceID: "resource-id-value",
				RoleID:     "role-id-value",
				SubjectID:  "subject-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.RoleGranted(r, attrs.(mail.RoleGrantedAttrs))
			},
		},
		{
			template: "role-revoked",
			subject:  true,
			feedgen:  feedgen.RoleRevokedAttrs{},
			valid: mail.RoleRevokedAttrs{
				OccurredAt: at,
				ResourceID: "resource-id-value",
				RoleID:     "role-id-value",
				SubjectID:  "subject-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.RoleRevoked(r, attrs.(mail.RoleRevokedAttrs))
			},
		},
		{
			template: "sa-key-issued",
			subject:  true,
			feedgen:  feedgen.SaKeyIssuedAttrs{},
			valid: mail.SaKeyIssuedAttrs{
				AccountID:        "account-id-value",
				KeyID:            "key-id-value",
				OccurredAt:       at,
				ServiceAccountID: "service-account-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.SaKeyIssued(r, attrs.(mail.SaKeyIssuedAttrs))
			},
		},
		{
			template: "second-factor-changed",
			subject:  true,
			feedgen:  feedgen.SecondFactorChangedAttrs{},
			valid: mail.SecondFactorChangedAttrs{
				Change:     "change-value",
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.SecondFactorChanged(r, attrs.(mail.SecondFactorChangedAttrs))
			},
		},
		{
			template: "service-account-disabled",
			subject:  true,
			feedgen:  feedgen.ServiceAccountDisabledAttrs{},
			valid: mail.ServiceAccountDisabledAttrs{
				AccountID:        "account-id-value",
				OccurredAt:       at,
				ServiceAccountID: "service-account-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.ServiceAccountDisabled(r, attrs.(mail.ServiceAccountDisabledAttrs))
			},
		},
		{
			template: "sessions-revoked",
			subject:  true,
			feedgen:  feedgen.SessionsRevokedAttrs{},
			valid: mail.SessionsRevokedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.SessionsRevoked(r, attrs.(mail.SessionsRevokedAttrs))
			},
		},
		{
			template: "user-blocked",
			subject:  true,
			feedgen:  feedgen.UserBlockedAttrs{},
			valid: mail.UserBlockedAttrs{
				OccurredAt: at,
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.UserBlocked(r, attrs.(mail.UserBlockedAttrs))
			},
		},
		{
			template: "user-token-issued",
			subject:  true,
			feedgen:  feedgen.UserTokenIssuedAttrs{},
			valid: mail.UserTokenIssuedAttrs{
				OccurredAt: at,
				TokenID:    "token-id-value",
				UserID:     "user-id-value",
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := subjectUserID
				if zeroTo {
					r = ""
				}
				return mail.UserTokenIssued(r, attrs.(mail.UserTokenIssuedAttrs))
			},
		},
		{
			template: "verification",
			subject:  false,
			feedgen:  feedgen.VerificationAttrs{},
			valid: mail.VerificationAttrs{
				Code:        "482913",
				RequestedAt: at,
			},
			build: func(attrs any, zeroTo bool) (mail.Letter, error) {
				r := to
				if zeroTo {
					r = address.Normalized{}
				}
				return mail.Verification(r, attrs.(mail.VerificationAttrs))
			},
		},
	}
}

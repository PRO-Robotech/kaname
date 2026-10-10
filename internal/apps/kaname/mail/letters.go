// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mail

// letters.go — конструкторы Letter по 24 шаблонам каталога feedgen (замысел
// issue-2917 З1, З27; приёмка NTF-2 Р3). У каждого шаблона ОДИН конструктор, и
// он принимает каждый объявленный атрибут: required — значением, optional —
// закрытым типом Optional (Present | Absent). Перечень атрибутов и их
// признаков — notification.yaml каталога шаблонов; полноту конструкторов против
// типов атрибутов feedgen держит модульная проба letters_test.go.
//
// Адресат — по форме описания шаблона: address — address.Normalized (вход-строки
// нет, значение строит только Normalize), subject — id пользователя.

import (
	"time"

	"github.com/PRO-Robotech/corelib/notify/address"
	"github.com/PRO-Robotech/corelib/notify/form"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"
)

// AccessKeyChangedAttrs — атрибуты письма шаблона access-key-changed.
type AccessKeyChangedAttrs struct {
	AccessKeyID string    // access_key_id · text · required
	Change      string    // change · text · required
	OccurredAt  time.Time // occurred_at · timestamp · required
}

// AccessKeyChanged — письмо шаблона access-key-changed пользователю toUserID (форма subject).
func AccessKeyChanged(toUserID string, a AccessKeyChangedAttrs) (Letter, error) {
	const tmpl = "access-key-changed"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "access_key_id", form.KindText, a.AccessKeyID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "change", form.KindText, a.Change); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendAccessKeyChanged, feedgen.AccessKeyChangedAttrs{
		To:          recipient,
		AccessKeyId: a.AccessKeyID,
		Change:      a.Change,
		OccurredAt:  a.OccurredAt,
	}), nil
}

// AccountDeletedAttrs — атрибуты письма шаблона account-deleted.
type AccountDeletedAttrs struct {
	AccountID  string    // account_id · text · required
	OccurredAt time.Time // occurred_at · timestamp · required
}

// AccountDeleted — письмо шаблона account-deleted пользователю toUserID (форма subject).
func AccountDeleted(toUserID string, a AccountDeletedAttrs) (Letter, error) {
	const tmpl = "account-deleted"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendAccountDeleted, feedgen.AccountDeletedAttrs{
		To:         recipient,
		AccountId:  a.AccountID,
		OccurredAt: a.OccurredAt,
	}), nil
}

// BackupCodesRegeneratedAttrs — атрибуты письма шаблона backup-codes-regenerated.
type BackupCodesRegeneratedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// BackupCodesRegenerated — письмо шаблона backup-codes-regenerated пользователю toUserID (форма subject).
func BackupCodesRegenerated(toUserID string, a BackupCodesRegeneratedAttrs) (Letter, error) {
	const tmpl = "backup-codes-regenerated"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendBackupCodesRegenerated, feedgen.BackupCodesRegeneratedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// ClusterAdminGrantedAttrs — атрибуты письма шаблона cluster-admin-granted.
type ClusterAdminGrantedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// ClusterAdminGranted — письмо шаблона cluster-admin-granted пользователю toUserID (форма subject).
func ClusterAdminGranted(toUserID string, a ClusterAdminGrantedAttrs) (Letter, error) {
	const tmpl = "cluster-admin-granted"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendClusterAdminGranted, feedgen.ClusterAdminGrantedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// ClusterAdminRevokedAttrs — атрибуты письма шаблона cluster-admin-revoked.
type ClusterAdminRevokedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// ClusterAdminRevoked — письмо шаблона cluster-admin-revoked пользователю toUserID (форма subject).
func ClusterAdminRevoked(toUserID string, a ClusterAdminRevokedAttrs) (Letter, error) {
	const tmpl = "cluster-admin-revoked"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendClusterAdminRevoked, feedgen.ClusterAdminRevokedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// InviteAttrs — атрибуты письма шаблона invite.
type InviteAttrs struct {
	AccountID      string    // account_id · text · required
	ExpiresAt      time.Time // expires_at · timestamp · required
	InviterAddress Optional  // inviter_address · text · optional
	Token          string    // token · token · required
}

// Invite — письмо шаблона invite адресату to (форма address).
func Invite(to address.Normalized, a InviteAttrs) (Letter, error) {
	const tmpl = "invite"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "expires_at", form.KindTimestamp, a.ExpiresAt); err != nil {
		return Letter{}, err
	}
	inviterAddress, err := optionalValue(tmpl, "inviter_address", form.KindText, a.InviterAddress)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "token", form.KindToken, a.Token); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendInvite, feedgen.InviteAttrs{
		To:             recipient,
		AccountId:      a.AccountID,
		ExpiresAt:      a.ExpiresAt,
		InviterAddress: inviterAddress,
		Token:          a.Token,
	}), nil
}

// MailThrottledAttrs — атрибуты письма шаблона mail-throttled.
type MailThrottledAttrs struct {
	RequestedAt time.Time // requested_at · timestamp · required
}

// MailThrottled — письмо шаблона mail-throttled адресату to (форма address).
func MailThrottled(to address.Normalized, a MailThrottledAttrs) (Letter, error) {
	const tmpl = "mail-throttled"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "requested_at", form.KindTimestamp, a.RequestedAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendMailThrottled, feedgen.MailThrottledAttrs{
		To:          recipient,
		RequestedAt: a.RequestedAt,
	}), nil
}

// NewDeviceLoginAttrs — атрибуты письма шаблона new-device-login.
type NewDeviceLoginAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// NewDeviceLogin — письмо шаблона new-device-login пользователю toUserID (форма subject).
func NewDeviceLogin(toUserID string, a NewDeviceLoginAttrs) (Letter, error) {
	const tmpl = "new-device-login"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendNewDeviceLogin, feedgen.NewDeviceLoginAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// PasswordChangedAttrs — атрибуты письма шаблона password-changed.
type PasswordChangedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// PasswordChanged — письмо шаблона password-changed пользователю toUserID (форма subject).
func PasswordChanged(toUserID string, a PasswordChangedAttrs) (Letter, error) {
	const tmpl = "password-changed"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendPasswordChanged, feedgen.PasswordChangedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// ProjectDeletedAttrs — атрибуты письма шаблона project-deleted.
type ProjectDeletedAttrs struct {
	AccountID  string    // account_id · text · required
	OccurredAt time.Time // occurred_at · timestamp · required
	ProjectID  string    // project_id · text · required
}

// ProjectDeleted — письмо шаблона project-deleted пользователю toUserID (форма subject).
func ProjectDeleted(toUserID string, a ProjectDeletedAttrs) (Letter, error) {
	const tmpl = "project-deleted"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "project_id", form.KindText, a.ProjectID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendProjectDeleted, feedgen.ProjectDeletedAttrs{
		To:         recipient,
		AccountId:  a.AccountID,
		OccurredAt: a.OccurredAt,
		ProjectId:  a.ProjectID,
	}), nil
}

// RecoveryCompletedAttrs — атрибуты письма шаблона recovery-completed.
type RecoveryCompletedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// RecoveryCompleted — письмо шаблона recovery-completed пользователю toUserID (форма subject).
func RecoveryCompleted(toUserID string, a RecoveryCompletedAttrs) (Letter, error) {
	const tmpl = "recovery-completed"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRecoveryCompleted, feedgen.RecoveryCompletedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// RecoveryAttrs — атрибуты письма шаблона recovery.
type RecoveryAttrs struct {
	Code        string    // code · secret · required
	RequestedAt time.Time // requested_at · timestamp · required
}

// Recovery — письмо шаблона recovery адресату to (форма address).
func Recovery(to address.Normalized, a RecoveryAttrs) (Letter, error) {
	const tmpl = "recovery"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "code", form.KindSecret, a.Code); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "requested_at", form.KindTimestamp, a.RequestedAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRecovery, feedgen.RecoveryAttrs{
		To:          recipient,
		Code:        a.Code,
		RequestedAt: a.RequestedAt,
	}), nil
}

// RegistrationExistingAttrs — атрибуты письма шаблона registration-existing.
type RegistrationExistingAttrs struct {
	RequestedAt time.Time // requested_at · timestamp · required
}

// RegistrationExisting — письмо шаблона registration-existing адресату to (форма address).
func RegistrationExisting(to address.Normalized, a RegistrationExistingAttrs) (Letter, error) {
	const tmpl = "registration-existing"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "requested_at", form.KindTimestamp, a.RequestedAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRegistrationExisting, feedgen.RegistrationExistingAttrs{
		To:          recipient,
		RequestedAt: a.RequestedAt,
	}), nil
}

// RegistrationAttrs — атрибуты письма шаблона registration.
type RegistrationAttrs struct {
	Code        string    // code · secret · required
	RequestedAt time.Time // requested_at · timestamp · required
}

// Registration — письмо шаблона registration адресату to (форма address).
func Registration(to address.Normalized, a RegistrationAttrs) (Letter, error) {
	const tmpl = "registration"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "code", form.KindSecret, a.Code); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "requested_at", form.KindTimestamp, a.RequestedAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRegistration, feedgen.RegistrationAttrs{
		To:          recipient,
		Code:        a.Code,
		RequestedAt: a.RequestedAt,
	}), nil
}

// RemovedFromAccountAttrs — атрибуты письма шаблона removed-from-account.
type RemovedFromAccountAttrs struct {
	AccountID  string    // account_id · text · required
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// RemovedFromAccount — письмо шаблона removed-from-account пользователю toUserID (форма subject).
func RemovedFromAccount(toUserID string, a RemovedFromAccountAttrs) (Letter, error) {
	const tmpl = "removed-from-account"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRemovedFromAccount, feedgen.RemovedFromAccountAttrs{
		To:         recipient,
		AccountId:  a.AccountID,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// RoleGrantedAttrs — атрибуты письма шаблона role-granted.
type RoleGrantedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	ResourceID string    // resource_id · text · required
	RoleID     string    // role_id · text · required
	SubjectID  string    // subject_id · text · required
}

// RoleGranted — письмо шаблона role-granted пользователю toUserID (форма subject).
func RoleGranted(toUserID string, a RoleGrantedAttrs) (Letter, error) {
	const tmpl = "role-granted"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "resource_id", form.KindText, a.ResourceID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "role_id", form.KindText, a.RoleID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "subject_id", form.KindText, a.SubjectID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRoleGranted, feedgen.RoleGrantedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		ResourceId: a.ResourceID,
		RoleId:     a.RoleID,
		SubjectId:  a.SubjectID,
	}), nil
}

// RoleRevokedAttrs — атрибуты письма шаблона role-revoked.
type RoleRevokedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	ResourceID string    // resource_id · text · required
	RoleID     string    // role_id · text · required
	SubjectID  string    // subject_id · text · required
}

// RoleRevoked — письмо шаблона role-revoked пользователю toUserID (форма subject).
func RoleRevoked(toUserID string, a RoleRevokedAttrs) (Letter, error) {
	const tmpl = "role-revoked"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "resource_id", form.KindText, a.ResourceID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "role_id", form.KindText, a.RoleID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "subject_id", form.KindText, a.SubjectID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendRoleRevoked, feedgen.RoleRevokedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		ResourceId: a.ResourceID,
		RoleId:     a.RoleID,
		SubjectId:  a.SubjectID,
	}), nil
}

// SaKeyIssuedAttrs — атрибуты письма шаблона sa-key-issued.
type SaKeyIssuedAttrs struct {
	AccountID        string    // account_id · text · required
	KeyID            string    // key_id · text · required
	OccurredAt       time.Time // occurred_at · timestamp · required
	ServiceAccountID string    // service_account_id · text · required
}

// SaKeyIssued — письмо шаблона sa-key-issued пользователю toUserID (форма subject).
func SaKeyIssued(toUserID string, a SaKeyIssuedAttrs) (Letter, error) {
	const tmpl = "sa-key-issued"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "key_id", form.KindText, a.KeyID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "service_account_id", form.KindText, a.ServiceAccountID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendSaKeyIssued, feedgen.SaKeyIssuedAttrs{
		To:               recipient,
		AccountId:        a.AccountID,
		KeyId:            a.KeyID,
		OccurredAt:       a.OccurredAt,
		ServiceAccountId: a.ServiceAccountID,
	}), nil
}

// SecondFactorChangedAttrs — атрибуты письма шаблона second-factor-changed.
type SecondFactorChangedAttrs struct {
	Change     string    // change · text · required
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// SecondFactorChanged — письмо шаблона second-factor-changed пользователю toUserID (форма subject).
func SecondFactorChanged(toUserID string, a SecondFactorChangedAttrs) (Letter, error) {
	const tmpl = "second-factor-changed"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "change", form.KindText, a.Change); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendSecondFactorChanged, feedgen.SecondFactorChangedAttrs{
		To:         recipient,
		Change:     a.Change,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// ServiceAccountDisabledAttrs — атрибуты письма шаблона service-account-disabled.
type ServiceAccountDisabledAttrs struct {
	AccountID        string    // account_id · text · required
	OccurredAt       time.Time // occurred_at · timestamp · required
	ServiceAccountID string    // service_account_id · text · required
}

// ServiceAccountDisabled — письмо шаблона service-account-disabled пользователю toUserID (форма subject).
func ServiceAccountDisabled(toUserID string, a ServiceAccountDisabledAttrs) (Letter, error) {
	const tmpl = "service-account-disabled"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "account_id", form.KindText, a.AccountID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "service_account_id", form.KindText, a.ServiceAccountID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendServiceAccountDisabled, feedgen.ServiceAccountDisabledAttrs{
		To:               recipient,
		AccountId:        a.AccountID,
		OccurredAt:       a.OccurredAt,
		ServiceAccountId: a.ServiceAccountID,
	}), nil
}

// SessionsRevokedAttrs — атрибуты письма шаблона sessions-revoked.
type SessionsRevokedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// SessionsRevoked — письмо шаблона sessions-revoked пользователю toUserID (форма subject).
func SessionsRevoked(toUserID string, a SessionsRevokedAttrs) (Letter, error) {
	const tmpl = "sessions-revoked"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendSessionsRevoked, feedgen.SessionsRevokedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// UserBlockedAttrs — атрибуты письма шаблона user-blocked.
type UserBlockedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	UserID     string    // user_id · text · required
}

// UserBlocked — письмо шаблона user-blocked пользователю toUserID (форма subject).
func UserBlocked(toUserID string, a UserBlockedAttrs) (Letter, error) {
	const tmpl = "user-blocked"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendUserBlocked, feedgen.UserBlockedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		UserId:     a.UserID,
	}), nil
}

// UserTokenIssuedAttrs — атрибуты письма шаблона user-token-issued.
type UserTokenIssuedAttrs struct {
	OccurredAt time.Time // occurred_at · timestamp · required
	TokenID    string    // token_id · text · required
	UserID     string    // user_id · text · required
}

// UserTokenIssued — письмо шаблона user-token-issued пользователю toUserID (форма subject).
func UserTokenIssued(toUserID string, a UserTokenIssuedAttrs) (Letter, error) {
	const tmpl = "user-token-issued"
	recipient, err := subjectRecipient(tmpl, toUserID)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "occurred_at", form.KindTimestamp, a.OccurredAt); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "token_id", form.KindText, a.TokenID); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "user_id", form.KindText, a.UserID); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendUserTokenIssued, feedgen.UserTokenIssuedAttrs{
		To:         recipient,
		OccurredAt: a.OccurredAt,
		TokenId:    a.TokenID,
		UserId:     a.UserID,
	}), nil
}

// VerificationAttrs — атрибуты письма шаблона verification.
type VerificationAttrs struct {
	Code        string    // code · secret · required
	RequestedAt time.Time // requested_at · timestamp · required
}

// Verification — письмо шаблона verification адресату to (форма address).
func Verification(to address.Normalized, a VerificationAttrs) (Letter, error) {
	const tmpl = "verification"
	recipient, err := addressRecipient(tmpl, to)
	if err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "code", form.KindSecret, a.Code); err != nil {
		return Letter{}, err
	}
	if err := required(tmpl, "requested_at", form.KindTimestamp, a.RequestedAt); err != nil {
		return Letter{}, err
	}
	return letterOf(tmpl, feedgen.SendVerification, feedgen.VerificationAttrs{
		To:          recipient,
		Code:        a.Code,
		RequestedAt: a.RequestedAt,
	}), nil
}

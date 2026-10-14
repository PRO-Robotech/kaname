// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package invite_mail_outbox — writer намерения отправить письмо в
// `kaname.invite_mail_outbox`: приглашение (ID-MAIL-1), с фазы Ф5 — код
// восстановления доступа (`kacho#1271`, Р3 — второй вид в ТОЙ ЖЕ очереди) и
// код подтверждения адреса (kaname#456, Р8 — третий вид).
//
// Намерение пишется В ТОЙ ЖЕ транзакции, что строка предмета (приглашения либо
// кода), и это несущее свойство, а не оптимизация: при откате предмета
// намерения нет ВОВСЕ, а при состоявшемся предмете оно переживает смерть
// процесса. Утверждать надо именно это — «событие эмитировано» есть утверждение
// о ВЫЗОВЕ, а не о свойстве, и остаётся зелёным на отправке письма о том, чего
// не случилось.
//
// # ВРЕМЯ СДАЧИ ПИСЬМА НА КОНТРАКТ НЕ ВЫХОДИТ, И ЭТО РЕШЕНИЕ
//
// Колонка `sent_at` этой очереди — ЖИВОСТЬ ОЧЕРЕДИ, а не факт для арендатора:
// её читают клейм дренажа, уборка доставленных и оживление отравленных, и ни
// одно поле контракта её не несёт. Соединить чтение с очередью ради показа
// «отправлено в …» НЕЛЬЗЯ: уборка снимает доставленную строку, поэтому пустое
// значение означало бы разом «ещё не сдано» и «сдано и убрано».
//
// Довод целиком, три читателя поимённо, границы и ВНЕШНИЙ предикат пересмотра —
// `docs/engineering/architecture/known-divergences.md`, §20. Держит решение гейт
// `internal/check` `TestSendTimeStaysQueueLivenessAndOffTheContract`.
package invite_mail_outbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/outbox"
)

const (
	// Table — полное имя очереди. Имя объявлено ЗДЕСЬ и у клиента-применителя
	// (clients.InviteMailTable); совпадение держит проба
	// TestInviteMailTableIsNamedOnce, а не соглашение.
	Table = "kaname.invite_mail_outbox"
	// EventSend — вид события приглашения; словарь закрыт CHECK'ом миграции.
	EventSend = "mail.invite.send"
	// EventRecoverySend — вид события письма восстановления (Ф5 Р3); заведён
	// миграцией `20260917015400_recovery_code_is_our_record`.
	EventRecoverySend = "mail.recovery.send"
	// EventVerificationSend — вид события письма подтверждения адреса
	// (kaname#456, Р8); заведён миграцией
	// `20260927190000_address_verification_is_our_verb`.
	EventVerificationSend = "mail.verification.send"
	// EventEmailChangeSend — вид события письма с кодом смены адреса на НОВЫЙ
	// адрес (kaname#635, Р7); заведён миграцией
	// `20261007150000_email_change_is_confirmed_from_the_new_address`.
	EventEmailChangeSend = "mail.email-change.send"
	// EventEmailChangedSend — вид события уведомления о смене адреса на
	// ПРЕЖНИЙ адрес (kaname#635, Р7); заведён той же миграцией.
	EventEmailChangedSend = "mail.email-changed.send"
	// kind — resource_kind денормализованной колонки приглашения.
	kind = "InviteMail"
	// recoveryKind — resource_kind письма восстановления.
	recoveryKind = "RecoveryMail"
	// verificationKind — resource_kind письма подтверждения адреса.
	verificationKind = "VerificationMail"
	// emailChangeKind — resource_kind письма с кодом смены адреса.
	emailChangeKind = "EmailChangeMail"
	// emailChangedKind — resource_kind уведомления о смене адреса.
	emailChangedKind = "EmailChangedMail"
)

// EmitTx кладёт намерение отправить письмо приглашения на транзакцию
// вызывающего.
//
// userID служит и денормализованной координатой, и КЛЮЧОМ ПАРТИЦИИ порядка:
// письма одному человеку уходят в том порядке, в котором их поставили. Пустой
// ключ отвергается здесь и ограничением миграции — предикат один на обе стороны,
// потому что разойдясь, они разойдутся ровно там, где расхождение опасно.
//
// Ссылки-предъявителя намерение не несёт (Р24): письмо приглашения даёт призыв и
// адрес страницы входа, а не доступ.
func EmitTx(ctx context.Context, tx pgx.Tx, userID, accountID, to, loginURL string) error {
	if tx == nil {
		return fmt.Errorf("invite_mail_outbox: tx must not be nil")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("invite_mail_outbox: recipient required — a letter to nobody has no subject")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invite_mail_outbox: user id required — it is the ordering partition key")
	}
	payload := map[string]any{
		"to":         to,
		"account_id": accountID,
		"user_id":    userID,
	}
	if loginURL != "" {
		payload["login_url"] = loginURL
	}
	if err := outbox.Emit(ctx, tx, Table, kind, userID, EventSend, payload); err != nil {
		return fmt.Errorf("invite_mail_outbox: emit %s: %w", EventSend, err)
	}
	return nil
}

// EmitRecoveryTx кладёт намерение отправить письмо восстановления на
// транзакцию вызывающего — ту же, что пишет строку кода (Ф5-09).
//
// Письмо НЕСЁТ предъявителя — код в форме для человека — потому что
// предъявитель и есть его предмет (Ф5 Р1). В строке очереди он лежит открытым до
// сдачи письма узлу; сданную строку снимает уборка. Срок называется письму в
// минутах: письмо говорит человеку, сколько код действует.
//
// userID — ключ партиции порядка, как у приглашения: письма одному человеку
// уходят в том порядке, в котором их поставили.
func EmitRecoveryTx(ctx context.Context, tx pgx.Tx, userID, accountID, to, code string, validFor time.Duration) error {
	if tx == nil {
		return fmt.Errorf("invite_mail_outbox: tx must not be nil")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("invite_mail_outbox: recipient required — a letter to nobody has no subject")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invite_mail_outbox: user id required — it is the ordering partition key")
	}
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("invite_mail_outbox: recovery code required — a recovery letter without a bearer recovers nothing")
	}
	minutes := int(validFor / time.Minute)
	if minutes <= 0 && validFor > 0 {
		minutes = 1
	}
	payload := map[string]any{
		"to":                 to,
		"account_id":         accountID,
		"user_id":            userID,
		"code":               code,
		"code_valid_minutes": minutes,
	}
	if err := outbox.Emit(ctx, tx, Table, recoveryKind, userID, EventRecoverySend, payload); err != nil {
		return fmt.Errorf("invite_mail_outbox: emit %s: %w", EventRecoverySend, err)
	}
	return nil
}

// EmitVerificationTx кладёт намерение отправить письмо подтверждения адреса на
// транзакцию вызывающего — ту же, что пишет строку кода (kaname#456, Р8, Р9).
//
// Письмо НЕСЁТ предъявителя — код в форме для человека: предъявитель и есть его
// предмет (тот же размен, что у восстановления). Адреса экрана подтверждения
// намерение не несёт: его собирает применитель из адреса консоли, объявленного
// настройкой установки, — строка очереди не становится вторым местом этой
// величины. Кода в адресе нет по построению: адрес ведёт на экран, код вводится
// руками.
//
// userID — ключ партиции порядка, как у прочих видов.
func EmitVerificationTx(ctx context.Context, tx pgx.Tx, userID, accountID, to, code string, validFor time.Duration) error {
	if tx == nil {
		return fmt.Errorf("invite_mail_outbox: tx must not be nil")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("invite_mail_outbox: recipient required — a letter to nobody has no subject")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invite_mail_outbox: user id required — it is the ordering partition key")
	}
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("invite_mail_outbox: verification code required — a verification letter without a code confirms nothing")
	}
	minutes := int(validFor / time.Minute)
	if minutes <= 0 && validFor > 0 {
		minutes = 1
	}
	payload := map[string]any{
		"to":                 to,
		"account_id":         accountID,
		"user_id":            userID,
		"code":               code,
		"code_valid_minutes": minutes,
	}
	if err := outbox.Emit(ctx, tx, Table, verificationKind, userID, EventVerificationSend, payload); err != nil {
		return fmt.Errorf("invite_mail_outbox: emit %s: %w", EventVerificationSend, err)
	}
	return nil
}

// EmitEmailChangeTx кладёт намерение отправить письмо с кодом смены адреса на
// НОВЫЙ адрес на транзакцию вызывающего — ту же, что пишет строку отложенной
// смены (kaname#635, Р7).
//
// Письмо НЕСЁТ предъявителя — код в форме для человека: предъявитель и есть его
// предмет (тот же размен, что у подтверждения адреса). Адрес экрана параметров
// консоли собирает применитель из адреса консоли, объявленного настройкой
// установки; ссылки-предъявителя нет по построению.
//
// userID — ключ партиции порядка, как у прочих видов.
func EmitEmailChangeTx(ctx context.Context, tx pgx.Tx, userID, accountID, to, code string, validFor time.Duration) error {
	if tx == nil {
		return fmt.Errorf("invite_mail_outbox: tx must not be nil")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("invite_mail_outbox: recipient required — a letter to nobody has no subject")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invite_mail_outbox: user id required — it is the ordering partition key")
	}
	if strings.TrimSpace(code) == "" {
		return fmt.Errorf("invite_mail_outbox: email change code required — a change letter without a code confirms nothing")
	}
	minutes := int(validFor / time.Minute)
	if minutes <= 0 && validFor > 0 {
		minutes = 1
	}
	payload := map[string]any{
		"to":                 to,
		"account_id":         accountID,
		"user_id":            userID,
		"code":               code,
		"code_valid_minutes": minutes,
	}
	if err := outbox.Emit(ctx, tx, Table, emailChangeKind, userID, EventEmailChangeSend, payload); err != nil {
		return fmt.Errorf("invite_mail_outbox: emit %s: %w", EventEmailChangeSend, err)
	}
	return nil
}

// EmitEmailChangedTx кладёт намерение уведомить ПРЕЖНИЙ адрес о смене на
// транзакцию исхода смены (kaname#635, Р7, Р8 п. 6).
//
// Уведомление несёт момент смены — и ничего сверх: ни нового адреса (прежний
// ящик мог оказаться в чужих руках, и новый адрес выдал бы, где теперь учётная
// запись), ни кода, ни ссылки.
func EmitEmailChangedTx(ctx context.Context, tx pgx.Tx, userID, accountID, to string, changedAt time.Time) error {
	if tx == nil {
		return fmt.Errorf("invite_mail_outbox: tx must not be nil")
	}
	if strings.TrimSpace(to) == "" {
		return fmt.Errorf("invite_mail_outbox: recipient required — a letter to nobody has no subject")
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invite_mail_outbox: user id required — it is the ordering partition key")
	}
	if changedAt.IsZero() {
		return fmt.Errorf("invite_mail_outbox: change moment required — the notice names when the address changed")
	}
	payload := map[string]any{
		"to":         to,
		"account_id": accountID,
		"user_id":    userID,
		"changed_at": changedAt.UTC().Truncate(time.Second).Format(time.RFC3339),
	}
	if err := outbox.Emit(ctx, tx, Table, emailChangedKind, userID, EventEmailChangedSend, payload); err != nil {
		return fmt.Errorf("invite_mail_outbox: emit %s: %w", EventEmailChangedSend, err)
	}
	return nil
}

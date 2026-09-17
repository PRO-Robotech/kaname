// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package invite_mail_outbox — writer намерения отправить письмо в
// `kaname.invite_mail_outbox`: приглашение (ID-MAIL-1) и, с фазы Ф5, код
// восстановления доступа (`kacho#1271`, Р3 — второй вид в ТОЙ ЖЕ очереди).
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
	// kind — resource_kind денормализованной колонки приглашения.
	kind = "InviteMail"
	// recoveryKind — resource_kind письма восстановления.
	recoveryKind = "RecoveryMail"
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

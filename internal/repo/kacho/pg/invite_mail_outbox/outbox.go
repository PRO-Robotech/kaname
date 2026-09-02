// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package invite_mail_outbox — writer намерения отправить письмо приглашения в
// `kacho_iam.invite_mail_outbox`.
//
// Намерение пишется В ТОЙ ЖЕ транзакции, что строка приглашения, и это несущее
// свойство, а не оптимизация: при откате приглашения намерения нет ВОВСЕ, а при
// состоявшемся приглашении оно переживает смерть процесса. Утверждать надо
// именно это — «событие эмитировано» есть утверждение о ВЫЗОВЕ, а не о свойстве,
// и остаётся зелёным на отправке письма о приглашении, которого не случилось.
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

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/outbox"
)

const (
	// Table — полное имя очереди. Имя объявлено ЗДЕСЬ и у клиента-применителя
	// (clients.InviteMailTable); совпадение держит проба
	// TestInviteMailTableIsNamedOnce, а не соглашение.
	Table = "kacho_iam.invite_mail_outbox"
	// EventSend — единственный вид события; словарь закрыт CHECK'ом миграции.
	EventSend = "mail.invite.send"
	// kind — resource_kind денормализованной колонки.
	kind = "InviteMail"
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

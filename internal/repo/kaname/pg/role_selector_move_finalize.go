// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5/pgconn"
)

// finalizePendingSelectorMove принимает решение той же RC-попытки. До выбора
// SQL-слота prepared writer доступен только внутренней проверке полного Grant.
func (w *preparedRoleWriteTx) finalizePendingSelectorMove(ctx context.Context, decision roleSelectorMoveAuthorizedChanges) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !w.liveRoleAttempt() || !w.canReadAccessLabelSource() || w.contentApprovalAttempted ||
		w.stage.selectorMove == nil || decision.changes.owner == nil || decision.changes.owner.move != w.stage.selectorMove {
		return kaname.ErrSourceUnconfirmed
	}
	sets, err := decision.pendingSourceInput(ctx, w.semanticAuthorityWriteTx)
	if err != nil {
		return err
	}
	// Проверяем rules и permissions из захваченной редакции и её проекции.
	// Попытка целиком откатывается при отказе любой страницы или области.
	w.contentApprovalAttempted = true
	if err := grantpolicy.RequireRole(ctx, w, w.stage.selectorMove.actor, w.stage.request.Role, false); err != nil {
		return err
	}
	budget := w.producerBudget
	rows, reads := budget.RemainingRows(), budget.RemainingReads()
	var receipt json.RawMessage
	err = w.tx.QueryRow(ctx, `SELECT kaname.authority_role_move_enrolled_finish_v1($1::jsonb,$2,$3)`, sets, rows, reads).Scan(&receipt)
	if err != nil {
		var pgerr *pgconn.PgError
		if errors.As(err, &pgerr) && pgerr.Code == "54000" {
			return errors.Join(kaname.ErrSourceReadLimit, err)
		}
		return err
	}
	if err := chargeSelectorMoveFinalizeReceipt(budget, receipt); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.selectorMoveFinalized = true
	return nil
}

// ConfirmPreparedSelectorMove подтверждает выбор слота в текущей попытке.
func (w *preparedRoleWriteTx) ConfirmPreparedSelectorMove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !w.liveRoleAttempt() || w.stage.selectorMove == nil || !w.selectorMoveFinalized || w.roleWriteStarted {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

// После выбора SQL владеет всем остатком для deferred replay. Оставить его
// в Go-бюджете означало бы второй раз разрешить те же строки и чтения.
func chargeSelectorMoveFinalizeReceipt(budget *relverdict.AdministrativeReadBudget, raw json.RawMessage) error {
	if budget == nil || len(raw) == 0 || len(raw) > 4096 {
		return kaname.ErrSourceUnconfirmed
	}
	var transport, phase, sourceHash, contentHash string
	var rows, reads, deferredRows, deferredReads int
	fields := map[string]any{
		"selector_move_transport": &transport, "phase": &phase,
		"source_sha256": &sourceHash, "content_sha256": &contentHash,
		"rows": &rows, "reads": &reads, "deferred_rows": &deferredRows, "deferred_reads": &deferredReads,
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := decoder.Token(); err != nil || tok != json.Delim('{') {
		return kaname.ErrSourceUnconfirmed
	}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || fields[name] == nil || decoder.Decode(fields[name]) != nil {
			return kaname.ErrSourceUnconfirmed
		}
		delete(fields, name)
	}
	if tok, err := decoder.Token(); err != nil || tok != json.Delim('}') || len(fields) != 0 {
		return kaname.ErrSourceUnconfirmed
	}
	if _, err := decoder.Token(); err != io.EOF || transport != pendingNoCopyPrepareTransport || phase != "selected" ||
		!accessLabelSourceDigest(sourceHash) || !accessLabelSourceDigest(contentHash) {
		return kaname.ErrSourceUnconfirmed
	}
	availableRows, availableReads := budget.RemainingRows(), budget.RemainingReads()
	// Finalize v1 списывает 5 фиксированных единиц и 4 непустые owner-фазы.
	// Publication v1 требует резерв как минимум 21 строку и 10 чтений.
	if rows < 9 || reads < 9 || deferredRows < 21 || deferredReads < 10 ||
		rows > availableRows || reads > availableReads ||
		deferredRows != availableRows-rows || deferredReads != availableReads-reads {
		return kaname.ErrSourceUnconfirmed
	}
	return chargeNativePolicyBudget(budget, availableRows, availableReads)
}

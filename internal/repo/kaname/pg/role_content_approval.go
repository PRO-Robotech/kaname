// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type roleAccessLabelMode string

const (
	roleAccessLabelOrdinary roleAccessLabelMode = "ordinary"
	roleAccessLabelApply    roleAccessLabelMode = "apply"
	roleAccessLabelRevoke   roleAccessLabelMode = "revoke"
	roleContentApprovedSQL                      = `SELECT kaname.authority_role_access_label_content_approved_v1()`
)

func (mode roleAccessLabelMode) requireSupported() error {
	switch mode {
	case roleAccessLabelOrdinary, roleAccessLabelApply, roleAccessLabelRevoke:
		return nil
	default:
		// Нет поля, null, пустое или неизвестное значение не означает ordinary.
		return kaname.ErrSourceUnconfirmed
	}
}

// RecordRoleContentApproval вызывается внутренним UC только после успешного
// полного RequireRole и до body. SQL самостоятельно сверяет owner actor custody,
// frozen mutation, final clock и полную матрицу; этот вызов не разрешает apply.
func (w *preparedRoleWriteTx) RecordRoleContentApproval(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if w == nil || w.stage == nil || w.semanticAuthorityWriteTx == nil ||
		w.authorityWriteTx == nil || w.writeTx == nil || w.tx == nil || w.closed ||
		w.roleWriteStarted || w.applied || w.contentApprovalAttempted {
		return kaname.ErrSourceUnconfirmed
	}
	if err := w.stage.accessLabelMode.requireSupported(); err != nil {
		return err
	}
	if w.stage.accessLabelMode == roleAccessLabelOrdinary {
		return nil
	}
	if !w.canReadAccessLabelSource() || w.conn == nil || w.fence.decisionAt.IsZero() ||
		(!w.stage.request.Create && !w.stage.request.Rules) ||
		(w.stage.accessLabelMode == roleAccessLabelRevoke &&
			(w.stage.request.Create || !w.stage.request.Update || !w.stage.request.Rules)) {
		return kaname.ErrSourceUnconfirmed
	}
	// Один SQL-вызов, фиксированная conservative стоимость owner helper.
	// SQL не списывает эти же 8 rows / 4 reads повторно.
	if err := chargeNativePolicyBudget(w.stage.plan.nativeBudget, 8, 4); err != nil {
		return err
	}
	// Не повторяем подтверждение на том же writer даже после ошибки backend.
	// Общий retry создаёт новую транзакцию и заново выполняет весь RequireRole.
	w.contentApprovalAttempted = true
	_, err := w.tx.Exec(ctx, roleContentApprovedSQL)
	if err == nil {
		w.contentApprovalRecorded = true
	}
	return err
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

import (
	"context"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// WithAdminTxBeginner вызывается только при сборке до публикации Handler.
// Оба transport используют эти же UC. Явный nil запрещает mutation, а не
// возвращает прежний beginner; отсутствие вызова сохраняет прежнюю сборку.
func (h *Handler) WithAdminTxBeginner(txb service.TxBeginner) *Handler {
	if txb == nil {
		txb = unavailableAdminTxBeginner{}
	}
	if h.grant != nil {
		h.grant.txb = txb
	}
	if h.revoke != nil {
		h.revoke.txb = txb
	}
	return h
}

type unavailableAdminTxBeginner struct{}

func (unavailableAdminTxBeginner) Begin(context.Context) (service.Tx, error) {
	return nil, iamerr.Wrapf(iamerr.ErrUnavailable, "cluster admin participant is not configured")
}

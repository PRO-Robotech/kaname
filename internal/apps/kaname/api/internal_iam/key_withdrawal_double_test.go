// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"sync"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// recordingWithdrawal — дублёр порта отзыва по снятию регистрации (kaname#963):
// запоминает ключи, по которым его позвали. Проб use-case с поддельной
// транзакцией хранилище отзыва не касается — его держат пробы мира У на
// настоящей базе (`access_binding/unregister_revokes_grants_world_integration_test.go`).
type recordingWithdrawal struct {
	mu   sync.Mutex
	keys []domain.ResourceRef
}

// LockTx — замок выдач и ролей ключа (kaname#975): поддельной транзакции запирать
// нечего.
func (r *recordingWithdrawal) LockTx(context.Context, service.Tx, domain.ResourceRef) error {
	return nil
}

func (r *recordingWithdrawal) WithdrawTx(_ context.Context, _ service.Tx, key domain.ResourceRef, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	return nil
}

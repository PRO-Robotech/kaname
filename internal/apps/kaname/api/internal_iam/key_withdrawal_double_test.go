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
	mu     sync.Mutex
	keys   []domain.ResourceRef
	locked [][]domain.ResourceRef
	// onLock — снимок состояния соседних дублёров в момент замка (kaname#1019):
	// проба порядка родов спрашивает, что успело случиться ДО него.
	onLock func(keys []domain.ResourceRef)
}

// LockTx — замок выдач и ролей ключей (kaname#975, kaname#1019): поддельной
// транзакции запирать нечего, набор ключей запоминается.
func (r *recordingWithdrawal) LockTx(_ context.Context, _ service.Tx, keys []domain.ResourceRef) error {
	r.mu.Lock()
	r.locked = append(r.locked, append([]domain.ResourceRef(nil), keys...))
	hook := r.onLock
	r.mu.Unlock()
	if hook != nil {
		hook(keys)
	}
	return nil
}

func (r *recordingWithdrawal) WithdrawTx(_ context.Context, _ service.Tx, key domain.ResourceRef, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = append(r.keys, key)
	return nil
}

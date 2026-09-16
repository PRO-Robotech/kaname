// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate_fakes_test.go — общие дублёры проб стража сверки.
//
// Они жили в пробе загрузочной дымовой пробы; та снята вместе со своим предметом
// (#119), а дублёры пережили её, потому что ими пользуются соседние пробы. Файл
// без своих утверждений заведён намеренно: оставить их в снятой пробе значило бы
// держать пробу ради её фикстуры.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// stubVerifyStore — дублёр VerifyStore: всякий не объявленный пробой вызов есть
// ошибка автора пробы, поэтому он паникует, а не отвечает нулём.
type stubVerifyStore struct{}

func (s stubVerifyStore) ListActiveBindingMaterialization(context.Context) ([]BindingMaterialization, error) {
	panic("ListActiveBindingMaterialization not expected")
}

func (s stubVerifyStore) ListOwnerBindingsMissingMembers(context.Context) ([]domain.AccessBindingID, error) {
	panic("ListOwnerBindingsMissingMembers not expected")
}

func (s stubVerifyStore) SeedSmokeMirrorObject(context.Context, string, string, string, string, map[string]string) error {
	panic("SeedSmokeMirrorObject not expected")
}

func (s stubVerifyStore) RemoveSmokeMirrorObject(context.Context, string, string) error {
	panic("RemoveSmokeMirrorObject not expected")
}

func (s stubVerifyStore) LedgerHasObject(context.Context, domain.AccessBindingID, string) (bool, error) {
	panic("LedgerHasObject not expected")
}

func (s stubVerifyStore) ListActiveBindingRelationChecks(context.Context) ([]BindingRelationCheck, error) {
	panic("ListActiveBindingRelationChecks not expected")
}

// panicEngine роняет пробу, если сведение вызвано там, где проба его не ждёт.
type panicEngine struct{}

func (panicEngine) ReconcileObject(context.Context, string, string) error {
	panic("ReconcileObject not expected")
}

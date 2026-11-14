// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// BindingDecisionRunner держит полный OLD/NEW source footprint и принимает
// решение до mutation. kaname#1034: callback не вызывает Commit/Rollback;
// повторяемая попытка целиком откатывается и заново читает snapshot.
// Tuples — прежний чистый emitter builder, не разрешение/источник authority.
type BindingDecisionRunner interface {
	RunBindingDecision(context.Context, domain.Subject, domain.AccessBinding, bool,
		func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
		func(context.Context, SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error
}

// BindingCapabilityWriter отмечает протокол фактического порта записи привязок.
// Его Insert повышает версию только у созданной строки в той же транзакции.
// Версия не заменяет проверку полномочий: владелец операции проходит полный
// policy gate до вставки и сохраняет ведомость выпущенных кортежей после неё.
type BindingCapabilityWriter interface {
	ab.WriterIface
	BindingCapabilityVersion() int
}

// DelegatedBindingDecisionRunner сохраняет выбранный GD ID через whole-TX retry.
// Это отдельный путь kaname#986: обычный gate не становится всеразрешающим fallback.
// Callback проверяет оси и живое право creator до вставки, на том же writer.
type DelegatedBindingDecisionRunner interface {
	RunDelegatedBindingDecision(context.Context, domain.Subject, domain.AccessBinding,
		func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
		func(context.Context, SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error
}

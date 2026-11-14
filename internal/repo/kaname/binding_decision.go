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

// BindingCapabilityInserter создаёт новую строку; существующий carrier этим
// портом не повышается. Вызывает только Create ПОСЛЕ полного policy gate.
type BindingCapabilityInserter interface {
	InsertBindingWithCapabilities(context.Context, domain.AccessBinding) (domain.AccessBinding, error)
}

// DelegatedBindingDecisionRunner сохраняет выбранный GD ID через whole-TX retry.
// Это отдельный путь kaname#986: обычный gate не становится всеразрешающим fallback.
// Callback проверяет оси и живое право creator до вставки, на том же writer.
type DelegatedBindingDecisionRunner interface {
	RunDelegatedBindingDecision(context.Context, domain.Subject, domain.AccessBinding,
		func(domain.AccessBinding, domain.Role) []ab.RelationTuple,
		func(context.Context, SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error
}

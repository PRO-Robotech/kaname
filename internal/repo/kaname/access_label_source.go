// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

// AccessLabelSourceCandidate хранит вопрос к прежнему источнику, НЕ proof allow.
// Checkpoint вычислительный: writer отдельно подтверждает held source identity.
type AccessLabelSourceCandidate struct {
	Binding         domain.AccessBinding
	BindingSnapshot CapturedAccessLabelBindingSource
	RoleSnapshot    RoleProjectionSourceSnapshot
	BindingID       domain.AccessBindingID
	Recipient       domain.Subject
	RoleID          domain.RoleID
	Checkpoint      granteffect.ProjectionCheckpoint
	Provenance      granteffect.Provenance
	Scope           domain.ScopeAnchor
	DefinitionID    domain.AccessLabelDefinitionID
}

// Минимальная стоимость включает сверку OLD и резерв на подтверждение
// положительного ответа в закрытом хранилище текущей транзакции.
const (
	AccessLabelSourceMinimumRows = 17
	AccessLabelSourceReads       = 10
)

// Порт реализует только тот же coordinated writer. Он сверяет actor, final clock,
// объявленный exact question, held binding/role/group/definition и checkpoint.
// SQL читает максимум оставшегося общего бюджета + sentinel; cost включает
// отрицательный результат и ошибку. Caller начисляет его ровно один раз.
// Положительный результат отмечает только точку, вычисленную владельцем
// транзакции. Итоговый допуск на запись роли требует отдельного решения.
type AccessLabelSourceReader interface {
	SemanticAuthorityWriter
	CheckAccessLabelSource(context.Context, domain.Subject, time.Time, AccessLabelSourceCandidate) (bool, SourceReadCost, error)
	ChargeSourceRead(SourceReadCost) error
}

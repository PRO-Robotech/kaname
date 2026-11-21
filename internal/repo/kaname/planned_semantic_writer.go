// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"errors"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

var ErrSemanticReadPlanRequired = errors.New("explicit semantic source read plan required")

// Read intent перечисляет вопросы вызывающего, но не передаёт guard keys,
// population token или утверждение полноты. Их строит репозиторий в RR.
type SemanticReadIntent struct {
	Actor  domain.Subject
	Native []SemanticNativeQuestion
	Roles  []domain.RoleID
}
type SemanticNativeQuestion struct{ Relation, Object string }

// Entry-only writer сравнивает bundle и protocol, но не выдаёт semantic checker
// либо producer capability. Он пригоден для явного участия существующего writer.
type EntryAuthorityWriter interface {
	AuthorityWriter
	SemanticBundle() *granteffect.Bundle
}
type PlannedSemanticAuthorityWriterFactory interface {
	PlannedSemanticAuthorityWriter(context.Context, AuthorityFencePlan, *granteffect.Bundle, SemanticReadIntent) (SemanticAuthorityWriter, error)
	PlannedSemanticPopulationWriter(context.Context, AuthorityFencePlan, *granteffect.Bundle, []SemanticReadIntent) (SemanticAuthorityWriter, error)
	PreparedAuthorityDecisionWriter(context.Context, AuthorityWriteIntent, SemanticReadIntent) (SemanticAuthorityWriter, error)
	CoordinatedEntryWriter(context.Context, AuthorityWriteIntent) (EntryAuthorityWriter, error)
}

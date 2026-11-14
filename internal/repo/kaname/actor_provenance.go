// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

var ErrSourceUnconfirmed = errors.New("actor source provenance unconfirmed")
var ErrSourceReadLimit = errors.New("actor provenance read limit")

// SourceReadCost учитывает прочитанные строки, metadata и чтения.
// Для joins допустима консервативная верхняя граница, но не бесплатные строки.
type SourceReadCost struct{ Rows, Reads int }
type ProducerSource struct {
	Receipt     domain.ProducerReceipt
	Versionless bool
	Identity    grantcoverage.Identity
	// Непустой Issue оставляет источник явным недоказанным компонентом.
	Issue string
}
type ProducerSourcePage struct {
	Sources []ProducerSource
	Cost    SourceReadCost
}

// SemanticSourceReader реализуется тем же semantic writer. Эти методы не
// активируют протокол и не превращают NULL identity receipt в persistent proof.
type SemanticSourceReader interface {
	SemanticAuthorityWriter
	AdmitSourceActor(context.Context, domain.Subject) (SourceReadCost, error)
	ProducerSources(context.Context, CanonicalSourceFilter) (ProducerSourcePage, string, error)
	RoleProjectionCheckpoint(context.Context, domain.RoleID) (granteffect.ProjectionCheckpoint, SourceReadCost, error)
}

// CapturedProducerPopulation — выходное свидетельство одного защищённого писателя,
// а не переданный вызывающим флаг Complete. Ненулевая запись указывает, что перечитана только
// захваченная RR-популяция: она НЕ удостоверяет текущую популяцию.
// Реализации обязаны отвергать другого actor, другую попытку, writer или часы решения.
type CapturedProducerPopulation interface {
	Validate(SemanticAuthorityWriter, domain.Subject, time.Time) error
}
type CapturedProducerPopulationReader interface {
	CapturedProducerPopulation(context.Context, domain.Subject) (CapturedProducerPopulation, error)
}

// Недостаточные захваченные положительные свидетельства означают Unknown, а не отсутствие полномочий.
// Существующие исполнители целых попыток распознают маркер классификации и ограничивают повторы.
var ErrCapturedProducerInsufficient = fmt.Errorf("captured producer lower bound insufficient: %w", ErrAuthorityClassificationChanged)

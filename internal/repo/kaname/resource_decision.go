// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"fmt"
	"maps"
	"slices"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// ErrAccessLabelReconcilePending означает, что наблюдаемое поколение отзыва ещё открыто.
// Очередь повторяет работу отдельной попыткой и сохраняет неснятое событие.
var ErrAccessLabelReconcilePending = fmt.Errorf("access label generation still pending: %w", iamerr.ErrUnavailable)

// ResourceDecisionAction задаёт закрытый сценарий, а не произвольный TX callback.
// Все prepared rows, источники и effect footprint вычисляет доверенный runner.
type ResourceDecisionAction uint8

const (
	ResourceDecisionRegister ResourceDecisionAction = iota + 1
	ResourceDecisionUnregister
	ResourceDecisionPublish
	ResourceDecisionUnpublish
	ResourceDecisionRecordRefusal
)

type ResourceRefusalOutcome string

const (
	ResourceRefusalPermissionDenied   ResourceRefusalOutcome = "permission_denied"
	ResourceRefusalFailedPrecondition ResourceRefusalOutcome = "failed_precondition"
)

// Intent содержит только доставленное намерение. Scope claims не становятся
// каноническими аккаунтами, а subject не определяет личность module SA.
// Версия доставки находится в Mirror.SourceVersion; ноль сохраняет legacy смысл.
// Отказный action может лишь записать аудит уже отвергнутого запроса.
type ResourceDecisionIntent struct {
	Action            ResourceDecisionAction
	Tuple             outboxtypes.RelationTuple
	Mirror            outboxtypes.ResourceMirrorRow
	RefusalOutcome    ResourceRefusalOutcome
	RefusalUnregister bool
}

// Snapshot отделяет повторяемую попытку от изменяемых slice/map входа.
// Это копия намерения, не свидетельство допуска или полной классификации.
func (in ResourceDecisionIntent) Snapshot() ResourceDecisionIntent {
	in.Mirror.ParentChain = slices.Clone(in.Mirror.ParentChain)
	in.Mirror.Labels = maps.Clone(in.Mirror.Labels)
	return in
}

type ResourceDecisionResult struct {
	CatalogType         string
	Changed             bool
	ProjectionUnchanged bool
}

// Caller не может передать подготовленные источники, complete-флаг или body.
// Runner владеет RR/RC, closed manifest, проверками и общим Commit/retry budget.
// App setter использует этот нейтральный порт без зависимости PG от API пакета.
type ResourceDecisionRunner interface {
	RunResourceDecision(context.Context, ResourceDecisionIntent) (ResourceDecisionResult, error)
}

// Структурный отказ входа сохраняет прежние field details на app boundary.
// Репозиторий не импортирует API пакет и не раскрывает ошибки SQL этим типом.
type ResourceDecisionFieldError struct{ Field, Description string }

func (e *ResourceDecisionFieldError) Error() string {
	if e == nil {
		return "invalid resource decision input"
	}
	return e.Description
}

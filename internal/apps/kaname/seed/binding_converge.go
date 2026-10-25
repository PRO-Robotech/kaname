// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

import (
	"context"
	"time"
)

// Исходы сведения одной выдачи — закрытый набор.
const (
	// BindingConvergeOutcomeConverged — выдача сведена.
	BindingConvergeOutcomeConverged = "converged"
	// BindingConvergeOutcomeFailed — выдача не сведена.
	BindingConvergeOutcomeFailed = "failed"
)

// BindingConvergeObserver — куда проход сообщает исход по каждой выдаче.
type BindingConvergeObserver interface {
	IncBindingConverge(outcome string)
}

// convergeOn — заготовка красной пробы.
func (r *BackfillRunner) convergeOn(ctx context.Context, _ <-chan time.Time) {
	<-ctx.Done()
}

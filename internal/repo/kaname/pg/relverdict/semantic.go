// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/jackc/pgx/v5"
)

// PlanSource — только чтение планов, без mutable Model(). Реализация immutable
// bundle отдаёт собственные копии срезов; прежний *Plans сохраняет старый API.
type PlanSource interface {
	Plan(string, string) (authzplan.Plan, error)
	GrantCapabilityPlan(string, string) error
}

// NewSemanticTransactionAsker использует планы и время переданного writer.
// Он не подменяет их Shared и не открывает дополнительную транзакцию.
func NewSemanticTransactionAsker(tx pgx.Tx, plans PlanSource, decisionAt time.Time) *Asker {
	if tx == nil || plans == nil || decisionAt.IsZero() {
		return nil
	}
	return &Asker{transaction: tx, preparedPlans: plans, decisionAt: decisionAt}
}

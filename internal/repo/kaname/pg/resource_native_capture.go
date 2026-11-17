// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Здесь захватываются только фактические вопросы account#fga_writer для OLD+NEW
// владельцев регистрации. Это не D1, не census producer receipts актора и не
// основание добавить домашний аккаунт module SA в mutation footprint.
type resourceNativeCapture struct {
	lifetime *resourceAttemptLifetime
	boundary *nativeReadBoundary
	budget   *relverdict.AdministrativeReadBudget
	guards   []string
	epochs   json.RawMessage
}

func (r *ResourceDecisionRunner) captureRegistrationNative(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime, module resourceModuleIdentity, accounts []domain.AccountID, budget *relverdict.AdministrativeReadBudget) (*resourceNativeCapture, error) {
	if r == nil || r.bundle == nil || tx == nil || lifetime == nil || lifetime.ended || lifetime.prepared != nil || tx.Conn() != lifetime.conn || lifetime.bundle != r.bundle || budget == nil || !module.valid() || len(accounts) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	questions, err := resourceRegistrationQuestions(module.serviceName, accounts)
	if err != nil {
		return nil, err
	}
	boundary, err := captureNativeReadBoundary(ctx, r.bundle, questions, nativePolicyReadSnapshot{tx}, &nativeReadBudget{shared: budget})
	if err != nil {
		return nil, err
	}
	// Полный fallback означал бы другую authority/read-set семантику. В этом
	// закрытом сценарии неизвестная native форма требует явной доработки, а не
	// расширения чтения до всех источников service account.
	if boundary == nil || boundary.global() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	guards := boundary.guardKeys()
	if len(guards) == 0 || len(guards) > policyDiscoveryGuards {
		return nil, kaname.ErrSourceReadLimit
	}
	if err = chargeNativePolicyBudget(budget, len(guards), 1); err != nil {
		return nil, err
	}
	captured := &resourceNativeCapture{lifetime: lifetime, boundary: boundary, budget: budget, guards: guards}
	if err = tx.QueryRow(ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, guards).Scan(&captured.epochs); err != nil {
		return nil, err
	}
	if len(captured.epochs) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return captured, nil
}

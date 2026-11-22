// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type childAuthorizationObservedTx struct {
	pgx.Tx
	queries *[]string
}

func (t childAuthorizationObservedTx) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	*t.queries = append(*t.queries, sql)
	return t.Tx.QueryRow(ctx, sql, args...)
}

func (t childAuthorizationObservedTx) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	*t.queries = append(*t.queries, sql)
	return t.Tx.Query(ctx, sql, args...)
}

// Адаптер наблюдает SQL публичной предварительной проверки на снимке RR.
func ProbeUserChildAuthorization(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, input kaname.UserChildRegistrationInput, principal operations.Principal) (target domain.UserChildRegistrationTarget, guards, queries []string, err error) {
	lifetime, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	if err != nil {
		return target, nil, nil, err
	}
	defer lifetime.close()
	observed := childAuthorizationObservedTx{Tx: tx, queries: &queries}
	runner := &ResourceDecisionRunner{bundle: bundle}
	captured, err := runner.captureUserChildAuthorization(ctx, observed, lifetime, input, principal, &relverdict.AdministrativeReadBudget{})
	if err != nil {
		return target, nil, queries, err
	}
	return captured.target, captured.native.guards, queries, nil
}

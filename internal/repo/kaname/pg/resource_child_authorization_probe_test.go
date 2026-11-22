// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
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

// Проверяет тот же snapshot source verifier, что и предварительный child допуск.
// Отдельный вход позволяет проверить role-backed admin без объявления admin
// допустимым child action: его план не является единственным прямым атомом.
func ProbeSnapshotAdministrativeCheck(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, subject, relation, object string) (allowed bool, queries []string, err error) {
	observed := childAuthorizationObservedTx{Tx: tx, queries: &queries}
	var at time.Time
	if err = observed.QueryRow(ctx, `SELECT transaction_timestamp() WHERE current_setting('transaction_isolation')='repeatable read' AND current_setting('transaction_read_only')='on'`).Scan(&at); err != nil {
		return false, queries, err
	}
	sources := &nativeAdministrativeSources{snapshot: observed, snapshotAt: at, bundle: bundle}
	form := relverdict.NewAdministrativeAsker(observed, bundle, func() time.Time { return at }, sources.verify)
	form.BindReadBudget(&relverdict.AdministrativeReadBudget{})
	allowed, err = authzcascade.WrapAdmitted(form, personmarks.NewTransaction(observed)).Check(ctx, subject, relation, object)
	if errors.Is(err, relverdict.ErrAdministrativeSourceUnconfirmed) {
		err = kaname.ErrSourceUnconfirmed
	}
	if errors.Is(err, relverdict.ErrAdministrativeSourceLimit) {
		err = kaname.ErrSourceReadLimit
	}
	return allowed, queries, err
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Человек передаёт только координату. Один lease держит RR, RC и Commit;
// повтор начинается после rollback и Release с тем же общим бюджетом чтений.
func (r *ResourceDecisionRunner) RunUserChildRegistration(ctx context.Context, input kaname.UserChildRegistrationInput, principal operations.Principal) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	verified, ok := operations.PrincipalFromContextOK(ctx)
	_, named := authzguard.SubjectFromPrincipal(verified)
	if !ok || !named || verified.Type != "user" || verified.IsAnonymous() || verified != principal ||
		input.ResourceType == "" || input.ResourceID == "" {
		return time.Time{}, domain.ErrUserChildRegistrationRefused
	}
	if r == nil || r.repo == nil || r.repo.master == nil || r.bundle == nil {
		return time.Time{}, resourceChildError(ctx, kaname.ErrSourceUnconfirmed)
	}
	// Эта полоса существует только под FULL: отсутствие startup contract
	// не разрешает enterResource выбрать прежний v2-вход.
	if r.repo.fullContract == nil || !r.repo.fullContractMatches(r.bundle) {
		return time.Time{}, resourceChildError(ctx, kaname.ErrSemanticIdentityUnavailable)
	}
	budget := &relverdict.AdministrativeReadBudget{}
	version, err := runResourceAttempts(ctx, func() (time.Time, error) {
		lease, err := r.repo.master.Acquire(ctx)
		if err != nil {
			return time.Time{}, resourceOpenError(ctx, err)
		}
		defer lease.Release()
		return r.runUserChildRegistrationOnce(ctx, lease.Conn(), input, principal, budget)
	})
	if err != nil {
		return time.Time{}, resourceChildError(ctx, err)
	}
	return version, nil
}

func (r *ResourceDecisionRunner) runUserChildRegistrationOnce(ctx context.Context, conn *pgx.Conn, input kaname.UserChildRegistrationInput,
	principal operations.Principal, budget *relverdict.AdministrativeReadBudget,
) (version time.Time, err error) {
	lifetime, err := newResourceAttemptLifetime(conn, r.bundle)
	if err != nil {
		return time.Time{}, err
	}
	var active pgx.Tx
	commitStarted := false
	defer func() {
		lifetime.close()
		if active == nil {
			return
		}
		cleanup := rollbackResourceAttempt(ctx, active)
		if err == nil {
			err = cleanup
		} else {
			err = resourceFailedAttempt(err, cleanup, commitStarted)
		}
		if err != nil {
			version = time.Time{}
		}
	}()
	if budget == nil {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return time.Time{}, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rr
	stage, err := r.stageUserChildRegistration(ctx, rr, lifetime, input, principal, budget)
	if err != nil {
		return time.Time{}, err
	}
	if stage == nil {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	// Только подтверждённое отсутствие после допуска даёт предметный отказ.
	// Ошибка чтения выше не превращается в отсутствие родителя.
	if !stage.parentRegistered {
		return time.Time{}, domain.ErrUserChildRegistrationRefused
	}
	proposal, err := stage.proposal()
	if err != nil {
		return time.Time{}, err
	}
	if err = stage.source.seal(); err != nil {
		return time.Time{}, err
	}
	if err = rollbackResourceAttempt(ctx, rr); err != nil {
		return time.Time{}, err
	}
	active = nil
	if err = ctx.Err(); err != nil {
		return time.Time{}, err
	}

	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return time.Time{}, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rc
	writer, err := r.enterResource(ctx, rc, lifetime, *stage.footprint)
	if err != nil {
		return time.Time{}, err
	}
	if err = proposal.prewait(ctx, writer, budget); err != nil {
		return time.Time{}, err
	}
	if err = stage.source.recheck(ctx, writer); err != nil {
		return time.Time{}, err
	}
	if err = proposal.recheckCatalogs(ctx, writer, stage.parents); err != nil {
		return time.Time{}, err
	}
	if err = proposal.finalize(ctx, writer, lifetime, budget); err != nil {
		return time.Time{}, err
	}
	decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}
	// Тело само повторяет точный вопрос о праве непосредственно перед входом.
	version, err = stage.applyChildBody(ctx, decision, proposal)
	if err != nil {
		return time.Time{}, err
	}
	if version.IsZero() {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	if err = ctx.Err(); err != nil {
		return time.Time{}, err
	}
	commitStarted = true
	if err = decision.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	active = nil
	return version, nil
}

// Перевод выполняется после whole-attempt retry: SQLSTATE и cleanup cause
// сохраняются для классификации. Ошибка протокола не означает отказ в праве.
func resourceChildError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if canceled := ctx.Err(); canceled != nil {
		return errors.Join(canceled, err)
	}
	var failed *resourceAttemptError
	if errors.As(err, &failed) && failed.cleanup != nil {
		return errors.Join(iamerr.ErrUnavailable, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, domain.ErrUserChildRegistrationRefused) || errors.Is(err, iamerr.ErrAborted) {
		return err
	}
	if errors.Is(err, kaname.ErrSourceUnconfirmed) || errors.Is(err, kaname.ErrSourceReadLimit) ||
		errors.Is(err, kaname.ErrSemanticIdentityUnavailable) ||
		errors.Is(err, relverdict.ErrAdministrativeSourceUnconfirmed) || errors.Is(err, relverdict.ErrAdministrativeSourceLimit) {
		return errors.Join(iamerr.ErrUnavailable, err)
	}
	var pgerr *pgconn.PgError
	if errors.As(err, &pgerr) && pgerr.Code == "54000" {
		return errors.Join(iamerr.ErrUnavailable, err)
	}
	return errors.Join(mapErr(err, "", ""), err)
}

var _ kaname.UserChildRegistrationTransactions = (*ResourceDecisionRunner)(nil)

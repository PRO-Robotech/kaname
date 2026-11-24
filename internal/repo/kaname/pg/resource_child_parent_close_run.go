// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Одна попытка удерживает один lease от RR до Commit. FULL обязателен:
// прежний ресурсный dispatcher не должен трактовать close как удаление.
func (r *ResourceDecisionRunner) RunChildParentClose(ctx context.Context, input kaname.ChildParentCloseInput) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if r == nil || r.repo == nil || r.repo.master == nil || r.bundle == nil || r.facts == nil || r.gate == nil {
		return time.Time{}, resourceChildError(ctx, kaname.ErrSourceUnconfirmed)
	}
	if r.repo.fullContract == nil || !r.repo.fullContractMatches(r.bundle) {
		return time.Time{}, resourceChildError(ctx, kaname.ErrSemanticIdentityUnavailable)
	}
	budget := &relverdict.AdministrativeReadBudget{}
	closedAt, err := runResourceAttempts(ctx, func() (time.Time, error) {
		lease, err := r.repo.master.Acquire(ctx)
		if err != nil {
			return time.Time{}, resourceOpenError(ctx, err)
		}
		defer lease.Release()
		return r.runChildParentCloseOnce(ctx, lease.Conn(), input, budget)
	})
	if err != nil {
		var failed *resourceAttemptError
		if ctx.Err() == nil && status.Code(err) == codes.PermissionDenied &&
			(!errors.As(err, &failed) || failed.cleanup == nil) {
			return time.Time{}, authzguard.PermissionDenied()
		}
		return time.Time{}, resourceChildError(ctx, err)
	}
	return closedAt, nil
}

func (r *ResourceDecisionRunner) runChildParentCloseOnce(ctx context.Context, conn *pgx.Conn,
	input kaname.ChildParentCloseInput, budget *relverdict.AdministrativeReadBudget,
) (closedAt time.Time, err error) {
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
			closedAt = time.Time{}
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
	module, err := resourceIdentityFromGate(ctx, r.gate)
	if err != nil {
		return time.Time{}, err
	}
	stage, err := r.stageChildParentClose(ctx, rr, lifetime, module, input, budget)
	if err != nil {
		return time.Time{}, err
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
	writer, err := r.enterResource(ctx, rc, lifetime, stage.footprint)
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
		return time.Time{}, stage.authorization.finalAuthorityError(err)
	}
	decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}
	closedAt, err = stage.apply(ctx, decision, proposal, r.gate)
	if err != nil {
		return time.Time{}, err
	}
	if err = ctx.Err(); err != nil {
		return time.Time{}, err
	}
	commitStarted = true
	if err = decision.Commit(ctx); err != nil {
		return time.Time{}, err
	}
	active = nil
	return closedAt, nil
}

// Непосредственно перед закрытым SQL телом повторяем личность и installation
// допуск на окончательном времени. Сервер сравнивает exact intent с manifest.
func (s *resourceChildParentCloseStage) apply(ctx context.Context, tx *resourceDecisionTx,
	proposal *resourceDecisionProposal, gate *authzguard.RelationWriteGate,
) (time.Time, error) {
	if err := ctx.Err(); err != nil {
		return time.Time{}, err
	}
	if s == nil || s.source == nil || !s.source.sealed || s.authorization == nil ||
		s.authorization.source != s.source || s.authorization.native == nil || s.authorization.installation == nil ||
		s.authorization.native.lifetime != s.source.lifetime || s.authorization.installation.lifetime != s.source.lifetime ||
		s.source.lifetime == nil || tx == nil || tx.Tx == nil || tx.lifetime != s.source.lifetime ||
		tx.registrationBody != nil || !tx.lifetime.valid(tx.owner, tx.lifetime.bundle) || tx.Tx != tx.owner.tx ||
		proposal == nil || proposal.lifetime != tx.lifetime || proposal.prepared != tx.owner {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	var intent resourceChildParentCloseIntent
	if err := json.Unmarshal(proposal.intent, &intent); err != nil {
		return time.Time{}, err
	}
	if intent.Kind != "child_parent_close" || intent.ResourceType != s.input.ResourceType ||
		intent.ResourceType != s.catalog.identity.Dotted || intent.ResourceID != s.input.ResourceID ||
		!intent.SourceVersion.Equal(s.input.SourceVersion) || intent.Actor != s.module.actor || !nativeQuestionToken(intent.AuditID) {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	module, err := resourceIdentityFromGate(ctx, gate)
	if err != nil {
		return time.Time{}, err
	}
	if module != s.module {
		return time.Time{}, authzguard.PermissionDenied()
	}
	if err := s.authorization.authorize(ctx, gate, tx.owner); err != nil {
		return time.Time{}, err
	}
	var closedAt time.Time
	if err := tx.QueryRow(ctx, `SELECT kaname.authority_child_parent_close_apply_v1($1::jsonb)`, proposal.intent).Scan(&closedAt); err != nil {
		return time.Time{}, s.authorization.finalAuthorityError(err)
	}
	// Повтор возвращает прежнее время закрытия, а не новый DecisionAt.
	if closedAt.IsZero() || closedAt.Year() < 1 || closedAt.Year() > 9999 || closedAt.After(tx.lifetime.at) {
		return time.Time{}, kaname.ErrSourceUnconfirmed
	}
	return closedAt, nil
}

var _ kaname.ChildParentCloseTransactions = (*ResourceDecisionRunner)(nil)

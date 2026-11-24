// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// RunResourceDecision принимает только значение намерения. Lease принадлежит
// одной попытке: её RR, RC и Commit используют одно соединение. После rollback
// lease возвращается в pool до restage; ни gate, ни тело не открывают вторую TX.
func (r *ResourceDecisionRunner) RunResourceDecision(ctx context.Context, input kaname.ResourceDecisionIntent) (kaname.ResourceDecisionResult, error) {
	if err := ctx.Err(); err != nil {
		return kaname.ResourceDecisionResult{}, err
	}
	if r == nil || r.repo == nil || r.repo.master == nil || r.bundle == nil || r.gate == nil || r.facts == nil {
		return kaname.ResourceDecisionResult{}, kaname.ErrSourceUnconfirmed
	}
	if err := r.bundle.Validate(); err != nil {
		return kaname.ResourceDecisionResult{}, err
	}
	in := input.Snapshot()
	switch in.Action {
	case kaname.ResourceDecisionRegister, kaname.ResourceDecisionUnregister, kaname.ResourceDecisionPublish, kaname.ResourceDecisionUnpublish, kaname.ResourceDecisionRecordRefusal:
	default:
		return kaname.ResourceDecisionResult{}, kaname.ErrInvalidAuthorityFencePlan
	}
	// Исторический отказный audit не пишет событие от непроверенного module peer.
	if in.Action == kaname.ResourceDecisionRecordRefusal {
		if _, _, verified := authzguard.ModuleActor(ctx); !verified {
			return kaname.ResourceDecisionResult{}, nil
		}
	}
	budget := &relverdict.AdministrativeReadBudget{}
	return runResourceAttempts(ctx, func() (kaname.ResourceDecisionResult, error) {
		lease, err := r.repo.master.Acquire(ctx)
		if err != nil {
			return kaname.ResourceDecisionResult{}, resourceOpenError(ctx, err)
		}
		defer lease.Release()
		// runResourceDecisionOnce завершает bounded cleanup до возврата. Поэтому
		// следующий attempt начинается после Release даже при MaxConns=1.
		return r.runResourceDecisionOnce(ctx, lease.Conn(), in, budget)
	})
}

// Никакая ветвь после Begin не покидает функцию до bounded rollback либо
// успешного Commit. Маркер retry создаётся лишь после фактической очистки.
func (r *ResourceDecisionRunner) runResourceDecisionOnce(ctx context.Context, conn *pgx.Conn, in kaname.ResourceDecisionIntent, budget *relverdict.AdministrativeReadBudget) (result kaname.ResourceDecisionResult, err error) {
	lifetime, err := newResourceAttemptLifetime(conn, r.bundle)
	if err != nil {
		return result, err
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
			result = kaname.ResourceDecisionResult{}
		}
	}()

	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return result, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rr
	if budget == nil {
		return result, kaname.ErrSourceUnconfirmed
	}
	var module resourceModuleIdentity
	var registration *resourceRegistrationStage
	var refusal *resourceRefusalPreparation
	var parents *resourceParentCapture
	var source *resourceSourceCapture
	var footprint resourceFenceFootprint
	if in.Action == kaname.ResourceDecisionRecordRefusal {
		source, err = newResourceSourceCapture(rr, budget, lifetime)
		if err != nil {
			return result, err
		}
		parents, err = newResourceParentCapture(rr, source)
		if err != nil {
			return result, err
		}
		refusal, err = prepareResourceRefusal(ctx, parents, in)
		if err != nil {
			return result, err
		}
		// Отказ не является новой регистрацией. Неизвестный объект допускает только
		// audit-only GLOBAL manifest; он не даёт права менять authority rows.
		footprint = resourceFenceFootprint{plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	} else {
		module, err = resourceIdentityFromGate(ctx, r.gate)
		if err != nil {
			return result, err
		}
		registration, err = r.stageRegistration(ctx, rr, lifetime, module, in, budget)
		if err != nil {
			return result, err
		}
		parents, source, footprint = registration.registration.parents, registration.source, registration.footprint
	}
	var proposal *resourceDecisionProposal
	if refusal != nil {
		proposal, err = makeResourceRefusalProposal(in, parents, footprint, refusal)
	} else {
		proposal, err = makeResourceRegistrationProposal(in, parents, footprint, registration)
	}
	if err != nil {
		return result, err
	}
	if err = source.seal(); err != nil {
		return result, err
	}
	if err = rollbackResourceAttempt(ctx, rr); err != nil {
		return result, err
	}
	active = nil
	if err = ctx.Err(); err != nil {
		return result, err
	}

	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return result, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rc
	writer, err := r.enterResource(ctx, rc, lifetime, footprint)
	if err != nil {
		return result, err
	}
	// Сервер создаёт private manifest сам; JSON proposal не считается proof.
	// Все блокирующие шаги выполняются здесь до source recheck/final clock.
	if err = proposal.prewait(ctx, writer, budget); err != nil {
		return result, err
	}
	if err = source.recheck(ctx, writer); err != nil {
		return result, err
	}
	if err = proposal.recheckCatalogs(ctx, writer, parents); err != nil {
		return result, err
	}
	if err = proposal.finalize(ctx, writer, lifetime, budget); err != nil {
		return result, registration.finalAuthorityError(err)
	}
	decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}
	if registration != nil {
		if err = registration.authorize(ctx, r.gate, writer); err != nil {
			return result, err
		}
	}
	switch in.Action {
	case kaname.ResourceDecisionRegister:
		result, err = registration.registration.applyRegister(ctx, decision)
	case kaname.ResourceDecisionUnregister:
		result, err = registration.unregistration.apply(ctx, decision)
	case kaname.ResourceDecisionPublish, kaname.ResourceDecisionUnpublish:
		result, err = registration.registration.applyPublication(ctx, decision)
	case kaname.ResourceDecisionRecordRefusal:
		result, err = refusal.apply(ctx, decision)
	}
	if err != nil {
		return result, err
	}
	if err = ctx.Err(); err != nil {
		return result, err
	}
	commitStarted = true
	if err = decision.Commit(ctx); err != nil {
		return result, err
	}
	active = nil
	return result, nil
}

func rollbackResourceAttempt(ctx context.Context, tx pgx.Tx) error {
	if tx == nil {
		return nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Rollback(cleanup)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Checker использует ровно эту RC TX и окончательное время. Исходный gate
// сохраняет roster; чужие carrier accounts не превращаются в installation scope.
func (s *resourceRegistrationStage) authorize(ctx context.Context, gate *authzguard.RelationWriteGate, writer *authorityWriteTx) error {
	if s == nil || s.native == nil || s.installation == nil || gate == nil || !s.source.lifetime.valid(writer, s.source.lifetime.bundle) || len(s.footprint.registration) == 0 {
		return kaname.ErrSourceUnconfirmed
	}
	writer.nativeRead = &protectedNativeRead{boundary: s.native.boundary, budget: s.native.budget}
	checker := &resourceRegistrationChecker{capture: s.installation, writer: writer,
		native: newLiveAdministrativeChecker(writer, s.source.lifetime.bundle), at: writer.fence.decisionAt}
	bound := gate.BindRelationChecker(checker)
	for _, account := range s.footprint.registration {
		if err := bound.AuthorizeAccount(ctx, string(account)); err != nil {
			return err
		}
	}
	return ctx.Err()
}

var _ kaname.ResourceDecisionRunner = (*ResourceDecisionRunner)(nil)

// Ошибка открытия сохраняет context и исходный driver cause для диагностики,
// а публичная граница получает существующий SQLSTATE/Unavailable sentinel.
func resourceOpenError(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	if canceled := ctx.Err(); canceled != nil {
		return errors.Join(canceled, err)
	}
	return errors.Join(wrapPgErr(err, "", ""), err)
}

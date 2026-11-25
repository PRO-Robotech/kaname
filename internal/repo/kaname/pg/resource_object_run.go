// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Engine использует тот же immutable catalog, что и bundle владельца. Он не
// получает legacy callback writer; module gate и D1 к OUTPUT не добавляются.
func (r *ResourceDecisionRunner) NewObjectReconciler(logger *slog.Logger) (*reconcile.Reconciler, error) {
	if r == nil || r.repo == nil || r.repo.master == nil || r.bundle == nil || r.facts == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := r.bundle.Validate(); err != nil {
		return nil, err
	}
	return reconcile.NewObjectDecisionReconciler(r, logger, catalog.Fixed{F: r.facts})
}

func resourceObjectRouteFrom(in reconcile.ObjectDecisionRoute) (resourceObjectRoute, error) {
	switch in {
	case reconcile.ObjectDecisionFull:
		return resourceObjectFull, nil
	case reconcile.ObjectDecisionForward:
		return resourceObjectForward, nil
	case reconcile.ObjectDecisionForwardNoStale:
		return resourceObjectForwardNoStale, nil
	default:
		return 0, kaname.ErrInvalidAuthorityFencePlan
	}
}

// Каждая попытка владеет одной lease от RR до завершения RC. Cleanup и Release
// заканчиваются до следующего Acquire; контекст и read budget общие для цикла.
func (r *ResourceDecisionRunner) RunObjectDecision(ctx context.Context, typ, id string, requested reconcile.ObjectDecisionRoute) ([]reconcile.ObjectDecisionSize, error) {
	route, err := resourceObjectRouteFrom(requested)
	if err != nil {
		return nil, err
	}
	return r.runObjectDecision(ctx, typ, id, route)
}

var errNoDirectGroupGeneration = errors.New("no direct Group generation in snapshot")

// Чистый RR возвращает управление штатному membership participant. Во всех
// остальных случаях этот runner владеет полным результатом попытки.
func (r *ResourceDecisionRunner) RunPendingGroupGeneration(ctx context.Context, id string) ([]reconcile.ObjectDecisionSize, bool, error) {
	sizes, err := r.runObjectDecision(ctx, "iam.group", id, resourceObjectPendingGroup)
	if err == errNoDirectGroupGeneration {
		return nil, false, nil
	}
	return sizes, true, err
}

func (r *ResourceDecisionRunner) runObjectDecision(ctx context.Context, typ, id string, route resourceObjectRoute) ([]reconcile.ObjectDecisionSize, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r == nil || r.repo == nil || r.repo.master == nil || r.bundle == nil || r.facts == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := r.bundle.Validate(); err != nil {
		return nil, err
	}
	if !nativeQuestionToken(typ) || !nativeQuestionToken(id) {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	budget := &relverdict.AdministrativeReadBudget{}
	var sizes []reconcile.ObjectDecisionSize
	_, err := runResourceAttempts(ctx, func() (kaname.ResourceDecisionResult, error) {
		// Ни одна неудачная попытка не оставляет наблюдение следующей попытке.
		sizes = nil
		lease, err := r.repo.master.Acquire(ctx)
		if err != nil {
			return kaname.ResourceDecisionResult{}, resourceOpenError(ctx, err)
		}
		defer lease.Release()
		current, err := r.runResourceObjectOnce(ctx, lease.Conn(), typ, id, route, budget)
		if err == nil {
			sizes = current
		}
		return kaname.ResourceDecisionResult{}, err
	})
	if err != nil {
		return nil, err
	}
	return sizes, nil
}

func (r *ResourceDecisionRunner) runResourceObjectOnce(ctx context.Context, conn *pgx.Conn, typ, id string, route resourceObjectRoute, budget *relverdict.AdministrativeReadBudget) (sizes []reconcile.ObjectDecisionSize, err error) {
	lifetime, err := newResourceAttemptLifetime(conn, r.bundle)
	if err != nil {
		return nil, err
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
			sizes = nil
		}
	}()
	if budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	rr, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rr
	source, err := newResourceSourceCapture(rr, budget, lifetime)
	if err != nil {
		return nil, err
	}
	parents, err := newResourceParentCapture(rr, source)
	if err != nil {
		return nil, err
	}
	prepared, err := prepareResourceObject(ctx, parents, r.facts, typ, id, route)
	if err != nil {
		return nil, err
	}
	if prepared == nil {
		if route != resourceObjectPendingGroup {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if err = rollbackResourceAttempt(ctx, rr); err != nil {
			return nil, err
		}
		active = nil
		return nil, errNoDirectGroupGeneration
	}
	empty, err := prepared.emptySnapshot(ctx, parents)
	if err != nil {
		return nil, err
	}
	if empty {
		// Только полное отсутствие, подтверждённое закрытым RR collector.
		// Ошибка или частичный graph не выбирают этот путь; RC/body здесь нет.
		if err = rollbackResourceAttempt(ctx, rr); err != nil {
			return nil, err
		}
		active = nil
		return nil, ctx.Err()
	}
	footprint := newResourceFootprint()
	for _, output := range prepared.outputs {
		if err = output.addFootprint(ctx, parents, footprint); err != nil {
			return nil, err
		}
	}
	global, err := source.requiresGlobalPredicate()
	if err != nil {
		return nil, err
	}
	footprint.global = footprint.global || global
	classified, err := footprint.classified()
	if err != nil {
		return nil, err
	}
	proposal, err := makeResourceObjectProposal(prepared, parents, classified)
	if err != nil {
		return nil, err
	}
	if err = source.seal(); err != nil {
		return nil, err
	}
	if err = rollbackResourceAttempt(ctx, rr); err != nil {
		return nil, err
	}
	active = nil
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	rc, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, resourceFailedAttempt(resourceOpenError(ctx, err), nil, false)
	}
	active = rc
	writer, err := r.enterResource(ctx, rc, lifetime, classified)
	if err != nil {
		return nil, err
	}
	if err = proposal.prewait(ctx, writer, budget); err != nil {
		return nil, err
	}
	if err = source.recheck(ctx, writer); err != nil {
		return nil, err
	}
	if err = proposal.recheckCatalogs(ctx, writer, parents); err != nil {
		return nil, err
	}
	if err = proposal.finalize(ctx, writer, lifetime, budget); err != nil {
		return nil, err
	}
	decision := &resourceDecisionTx{Tx: rc, lifetime: lifetime, owner: writer}
	if err = prepared.apply(ctx, decision, r.facts); err != nil {
		return nil, err
	}
	sizes, err = resourceObjectDecisionSizes(prepared, decision)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	commitStarted = true
	if err = decision.Commit(ctx); err != nil {
		return nil, err
	}
	active = nil
	// Подтверждаем событие только после успешного COMMIT. Открытые факты
	// остаются для следующего прохода очереди без повтора этой транзакции.
	if decision.accessLabelPending > 0 {
		return nil, kaname.ErrAccessLabelReconcilePending
	}
	return sizes, nil
}

func (p *resourceObjectPreparation) intent() (json.RawMessage, error) {
	return json.Marshal(struct {
		Kind                  string              `json:"kind"`
		Type                  string              `json:"object_type"`
		ID                    string              `json:"object_id"`
		Route                 resourceObjectRoute `json:"route"`
		GenerationFingerprint *string             `json:"generation_fingerprint,omitempty"`
	}{"object", p.root.object.Type, p.root.object.ID, p.route, p.generation.fingerprint})
}

func makeResourceObjectProposal(prepared *resourceObjectPreparation, parents *resourceParentCapture, footprint resourceFenceFootprint) (*resourceDecisionProposal, error) {
	if prepared == nil || prepared.root == nil || parents == nil || parents.source == nil || prepared.source != parents.source || prepared.lifetime != parents.source.lifetime || prepared.route < resourceObjectFull || prepared.route > resourceObjectForwardNoStale {
		return nil, kaname.ErrSourceUnconfirmed
	}
	intent, err := prepared.intent()
	if err != nil {
		return nil, err
	}
	envelope, catalogs, err := makeResourceProposalEnvelope(intent, parents, footprint)
	if err != nil {
		return nil, err
	}
	if prepared.effects == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	envelope.ObjectEffects = prepared.effects
	return finishResourceDecisionProposal(envelope, parents.source.lifetime, catalogs)
}

// Наблюдение повторяет смысл observeSize: различные координаты желаемых
// объектов и сумма их кортежей. TTL сужает набор по тем же held final часам,
// что finalCommands; никаких новых чтений и вызовов внешнего recorder здесь нет.
func resourceObjectDecisionSizes(prepared *resourceObjectPreparation, tx *resourceDecisionTx) ([]reconcile.ObjectDecisionSize, error) {
	if prepared == nil || prepared.root == nil || prepared.lifetime == nil || tx == nil || tx.lifetime != prepared.lifetime || !prepared.lifetime.valid(tx.owner, prepared.lifetime.bundle) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var sizes []reconcile.ObjectDecisionSize
	for _, input := range prepared.inputs {
		binding, ok := prepared.root.bindings[string(input.Binding.BindingID)]
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if !input.Binding.Active || (binding.ExpiresAt != nil && !binding.ExpiresAt.After(prepared.lifetime.at)) {
			continue
		}
		objects := make(map[reconcile.MemberCoord]struct{}, len(input.Desired))
		tuples := 0
		for _, desired := range input.Desired {
			objects[reconcile.MemberCoord{ObjectType: desired.ObjectType, ObjectID: desired.ObjectID}] = struct{}{}
			tuples += len(desired.Tuples)
		}
		sizes = append(sizes, reconcile.ObjectDecisionSize{Objects: len(objects), Tuples: tuples})
	}
	return sizes, nil
}

var _ reconcile.ObjectDecisionRunner = (*ResourceDecisionRunner)(nil)

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Страж модуля появляется при сборке API. Достраиваем первое поколение до
// запуска слушателей, рабочие поколения собираются целиком в generationFor.
func (r *publishedWriterGenerations) installResourceGate(ctx context.Context, gate *authzguard.RelationWriteGate) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	if gate == nil {
		return fmt.Errorf("страж регистрации ресурсов не настроен")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.resourceGate != nil || r.current != generation {
		return fmt.Errorf("поколение для настройки стража регистрации ресурсов изменилось")
	}
	resource, err := kanamepg.NewResourceDecisionRunner(pinned, generation.repo, generation.bundle, gate)
	if err != nil {
		return err
	}
	if err := r.store.ConfirmPin(pinned); err != nil {
		return err
	}
	completed := *generation
	completed.resource = resource
	r.resourceGate = gate
	r.current = &completed
	return nil
}

func (r *publishedWriterGenerations) RunResourceDecision(ctx context.Context, in kaname.ResourceDecisionIntent) (kaname.ResourceDecisionResult, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return kaname.ResourceDecisionResult{}, err
	}
	if generation.resource == nil {
		return kaname.ResourceDecisionResult{}, authzsnapshot.ErrUnconfirmed
	}
	return generation.resource.RunResourceDecision(pinned, in)
}

func (r *publishedWriterGenerations) RunUserChildRegistration(ctx context.Context, in kaname.UserChildRegistrationInput, principal operations.Principal) (time.Time, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if generation.resource == nil {
		return time.Time{}, authzsnapshot.ErrUnconfirmed
	}
	return generation.resource.RunUserChildRegistration(pinned, in, principal)
}

func (r *publishedWriterGenerations) RunChildParentClose(ctx context.Context, in kaname.ChildParentCloseInput) (time.Time, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if generation.resource == nil {
		return time.Time{}, authzsnapshot.ErrUnconfirmed
	}
	return generation.resource.RunChildParentClose(pinned, in)
}

// Проверку открытого подписанного поколения вызывает только фоновый reconciler.
func (r *publishedWriterGenerations) RunPendingGroupGeneration(ctx context.Context, id string) ([]reconcile.ObjectDecisionSize, bool, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, false, err
	}
	if generation.resource == nil {
		return nil, false, authzsnapshot.ErrUnconfirmed
	}
	return generation.resource.RunPendingGroupGeneration(pinned, id)
}

func (r *publishedWriterGenerations) RunObjectDecision(ctx context.Context, typ, id string, route reconcile.ObjectDecisionRoute) ([]reconcile.ObjectDecisionSize, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return nil, err
	}
	if generation.resource == nil {
		return nil, authzsnapshot.ErrUnconfirmed
	}
	if typ != "iam.group" {
		return generation.resource.RunObjectDecision(pinned, typ, id, route)
	}
	switch route {
	case reconcile.ObjectDecisionFull:
		return nil, generation.groups.ReconcileObject(pinned, typ, id)
	case reconcile.ObjectDecisionForward:
		return nil, generation.groups.ReconcileObjectForward(pinned, typ, id)
	case reconcile.ObjectDecisionForwardNoStale:
		return nil, generation.groups.ReconcileObjectForwardNoStale(pinned, typ, id)
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
}

func (r *publishedWriterGenerations) ReconcileStagedBinding(ctx context.Context, id domain.AccessBindingID, converge bool, recorder reconcile.SizeRecorder) error {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return err
	}
	return generation.policy.stages.ReconcileStagedBinding(pinned, id, converge, recorder)
}

func (r *publishedWriterGenerations) selectRoleProjection(ctx context.Context) (context.Context, kaname.Repository, *catalog.Facts, error) {
	pinned, generation, err := r.resolve(ctx)
	if err != nil {
		return ctx, nil, nil, err
	}
	return generation.contract.Context(pinned), generation.repo, generation.snapshot.Facts, nil
}

var (
	_ kaname.UserChildRegistrationTransactions = (*publishedWriterGenerations)(nil)
	_ kaname.ChildParentCloseTransactions      = (*publishedWriterGenerations)(nil)
	_ kaname.ResourceDecisionRunner            = (*publishedWriterGenerations)(nil)
	_ reconcile.ObjectDecisionRunner           = (*publishedWriterGenerations)(nil)
	_ reconcile.StagedBindingReconciler        = (*publishedWriterGenerations)(nil)
)

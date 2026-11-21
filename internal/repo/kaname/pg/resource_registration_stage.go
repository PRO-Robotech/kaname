// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

// Stage владеет одним RR capture и сохраняет тела всех сценариев регистрации.
// Он не открывает RC и не удостоверяет полноту lock manifest: окончательный
// admission выполняется только после добавления SQL prewait и SOURCE guards.
type resourceRegistrationStage struct {
	registration   *resourceRegistrationPreparation
	unregistration *resourceUnregistrationPreparation
	outputs        []*resourceOutputCapture
	installation   *resourceInstallationCapture
	native         *resourceNativeCapture
	footprint      resourceFenceFootprint
	source         *resourceSourceCapture
}

func (r *ResourceDecisionRunner) stageRegistration(ctx context.Context, tx pgx.Tx, lifetime *resourceAttemptLifetime, module resourceModuleIdentity, in kaname.ResourceDecisionIntent, budget *relverdict.AdministrativeReadBudget) (*resourceRegistrationStage, error) {
	if r == nil || r.bundle == nil || r.facts == nil || lifetime == nil || lifetime.bundle != r.bundle || !module.valid() {
		return nil, kaname.ErrSourceUnconfirmed
	}
	source, err := newResourceSourceCapture(tx, budget, lifetime)
	if err != nil {
		return nil, err
	}
	parents, err := newResourceParentCapture(tx, source)
	if err != nil {
		return nil, err
	}
	registration, err := prepareResourceRegistration(ctx, parents, module, in)
	if err != nil {
		return nil, err
	}
	if err = captureResourceDirectSources(ctx, parents, registration.catalog, registration.row.ObjectID, in.Action); err != nil {
		return nil, err
	}
	out := &resourceRegistrationStage{registration: registration, source: source}
	if in.Action == kaname.ResourceDecisionUnregister {
		out.unregistration, err = prepareResourceUnregistration(ctx, registration, module.actor, r.facts)
		if err != nil {
			return nil, err
		}
		if out.unregistration.withdrawal != nil {
			// Metadata остаётся ROW EXCLUSIVE. Authored source эффекты отдельно
			// объявляют EXCLUSIVE exact guard keys до любых body waits/clock.
			for _, step := range out.unregistration.withdrawal.plan.Steps {
				for _, change := range step.Bindings {
					if err = registration.footprint.addSourceEffect("binding", string(change.ID)); err != nil {
						return nil, err
					}
				}
				for _, change := range step.Roles {
					if err = registration.footprint.addSourceEffect("role", string(change.ID)); err != nil {
						return nil, err
					}
				}
			}
			out.outputs = append(out.outputs, out.unregistration.withdrawal.outputs...)
		}
	}
	root, err := captureResourceOutput(ctx, parents, registration.catalog, registration.row.ObjectID)
	if err != nil {
		return nil, err
	}
	if err = root.addFootprint(ctx, parents, registration.footprint); err != nil {
		return nil, err
	}
	out.outputs = append(out.outputs, root)
	if out.unregistration != nil {
		for _, child := range out.unregistration.descendants {
			if err = captureResourceDirectSources(ctx, parents, child.catalog, child.id, kaname.ResourceDecisionUnregister); err != nil {
				return nil, err
			}
			captured, err := captureResourceOutput(ctx, parents, child.catalog, child.id)
			if err != nil {
				return nil, err
			}
			if err = captured.addFootprint(ctx, parents, registration.footprint); err != nil {
				return nil, err
			}
			out.outputs = append(out.outputs, captured)
		}
	}
	broadPredicate, err := source.requiresGlobalPredicate()
	if err != nil {
		return nil, err
	}
	if broadPredicate {
		registration.footprint.global = true
	}
	out.footprint, err = registration.footprint.classified()
	if err != nil {
		return nil, err
	}
	out.installation, err = captureResourceInstallation(ctx, tx, lifetime, module, out.footprint.registration, budget)
	if err != nil {
		return nil, err
	}
	out.native, err = r.captureRegistrationNative(ctx, tx, lifetime, module, out.footprint.registration, budget)
	if err != nil {
		return nil, err
	}
	// Не seal здесь: последующий закрытый compiler ещё добавляет predicates
	// tuple-fold и точные строки, ожидаемые физическим body.
	return out, nil
}

// Direct predicates обязательны независимо от ветвления savedScopes/parent
// resolver. В частности, отсутствие parent_edge у нового Register — захваченный
// пустой predicate, а не отсутствие ключа. SQL повторяет этот закрытый contract
// до prewait; capture использует тот же RR/cache/budget и обычный recheck.
func captureResourceDirectSources(ctx context.Context, parents *resourceParentCapture, cat resourceCatalogRow, id string, action kaname.ResourceDecisionAction) error {
	if parents == nil || parents.source == nil || parents.source.sealed || cat.identity.Dotted == "" || cat.identity.ObjectType == "" || !nativeQuestionToken(id) {
		return kaname.ErrSourceUnconfirmed
	}
	var kinds []resourceSourceKind
	switch action {
	case kaname.ResourceDecisionRegister:
		kinds = []resourceSourceKind{resourceSourceMirror, resourceSourceParentEdges, resourceSourceRegistrationScopes, resourceSourceProjectBinding, resourceSourcePointerFacts, resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectRetirement}
	case kaname.ResourceDecisionUnregister:
		kinds = []resourceSourceKind{resourceSourceMirror, resourceSourceParentEdges, resourceSourcePointerFacts, resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceFactLedgerHolders}
	case kaname.ResourceDecisionPublish, kaname.ResourceDecisionUnpublish:
		kinds = []resourceSourceKind{resourceSourcePointerFacts, resourceSourceRegistrationPointers, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceFactLedgerHolders}
	default:
		return kaname.ErrSourceUnconfirmed
	}
	for _, kind := range kinds {
		typ := cat.identity.ObjectType
		if kind == resourceSourceMirror {
			typ = cat.identity.Dotted
		}
		if _, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: kind, typ: typ, id: id}); err != nil {
			return err
		}
	}
	return nil
}

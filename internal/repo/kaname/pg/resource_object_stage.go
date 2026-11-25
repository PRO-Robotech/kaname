// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type resourceObjectRoute uint8

const (
	resourceObjectFull resourceObjectRoute = iota + 1
	resourceObjectForward
	resourceObjectForwardNoStale
)

type resourceObjectPreparation struct {
	lifetime   *resourceAttemptLifetime
	source     *resourceSourceCapture
	route      resourceObjectRoute
	root       *resourceOutputCapture
	outputs    []*resourceOutputCapture
	inputs     []reconcile.CapturedObjectDiff
	commands   []reconcile.BindingCommand
	effects    *resourceObjectEffectProposal
	additive   bool
	generation resourceGenerationProjection
}

// Маршруты сохраняют прежний выбор: обычный forward при standing members
// переходит к полному diff; NoStale остаётся добавляющим. Ledger-only holder
// входит в protected source footprint, но сам по себе не выбирает выдачу для
// materialization: кандидатами остаются members и selector match.
func prepareResourceObject(ctx context.Context, parents *resourceParentCapture, facts *catalog.Facts, typ, id string, route resourceObjectRoute) (*resourceObjectPreparation, error) {
	if parents == nil || parents.source == nil || parents.source.sealed || facts == nil || !nativeQuestionToken(typ) || !nativeQuestionToken(id) || route < resourceObjectFull || route > resourceObjectForwardNoStale {
		return nil, kaname.ErrSourceUnconfirmed
	}
	capture, err := parents.catalog(ctx, typ)
	if err != nil {
		return nil, err
	}
	cat, known := capture.selected()
	if !known || cat.identity.Dotted != typ {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var generation resourceGenerationProjection
	if route == resourceObjectFull {
		generation, err = captureResourceGeneration(ctx, parents, cat.identity.ObjectType, id)
		if err != nil {
			return nil, err
		}
	}
	object, present, err := parents.captureObjectProjection(ctx, typ, id)
	if err != nil {
		return nil, err
	}
	if !present {
		if generation.fingerprint != nil {
			// Отсутствующий выход чужого поколения не определяет область корня.
			if !slices.Contains(generation.externalRoots, domain.ResourceRef{Type: typ, ID: id}) {
				return nil, kaname.ErrAccessLabelReconcilePending
			}
			// Сохранённый scope нужен SQL для проверки жизненного цикла под
			// оградами. Пустой предикат оставляет событие в очереди.
			scopes, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: cat.identity.ObjectType, id: id})
			if err != nil {
				return nil, err
			}
			if len(scopes) == 0 {
				return nil, kaname.ErrAccessLabelReconcilePending
			}
		}
		object = domain.MirrorObject{ObjectType: typ, ObjectID: id}
	}
	root, err := captureResourceOutput(ctx, parents, cat, id)
	if err != nil {
		return nil, err
	}
	existing := len(root.selected) > 0
	additive := route != resourceObjectFull && (route == resourceObjectForwardNoStale || !existing)
	if additive {
		// Existing members не становятся кандидатами добавляющего прохода.
		root.selected = map[string]bool{}
	}
	if err = root.captureMatchingBindings(ctx, parents, object, present); err != nil {
		return nil, err
	}
	result := &resourceObjectPreparation{lifetime: parents.source.lifetime, source: parents.source, route: route, root: root, outputs: []*resourceOutputCapture{root}, additive: additive, generation: generation}
	var ancestors []domain.MirrorObject
	if len(root.selected) > 0 {
		// SQL certificate проверяет ancestry каждой выбранной координаты,
		// включая ordinary и foreign REJECTED, а не только nested selectors.
		// Существующий helper захватывает настоящий bounded RR predicate
		// (включая пустой), catalog JOIN и текущие проекции родителей.
		ancestors, err = parents.captureObjectAncestors(ctx, typ, id, present)
		if err != nil {
			return nil, err
		}
	}
	narrow, err := root.coordinateDiffInputs(ctx, parents, facts, object, present, ancestors, additive)
	if err != nil {
		return nil, err
	}
	for _, input := range narrow {
		whole, _ := reconcile.CapturedObjectDependencyShape(input.Binding, typ)
		if !additive && whole && input.Binding.Active {
			full, outputs, err := root.captureWholeBindingDiff(ctx, parents, facts, string(input.Binding.BindingID), typ, false)
			if err != nil {
				return nil, err
			}
			result.inputs = append(result.inputs, full)
			result.outputs = append(result.outputs, outputs...)
		} else {
			result.inputs = append(result.inputs, input)
		}
	}
	result.commands, err = reconcile.CompileCapturedObjectDiff(ctx, result.inputs)
	if err != nil {
		return nil, err
	}
	if err = parents.source.budget.Charge(len(result.commands), 0); err != nil {
		return nil, err
	}
	result.effects, err = compileResourceObjectEffectProposal(ctx, result)
	if err != nil {
		return nil, err
	}
	if err = result.captureFoldOutputs(ctx, parents); err != nil {
		return nil, err
	}
	return result, ctx.Err()
}

// RR подготавливает live/expired ветви каждого binding. TTL выбирает итог
// по единственным final часам уже удерживаемой попытки. Общий collector может
// освободить delete после утраты другого write claim; этот эффект заранее
// входит в индивидуальные ветви. Новых SQL чтений или waits здесь нет.
func (p *resourceObjectPreparation) finalCommands(ctx context.Context, tx *resourceDecisionTx) ([]reconcile.BindingCommand, error) {
	if p == nil || p.root == nil || p.lifetime == nil || tx == nil || tx.lifetime != p.lifetime || !p.lifetime.valid(tx.owner, p.lifetime.bundle) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	inputs := slices.Clone(p.inputs)
	for i := range inputs {
		binding, ok := p.root.bindings[string(inputs[i].Binding.BindingID)]
		if !ok {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if binding.ExpiresAt != nil && !binding.ExpiresAt.After(p.lifetime.at) {
			inputs[i].Binding.Active = false
		}
	}
	return reconcile.CompileCapturedObjectDiff(ctx, inputs)
}

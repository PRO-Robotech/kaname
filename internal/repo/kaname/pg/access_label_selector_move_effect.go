// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

type accessLabelMoveGraph struct {
	Present   bool
	Object    domain.MirrorObject
	Ancestors []domain.MirrorObject
	Project   *resourceeffect.ProjectGraphProjection
}

type accessLabelMoveBindingEffect struct {
	BindingID   domain.AccessBindingID
	Pending     bool
	Coordinates []accessLabelMoveCoordinateEffect
}

// Сохраняем подтверждённое отсутствие объекта и пустой набор членов
// существующего объекта отдельно. Для обоих состояний координата обязательна.
type accessLabelMoveCoordinateEffect struct {
	Resource domain.ResourceRef
	Present  bool
	Before   []resourceeffect.ObjectDesiredMember
	Proposed []resourceeffect.ObjectDesiredMember
}

type accessLabelMoveEffect struct {
	Bindings []accessLabelMoveBindingEffect
	Added    []domain.MembershipTuple
	Removed  []domain.MembershipTuple
	Commands []reconcile.BindingCommand
	// ResidualFold — кортежи из старого журнала вне обычного diff.
	// Кандидатов на снятие перепроверяет владелец под замками фактов.
	ResidualFold []domain.MembershipTuple
}

type accessLabelMoveCopies map[domain.ResourceRef]map[string]string

// В дополнительной карте сохраняются только пары с доказанным вложенным
// источником, которые невозможно вывести из обычных меток собственной строки.
type accessLabelMoveCopyPlan struct {
	labels       accessLabelMoveCopies
	projectPairs accessLabelMoveCopies
}

func (p *resourceParentCapture) captureAccessLabelMoveGraph(ctx context.Context, ref domain.ResourceRef) (accessLabelMoveGraph, error) {
	object, present, err := p.captureObjectProjection(ctx, ref.Type, ref.ID)
	if err != nil || !present {
		return accessLabelMoveGraph{Object: object, Present: present}, err
	}
	graph := accessLabelMoveGraph{Object: object, Present: true}
	if ref.Type == domain.ScopeTypeProjectDotted {
		project, err := p.captureProjectObjectGraph(ctx, ref.ID)
		if err != nil {
			return accessLabelMoveGraph{}, err
		}
		graph.Project = &project
	} else {
		graph.Ancestors, err = p.captureObjectAncestors(ctx, ref.Type, ref.ID, true)
		if err != nil {
			return accessLabelMoveGraph{}, err
		}
	}
	return graph, ctx.Err()
}

func (g accessLabelMoveGraph) ancestors() []domain.MirrorObject {
	if g.Project != nil {
		return g.Project.Ancestors
	}
	return g.Ancestors
}

func (g accessLabelMoveGraph) compileDesired(facts *catalog.Facts, binding resourceeffect.ObjectBinding, copies accessLabelMoveCopies) ([]resourceeffect.ObjectDesiredMember, error) {
	object := overlaySelectorMoveLabels(g.Object, copies)
	if g.Project != nil {
		project := *g.Project
		project.Ancestors = overlaySelectorMoveAncestors(project.Ancestors, copies)
		return resourceeffect.CompileProjectObjectDesired(facts, binding, object, project)
	}
	return resourceeffect.CompileObjectDesired(facts, binding, object, overlaySelectorMoveAncestors(g.Ancestors, copies))
}

func overlaySelectorMoveAncestors(ancestors []domain.MirrorObject, copies accessLabelMoveCopies) []domain.MirrorObject {
	if len(copies) == 0 {
		return ancestors
	}
	proposed := slices.Clone(ancestors)
	for i, ancestor := range proposed {
		proposed[i] = overlaySelectorMoveLabels(ancestor, copies)
	}
	return proposed
}

// captureAccessLabelMoveGraphs снимает одну проекцию на координату, даже
// если объект участвует в нескольких выдачах. Отсутствующие исторические
// объекты остаются в снимке как явные отрицательные наблюдения.
func (p *resourceParentCapture) captureAccessLabelMoveGraphs(
	ctx context.Context, scopes []accessLabelSelectorMoveScope, copyTargets []domain.ResourceRef,
) (map[domain.ResourceRef]accessLabelMoveGraph, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	keys := slices.Clone(copyTargets)
	for _, scope := range scopes {
		keys = append(keys, scope.Coordinates...)
	}
	graphs := make(map[domain.ResourceRef]accessLabelMoveGraph)
	for _, key := range sortedRefs(keys) {
		if err := p.source.budget.Charge(1, 0); err != nil {
			return nil, err
		}
		graph, err := p.captureAccessLabelMoveGraph(ctx, key)
		if err != nil {
			return nil, err
		}
		graphs[key] = graph
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return graphs, nil
}

// targets связывает удержанный объект с индексами переноса. Для вложенного
// правила выбор контейнера и ребёнка подтверждается переписью владельца.
// Только после этого компилятор предлагает полные новые карты меток.
func planAccessLabelMoveCopies(
	ctx context.Context, moves []domain.ValidatedAccessLabelSelectorMove, targets map[domain.ResourceRef][]int,
	graphs map[domain.ResourceRef]accessLabelMoveGraph, budget *relverdict.AdministrativeReadBudget,
) (accessLabelMoveCopyPlan, error) {
	var empty accessLabelMoveCopyPlan
	if graphs == nil || budget == nil {
		return empty, kaname.ErrSourceUnconfirmed
	}
	result := accessLabelMoveCopyPlan{labels: make(accessLabelMoveCopies)}
	for key, selected := range targets {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		graph, captured := graphs[key]
		if !captured || !graph.Present || graph.Object.ObjectType != key.Type || graph.Object.ObjectID != key.ID {
			return empty, kaname.ErrSourceUnconfirmed
		}
		next, changed, err := mergeAccessLabelMoveCopies(ctx, graph, moves, selected, budget)
		if err != nil {
			return empty, err
		}
		if !changed {
			continue
		}
		result.labels[key] = next
		for k, v := range next {
			if _, exists := graph.Object.AccessLabels[k]; exists {
				continue
			}
			if native, exists := graph.Object.Labels[k]; exists && native == v {
				continue
			}
			if graph.Project == nil || graph.Project.Object == nil {
				return empty, kaname.ErrSourceUnconfirmed
			}
			if value, exists := graph.Project.Object.Labels[k]; !exists || value != v {
				return empty, kaname.ErrSourceUnconfirmed
			}
			if result.projectPairs == nil {
				result.projectPairs = make(accessLabelMoveCopies)
			}
			if result.projectPairs[key] == nil {
				result.projectPairs[key] = make(map[string]string)
			}
			result.projectPairs[key][k] = v
		}
	}
	return result, ctx.Err()
}

// compileAccessLabelMoveEffect считает разницу фактических кортежей отдельно
// от замены fingerprints. scopes включает также другие выдачи, эффекты
// которых меняются из-за копии меток; retained поступает только из
// подтверждённых неизменных источников. Функция вычисляет эффект снимка.
// Полноту переписи, версию источников и разрешение записи сверяет владелец TX.
func compileAccessLabelMoveEffect(
	ctx context.Context, facts *catalog.Facts, scopes []accessLabelSelectorMoveScope,
	graphs map[domain.ResourceRef]accessLabelMoveGraph, copyPlan accessLabelMoveCopyPlan,
	retained []domain.MembershipTuple, decisionAt time.Time, budget *relverdict.AdministrativeReadBudget,
) (accessLabelMoveEffect, error) {
	var empty accessLabelMoveEffect
	if facts == nil || graphs == nil || decisionAt.IsZero() || budget == nil {
		return empty, kaname.ErrSourceUnconfirmed
	}
	accessLabels := copyPlan.labels
	if err := budget.Charge(len(scopes)+len(retained)+len(accessLabels), 0); err != nil {
		return empty, err
	}
	for key, labels := range accessLabels {
		graph, captured := graphs[key]
		if !captured || !graph.Present || graph.Object.ObjectType != key.Type || graph.Object.ObjectID != key.ID {
			return empty, kaname.ErrSourceUnconfirmed
		}
		for k, old := range graph.Object.AccessLabels {
			if value, present := labels[k]; !present || value != old {
				return empty, kaname.ErrSourceUnconfirmed
			}
		}
		typed := make(domain.Labels, len(labels))
		for k, v := range labels {
			if _, existed := graph.Object.AccessLabels[k]; !existed {
				value, copied := graph.Object.Labels[k]
				if !copied || value != v {
					held, witnessed := copyPlan.projectPairs[key][k]
					if !witnessed || held != v || graph.Project == nil || graph.Project.Object == nil {
						return empty, kaname.ErrSourceUnconfirmed
					}
					if nested, found := graph.Project.Object.Labels[k]; !found || nested != v {
						return empty, kaname.ErrSourceUnconfirmed
					}
				}
			}
			typed[domain.LabelKey(k)] = domain.LabelVal(v)
		}
		if err := typed.Validate(); err != nil {
			return empty, err
		}
	}
	beforeSet := make(map[domain.MembershipTuple]bool)
	proposedSet := make(map[domain.MembershipTuple]bool)
	for _, tuple := range retained {
		if tuple.User == "" || tuple.Relation == "" || tuple.Object == "" {
			return empty, kaname.ErrSourceUnconfirmed
		}
		beforeSet[tuple], proposedSet[tuple] = true, true
	}

	var result accessLabelMoveEffect
	diff := make([]reconcile.CapturedObjectDiff, 0, len(scopes))
	var forget []reconcile.BindingCommand
	residual := make(map[domain.MembershipTuple]bool)
	seenBindings := make(map[domain.AccessBindingID]bool, len(scopes))
	for _, scope := range scopes {
		if err := ctx.Err(); err != nil {
			return empty, err
		}
		id := scope.Carrier.Binding.ID
		if id == "" || scope.Before.BindingID != id || scope.Proposed.BindingID != id || seenBindings[id] ||
			scope.Before.RoleID != string(scope.Carrier.Binding.RoleID) || scope.Proposed.RoleID != scope.Before.RoleID ||
			scope.Before.Scope != scope.Proposed.Scope || !slices.Equal(scope.Before.Subjects, scope.Proposed.Subjects) ||
			scope.Before.Target.Digest() != scope.Proposed.Target.Digest() {
			return empty, kaname.ErrSourceUnconfirmed
		}
		seenBindings[id] = true
		active := scope.Carrier.activeAt(decisionAt)
		eligible := scope.Carrier.canSelectAt(decisionAt)
		if err := budget.Charge(len(scope.Coordinates), 0); err != nil {
			return empty, err
		}
		bindingEffect := accessLabelMoveBindingEffect{
			BindingID: id, Pending: eligible && !active,
			Coordinates: make([]accessLabelMoveCoordinateEffect, 0, len(scope.Coordinates)),
		}
		oldBinding, newBinding := resourceEffectBinding(scope.Before), resourceEffectBinding(scope.Proposed)
		oldBinding.Active, newBinding.Active = eligible, eligible
		var currentClaims, futureClaims map[domain.MembershipTuple]bool
		if active {
			currentClaims, futureClaims = beforeSet, proposedSet
		}
		for _, key := range scope.Coordinates {
			if err := ctx.Err(); err != nil {
				return empty, err
			}
			graph, captured := graphs[key]
			if !captured || (graph.Present && (graph.Object.ObjectType != key.Type || graph.Object.ObjectID != key.ID)) {
				return empty, kaname.ErrSourceUnconfirmed
			}
			coordinate := accessLabelMoveCoordinateEffect{Resource: key, Present: graph.Present}
			if eligible && graph.Present {
				if err := budget.Charge(1+len(graph.ancestors()), 0); err != nil {
					return empty, err
				}
				before, err := graph.compileDesired(facts, oldBinding, nil)
				if err != nil {
					return empty, err
				}
				proposed, err := graph.compileDesired(facts, newBinding, accessLabels)
				if err != nil {
					return empty, err
				}
				if err = collectSelectorMoveTuples(before, currentClaims, budget); err != nil {
					return empty, err
				}
				if err = collectSelectorMoveTuples(proposed, futureClaims, budget); err != nil {
					return empty, err
				}
				coordinate.Before, coordinate.Proposed = before, proposed
			}
			bindingEffect.Coordinates = append(bindingEffect.Coordinates, coordinate)
		}
		captured, orphaned, err := selectorMoveCapturedDiff(scope, bindingEffect.Coordinates, active, residual, budget)
		if err != nil {
			return empty, err
		}
		if active {
			diff = append(diff, captured)
		}
		if len(orphaned) != 0 {
			forget = append(forget, reconcile.BindingCommand{Kind: "forget", Binding: id, Rows: orphaned})
		}
		result.Bindings = append(result.Bindings, bindingEffect)
	}
	slices.SortFunc(diff, func(a, b reconcile.CapturedObjectDiff) int {
		return cmp.Compare(a.Binding.BindingID, b.Binding.BindingID)
	})
	commands, err := reconcile.CompileCapturedObjectDiff(ctx, diff)
	if err != nil {
		return empty, err
	}
	if err = budget.Charge(len(commands)+len(forget), 0); err != nil {
		return empty, err
	}
	for _, command := range commands {
		if command.Kind == "delete" {
			for _, tuple := range command.Tuples {
				delete(residual, tuple)
			}
		}
	}
	result.Commands = append(forget, commands...)
	result.ResidualFold = selectorMoveTupleDifference(residual, proposedSet)
	result.Added = selectorMoveTupleDifference(proposedSet, beforeSet)
	result.Removed = selectorMoveTupleDifference(beforeSet, proposedSet)
	if err := ctx.Err(); err != nil {
		return empty, err
	}
	return result, nil
}

func overlaySelectorMoveLabels(object domain.MirrorObject, accessLabels accessLabelMoveCopies) domain.MirrorObject {
	if labels, copied := accessLabels[domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}]; copied {
		object.AccessLabels = labels
	}
	return object
}

func collectSelectorMoveTuples(members []resourceeffect.ObjectDesiredMember, dst map[domain.MembershipTuple]bool, budget *relverdict.AdministrativeReadBudget) error {
	if err := budget.Charge(len(members), 0); err != nil {
		return err
	}
	for _, member := range members {
		if err := budget.Charge(len(member.Tuples), 0); err != nil {
			return err
		}
		if dst == nil || member.Status != domain.VerificationActive {
			continue
		}
		for _, tuple := range member.Tuples {
			dst[tuple] = true
		}
	}
	return nil
}

func selectorMoveTupleDifference(left, right map[domain.MembershipTuple]bool) []domain.MembershipTuple {
	var result []domain.MembershipTuple
	for tuple := range left {
		if !right[tuple] {
			result = append(result, tuple)
		}
	}
	slices.SortFunc(result, func(a, b domain.MembershipTuple) int {
		if n := cmp.Compare(a.Object, b.Object); n != 0 {
			return n
		}
		if n := cmp.Compare(a.Relation, b.Relation); n != 0 {
			return n
		}
		return cmp.Compare(a.User, b.User)
	})
	return result
}

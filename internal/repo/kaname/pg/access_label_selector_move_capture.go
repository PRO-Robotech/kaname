// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type accessLabelSelectorMoveCapture struct {
	Before               domain.Role
	ProposedRules        domain.Rules
	ProposedImage        json.RawMessage
	Moves                []domain.ValidatedAccessLabelSelectorMove
	Carriers             []accessLabelSelectorMoveScope
	BindingTargets       accessLabelMoveTargetCensus
	DefinitionTargets    map[domain.ResourceRef][]int
	DefinitionCandidates []domain.ResourceRef
	Collateral           []accessLabelSelectorMoveScope
	Graphs               map[domain.ResourceRef]accessLabelMoveGraph
	retainedSources      map[domain.ResourceRef]accessLabelMoveRetainedSource
	copyUpdates          accessLabelMoveObjectUpdates
	copyPlan             json.RawMessage
	targetsSnapshotAt    time.Time
	proof                *accessLabelMoveRRProof
}

type accessLabelSelectorMoveScope struct {
	Carrier     accessLabelSelectorMoveCarrier
	Before      reconcile.BindingScope
	Proposed    reconcile.BindingScope
	Coordinates []domain.ResourceRef
}

// captureAccessLabelSelectorMove читает текущую роль и гипотетические
// селекторы в одном RR. Это вход для доказательства, а не разрешение записи.
// Удержанный role writer отдельно подтверждает предложенный предикат,
// изменения самих меток и полный набор затрагиваемых ими ролей.
func (p *resourceParentCapture) captureAccessLabelSelectorMove(
	ctx context.Context, facts *catalog.Facts, roleID domain.RoleID, version string,
	moves []domain.AccessLabelSelectorMove,
) (accessLabelSelectorMoveCapture, error) {
	var empty accessLabelSelectorMoveCapture
	if p == nil || p.source == nil || facts == nil || !nativeQuestionToken(string(roleID)) || version == "" {
		return empty, kaname.ErrSourceUnconfirmed
	}
	key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(roleID)}
	rows, err := p.source.read(ctx, p.tx, key)
	if err != nil {
		return empty, err
	}
	if len(rows) != 1 {
		return empty, kaname.ErrSourceUnconfirmed
	}
	// GetWithVersion и UpdateCAS используют xmin; в удерживаемом
	// свидетельстве вместе с ним остаются ctid и полный образ строки.
	var generation []json.RawMessage
	var xmin string
	if err = json.Unmarshal([]byte(rows[0].state), &generation); err != nil || len(generation) != 3 ||
		json.Unmarshal(generation[0], &xmin) != nil || xmin == "" {
		return empty, kaname.ErrSourceUnconfirmed
	}
	if xmin != version {
		return empty, kaname.ErrAuthorityClassificationChanged
	}
	authored, err := resourceCapturedRole(rows[0].value)
	if err != nil {
		return empty, err
	}
	if authored.ID != roleID {
		return empty, kaname.ErrSourceUnconfirmed
	}
	key.kind = resourceSourceRoleSelectors
	selectors, err := p.source.read(ctx, p.tx, key)
	if err != nil {
		return empty, err
	}
	currentLayout, err := resourceCapturedMaterializingRole(rows[0].value, selectors)
	if err != nil {
		return empty, err
	}
	if currentLayout.Lifecycle.State != domain.RoleLifecycleDeclared {
		return empty, kaname.ErrSourceUnconfirmed
	}
	proposed, validatedMoves, err := authored.Rules.PlanAccessLabelSelectorMoves(moves, domain.PolicyOfRole(authored.IsSystem, authored.OwnerModule), facts)
	if err != nil {
		return empty, err
	}
	var row struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err = json.Unmarshal(rows[0].value, &row); err != nil {
		return empty, kaname.ErrSourceUnconfirmed
	}
	ruleImage, err := verifySelectorMoveRules(ctx, p.tx, row.Rules, authored.Rules, proposed, validatedMoves, p.source.budget)
	if err != nil {
		return empty, err
	}
	authored.Lifecycle = currentLayout.Lifecycle
	authored.ResourceVersion = xmin
	proposedLayout := authored
	proposedLayout.Rules = proposed

	carriers, err := readAccessLabelSelectorMoveCarriers(ctx, p.tx, p.source, roleID)
	if err != nil {
		return empty, err
	}
	result := accessLabelSelectorMoveCapture{
		Before: authored, ProposedRules: proposed, ProposedImage: ruleImage, Moves: validatedMoves,
		Carriers: make([]accessLabelSelectorMoveScope, 0, len(carriers)),
	}
	for _, carrier := range carriers {
		before := bindingScopeFrom(facts, carrier.Binding, currentLayout)
		after := bindingScopeFrom(facts, carrier.Binding, proposedLayout)
		coordinates := maps.Clone(carrier.Coordinates)
		// PENDING участвует в проверке будущего эффекта, но сам по себе
		// не удерживает действующее право. TTL сверяется по финальным часам.
		if carrier.canSelect() {
			if err = p.captureBindingDiffScope(ctx, facts, coordinates, before, resourceSourceSelectorObjects); err != nil {
				return empty, err
			}
			if err = p.captureBindingDiffScope(ctx, facts, coordinates, after, resourceSourceRoleProposedSelectorObjects); err != nil {
				return empty, err
			}
		}
		keys, err := p.finishBindingDiffKeys(ctx, coordinates)
		if err != nil {
			return empty, err
		}
		result.Carriers = append(result.Carriers, accessLabelSelectorMoveScope{
			Carrier: carrier, Before: before, Proposed: after, Coordinates: keys,
		})
	}
	result.BindingTargets, err = p.captureAccessLabelMoveBindingTargets(ctx, result)
	if err != nil {
		return empty, err
	}
	result.BindingTargets, result.targetsSnapshotAt, err = p.filterAccessLabelMoveTargets(ctx, result.BindingTargets)
	if err != nil {
		return empty, err
	}
	var overlay map[domain.ResourceRef]domain.MirrorObject
	if len(result.BindingTargets) == 0 {
		result.DefinitionTargets, err = p.captureAccessLabelMoveDefinitionTargets(ctx, result)
		if err != nil {
			return empty, err
		}
		anchor, err := accessLabelMoveRoleScope(authored)
		if err != nil {
			return empty, err
		}
		scope := reconcile.BindingScope{Scope: anchor, Target: domain.AccessTarget{AllInScope: true}}
		result.DefinitionCandidates, err = p.captureAccessLabelMoveDefinitionCandidates(ctx, result, scope, result.DefinitionTargets)
		if err != nil {
			return empty, err
		}
		overlay, err = p.captureAccessLabelMovePotentialOverlay(ctx, result.Moves, result.DefinitionTargets)
	} else {
		overlay, err = p.captureAccessLabelMoveCarrierCandidates(ctx, result)
	}
	if err != nil {
		return empty, err
	}
	result.copyPlan, err = p.captureAccessLabelMoveCopyPlan(ctx, overlay, result.DefinitionTargets != nil)
	if err != nil {
		return empty, err
	}
	result.copyUpdates, err = p.captureAccessLabelMoveObjectUpdates(ctx, facts, overlay)
	if err != nil {
		return empty, err
	}
	otherBindings, err := p.captureAccessLabelMoveCollateralBindings(ctx, overlay, authored.ID)
	if err != nil {
		return empty, err
	}
	result.Collateral, err = p.captureAccessLabelMoveCollateralScopes(ctx, facts, otherBindings, overlay)
	if err != nil {
		return empty, err
	}
	targets := slices.Clone(result.DefinitionCandidates)
	for _, binding := range result.BindingTargets {
		if err = p.source.budget.Charge(len(binding.targets), 0); err != nil {
			return empty, err
		}
		targets = slices.AppendSeq(targets, maps.Keys(binding.targets))
	}
	scopes := slices.Concat(result.Carriers, result.Collateral)
	result.Graphs, err = p.captureAccessLabelMoveGraphs(ctx, scopes, targets)
	if err != nil {
		return empty, err
	}
	result.retainedSources, err = p.captureAccessLabelMoveRetainedSources(ctx, result)
	if err != nil {
		return empty, err
	}
	result.proof, err = p.rememberAccessLabelMoveRR(result)
	if err != nil {
		return empty, err
	}
	return result, ctx.Err()
}

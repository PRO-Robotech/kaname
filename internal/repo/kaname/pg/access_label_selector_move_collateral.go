// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Перепись чужих выдач для всех предложенных копий в одном RR. Результат
// включает и неизменное покрытие, и историю. Наличие выдачи в нём само по
// себе не подтверждает действующее право или необходимость менять её ledger.
func (p *resourceParentCapture) captureAccessLabelMoveCollateralBindings(
	ctx context.Context, overlay map[domain.ResourceRef]domain.MirrorObject, roleID domain.RoleID,
) ([]domain.AccessBindingID, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil ||
		!nativeQuestionToken(string(roleID)) || overlay == nil || (p.source.metadataParents != nil && p.source.metadataParents != p) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := p.source.budget.Charge(len(overlay), 0); err != nil {
		return nil, err
	}
	// Связи зеркала и каталог должны войти в тот же RR collector.
	if len(overlay) > 0 {
		p.source.metadataParents = p
	}
	// Исторический предикат возвращает также role_id. Сверяем его с физической
	// строкой перед исключением собственной выдачи из объединённого набора.
	candidates := make(map[domain.AccessBindingID]domain.RoleID)
	for _, ref := range sortedRefs(slices.Collect(maps.Keys(overlay))) {
		projection, err := p.captureAccessLabelMoveCollateralProjection(ctx, ref, overlay[ref])
		if err != nil {
			return nil, err
		}
		if projection == "" {
			continue
		}
		for _, kind := range []resourceSourceKind{
			resourceSourceMetadataBindings, resourceSourceMetadataAuthoredBindings,
			resourceSourceMetadataBindingCoverage, resourceSourceMetadataHistoricalCarriers,
		} {
			rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: kind, typ: ref.Type, id: ref.ID, projection: projection})
			if err != nil {
				return nil, err
			}
			if err := p.source.budget.Charge(len(rows), 0); err != nil {
				return nil, err
			}
			for _, row := range rows {
				var hit struct {
					ID      domain.AccessBindingID `json:"binding_id"`
					RoleID  domain.RoleID          `json:"role_id"`
					Changes *bool                  `json:"changes"`
				}
				if json.Unmarshal(row.value, &hit) != nil || !nativeQuestionToken(string(hit.ID)) {
					return nil, kaname.ErrSourceUnconfirmed
				}
				owner := candidates[hit.ID]
				if kind == resourceSourceMetadataHistoricalCarriers {
					if !nativeQuestionToken(string(hit.RoleID)) || (owner != "" && owner != hit.RoleID) {
						return nil, kaname.ErrSourceUnconfirmed
					}
					owner = hit.RoleID
				} else if hit.Changes == nil || (kind == resourceSourceMetadataBindings && !*hit.Changes) {
					return nil, kaname.ErrSourceUnconfirmed
				}
				candidates[hit.ID] = owner
			}
		}
	}
	ids := make([]domain.AccessBindingID, 0, len(candidates))
	for _, id := range slices.Sorted(maps.Keys(candidates)) {
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: string(id)})
		if err != nil {
			return nil, err
		}
		var binding struct {
			ID     domain.AccessBindingID `json:"id"`
			RoleID domain.RoleID          `json:"role_id"`
		}
		if len(rows) != 1 || json.Unmarshal(rows[0].value, &binding) != nil || binding.ID != id ||
			!nativeQuestionToken(string(binding.RoleID)) || (candidates[id] != "" && candidates[id] != binding.RoleID) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		if binding.RoleID != roleID {
			ids = append(ids, id)
		}
	}
	return ids, ctx.Err()
}

func (p *resourceParentCapture) captureAccessLabelMoveCollateralProjection(
	ctx context.Context, ref domain.ResourceRef, next domain.MirrorObject,
) (string, error) {
	old, present, err := p.captureObjectProjection(ctx, ref.Type, ref.ID)
	if err != nil {
		return "", err
	}
	if !present {
		return "", kaname.ErrSourceUnconfirmed
	}
	if err := p.source.budget.Charge(len(old.Labels)+len(next.Labels)+len(old.AccessLabels)+len(next.AccessLabels)+len(next.ParentAccountIDs), 0); err != nil {
		return "", err
	}
	return accessLabelMoveCollateralProjection(old, next)
}

func accessLabelMoveCollateralProjection(old, next domain.MirrorObject) (string, error) {
	if old.ObjectType != next.ObjectType || old.ObjectID != next.ObjectID || old.ParentProjectID != next.ParentProjectID ||
		!slices.Equal(old.ParentAccountIDs, next.ParentAccountIDs) || old.CreatedBy != next.CreatedBy || !maps.Equal(old.Labels, next.Labels) {
		return "", kaname.ErrSourceUnconfirmed
	}
	for k, v := range old.AccessLabels {
		if value, ok := next.AccessLabels[k]; !ok || value != v {
			return "", kaname.ErrSourceUnconfirmed
		}
	}
	if len(old.AccessLabels) == len(next.AccessLabels) {
		return "", nil
	}
	projection := resourceMetadataProjection{Labels: make(domain.Labels, len(old.Labels)), AccessLabels: make(domain.Labels, len(next.AccessLabels))}
	for k, v := range old.Labels {
		projection.Labels[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	for k, v := range next.AccessLabels {
		if _, existed := old.AccessLabels[k]; !existed {
			if source, ok := old.Labels[k]; !ok || source != v {
				return "", kaname.ErrSourceUnconfirmed
			}
		}
		projection.AccessLabels[domain.LabelKey(k)] = domain.LabelVal(v)
	}
	if projection.Labels.Validate() != nil || projection.AccessLabels.Validate() != nil {
		return "", kaname.ErrSourceUnconfirmed
	}
	raw, err := json.Marshal(projection)
	return string(raw), err
}

// Для чужой роли обе стороны используют одну сохранённую раскладку. Меняются
// только карты меток на объектах и предках. Координаты членов и журнала
// сохраняются также у неактивных носителей, включая уже исчезнувшие объекты.
func (p *resourceParentCapture) captureAccessLabelMoveCollateralScopes(
	ctx context.Context, facts *catalog.Facts, ids []domain.AccessBindingID, overlay map[domain.ResourceRef]domain.MirrorObject,
) ([]accessLabelSelectorMoveScope, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || facts == nil || ids == nil || overlay == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := p.source.budget.Charge(len(ids)+len(overlay), 0); err != nil {
		return nil, err
	}
	result := make([]accessLabelSelectorMoveScope, 0, len(ids))
	if len(ids) == 0 {
		return result, ctx.Err()
	}
	byType := make(map[string][]domain.MirrorObject)
	for ref, object := range overlay {
		projection, err := p.captureAccessLabelMoveCollateralProjection(ctx, ref, object)
		if err != nil {
			return nil, err
		}
		if projection != "" {
			byType[ref.Type] = append(byType[ref.Type], object)
		}
	}
	roles := make(map[domain.RoleID]domain.Role)
	ordered := slices.Sorted(slices.Values(ids))
	for i, id := range ordered {
		if !nativeQuestionToken(string(id)) || (i > 0 && ordered[i-1] == id) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: string(id)})
		if err != nil {
			return nil, err
		}
		if len(rows) != 1 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		binding, err := resourceCapturedBinding(rows[0].value)
		if err != nil {
			return nil, err
		}
		if binding.ID != id || !nativeQuestionToken(string(binding.RoleID)) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		carrier, err := readAccessLabelSelectorMoveCarrier(ctx, p.tx, p.source, binding)
		if err != nil {
			return nil, err
		}
		role, ok := roles[binding.RoleID]
		if !ok {
			key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(binding.RoleID)}
			roleRows, err := p.source.read(ctx, p.tx, key)
			if err != nil {
				return nil, err
			}
			if len(roleRows) != 1 {
				return nil, kaname.ErrSourceUnconfirmed
			}
			key.kind = resourceSourceRoleSelectors
			selectors, err := p.source.read(ctx, p.tx, key)
			if err != nil {
				return nil, err
			}
			role, err = resourceCapturedMaterializingRole(roleRows[0].value, selectors)
			if err != nil {
				return nil, err
			}
			if role.ID != binding.RoleID {
				return nil, kaname.ErrSourceUnconfirmed
			}
			roles[role.ID] = role
		}
		scope := bindingScopeFrom(facts, carrier.Binding, role)
		coordinates := maps.Clone(carrier.Coordinates)
		if carrier.canSelect() && role.Lifecycle.State == domain.RoleLifecycleDeclared {
			if err := p.source.budget.Charge(len(scope.Selectors), 0); err != nil {
				return nil, err
			}
			if err := p.captureBindingDiffScope(ctx, facts, coordinates, scope, resourceSourceSelectorObjects); err != nil {
				return nil, err
			}
			extra, err := p.captureAccessLabelMoveCarrierOverlay(ctx, scope, byType)
			if err != nil {
				return nil, err
			}
			for _, ref := range extra {
				coordinates[ref] = true
			}
		}
		keys, err := p.finishBindingDiffKeys(ctx, coordinates)
		if err != nil {
			return nil, err
		}
		result = append(result, accessLabelSelectorMoveScope{Carrier: carrier, Before: scope, Proposed: scope, Coordinates: keys})
	}
	return result, ctx.Err()
}

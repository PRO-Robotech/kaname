// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type resourceNestedPredicate struct {
	RuleFP        string              `json:"rule_fp"`
	ContainerType string              `json:"container_type"`
	ContainerIDs  []string            `json:"container_ids"`
	Scope         *domain.ScopeAnchor `json:"scope,omitempty"`
}

func resourceNestedDescendantsSQL(key resourceSourceKey, limit int) (string, []any, error) {
	var predicate resourceNestedPredicate
	roleOwned := key.kind == resourceSourceRoleNestedDescendants
	if (!roleOwned && key.kind != resourceSourceNestedDescendants && key.kind != resourceSourceRoleProposedNestedDescendants) || !nativeQuestionToken(key.typ) || !nativeQuestionToken(key.id) || limit < 1 || json.Unmarshal([]byte(key.projection), &predicate) != nil || !nativeQuestionToken(predicate.RuleFP) || !nativeQuestionToken(predicate.ContainerType) || len(predicate.ContainerIDs) == 0 {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	if roleOwned {
		if predicate.Scope == nil || (predicate.Scope.Type != "account" && predicate.Scope.Type != "project") || !nativeQuestionToken(predicate.Scope.ID) {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
	} else if predicate.Scope != nil {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	for _, id := range predicate.ContainerIDs {
		if !nativeQuestionToken(id) {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
	}
	// Не DISTINCT/ORDER BY до LIMIT: сохраняется каждая строка соединения и её
	// версия; координаты дедуплицируются только после полного bounded census.
	state := `jsonb_build_array(cc.xmin::text,cc.ctid::text,to_jsonb(cc),
 pe.xmin::text,pe.ctid::text,to_jsonb(pe),co.xmin::text,co.ctid::text,to_jsonb(co),
 m.xmin::text,m.ctid::text,to_jsonb(m))`
	from := ` FROM kaname.catalog_resource cc
 JOIN kaname.resource_parent_edge pe ON pe.parent_type=cc.object_type AND pe.parent_id=ANY($2::text[])
 JOIN kaname.catalog_resource co ON co.object_type=pe.object_type AND co.live
 JOIN kaname.resource_mirror m ON m.object_type=co.dotted AND m.object_id=pe.object_id`
	filter := ` WHERE cc.dotted=$1 AND cc.live AND m.object_type=$3`
	args := []any{predicate.ContainerType, predicate.ContainerIDs, key.typ, limit}
	if roleOwned {
		state += ` || jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p))`
		from += ` LEFT JOIN kaname.projects p ON p.id=m.parent_project_id`
		filter += ` AND (($5::text='project' AND m.parent_project_id=$6::text)
   OR ($5::text='account' AND (COALESCE(NULLIF(m.parent_account_id,''),p.account_id,'')=$6::text OR p.account_id=$6::text)))`
		args = append(args, predicate.Scope.Type, predicate.Scope.ID)
	}
	query := "SELECT (" + state + ")::text, jsonb_build_object('object_type',m.object_type,'object_id',m.object_id)::text" +
		from + filter + " LIMIT $4"
	return query, args, nil
}

func (p *resourceParentCapture) captureNestedCandidatesFrom(ctx context.Context, source resourceSourceKey, bs reconcile.BindingScope, selector domain.RuleSelector, includeParents bool) ([]domain.MirrorObject, error) {
	owner, err := reconcile.CapturedNestedOwnerSelector(selector)
	if err != nil {
		return nil, err
	}
	containers, err := p.captureSelectorFrom(ctx, source, owner, bs.Scope, bs.Target, selector.RuleFP, true)
	if err != nil {
		return nil, err
	}
	var ids []string
	roleOwned := source.kind == resourceSourceRoleSelectorObjects
	var result []domain.MirrorObject
	for _, container := range containers {
		if roleOwned {
			if !container.IsContainedIn(bs.Scope) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if err := p.confirmAccessLabelMoveDefinitionProject(ctx, container); err != nil {
				return nil, err
			}
		}
		selected, err := reconcile.CapturedNestedContainerSelected(selector, bs, container)
		if err != nil {
			return nil, err
		}
		if selected {
			ids = append(ids, container.ObjectID)
			// Именованное право регистрации лежит на выбранном родителе.
			// Его координата нужна для сверки даже при пустом списке детей.
			if includeParents {
				result = append(result, container)
			}
		}
	}
	descendants, err := p.captureNestedDescendantsFrom(ctx, source, bs, selector, ids)
	if err != nil {
		return nil, err
	}
	return append(result, descendants...), nil
}

func (p *resourceParentCapture) captureNestedDescendantsFrom(
	ctx context.Context, source resourceSourceKey, bs reconcile.BindingScope, selector domain.RuleSelector, ids []string,
) ([]domain.MirrorObject, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || selector.Container == nil ||
		(source.kind != resourceSourceSelectorObjects && source.kind != resourceSourceRoleSelectorObjects && source.kind != resourceSourceRoleProposedSelectorObjects) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if len(ids) == 0 {
		return nil, nil
	}
	ids = slices.Compact(slices.Sorted(slices.Values(ids)))
	predicate := resourceNestedPredicate{RuleFP: selector.RuleFP, ContainerType: selector.Container.Type, ContainerIDs: ids}
	kind := resourceSourceNestedDescendants
	switch source.kind {
	case resourceSourceRoleSelectorObjects:
		predicate.Scope = &bs.Scope
		kind = resourceSourceRoleNestedDescendants
	case resourceSourceRoleProposedSelectorObjects:
		kind = resourceSourceRoleProposedNestedDescendants
	}
	raw, err := json.Marshal(predicate)
	if err != nil {
		return nil, err
	}
	types := slices.Clone(selector.ObjectTypes)
	slices.Sort(types)
	types = slices.Compact(types)
	if err = p.source.budget.Charge(len(ids)+len(types), 0); err != nil {
		return nil, err
	}
	roleProjectChildren := selector.Container.Type == "iam.account" &&
		(kind == resourceSourceRoleNestedDescendants || kind == resourceSourceRoleProposedNestedDescendants)
	seen := map[domain.ResourceRef]bool{}
	var result []domain.MirrorObject
	for _, typ := range types {
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: kind, typ: typ, id: source.id, projection: string(raw)})
		if err != nil {
			return nil, err
		}
		for _, row := range rows {
			var coordinate struct {
				Type string `json:"object_type"`
				ID   string `json:"object_id"`
			}
			if json.Unmarshal(row.value, &coordinate) != nil || coordinate.Type != typ || !nativeQuestionToken(coordinate.ID) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			key := domain.ResourceRef{Type: typ, ID: coordinate.ID}
			if seen[key] {
				continue
			}
			seen[key] = true
			object, present, err := p.captureObjectProjection(ctx, typ, coordinate.ID)
			if err != nil {
				return nil, err
			}
			if !present {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if roleProjectChildren && typ == "iam.project" {
				object, err = p.captureNestedProjectShape(ctx, object)
				if err != nil {
					return nil, err
				}
			}
			// Предварительный набор может быть шире ветви ребёнка. Окончательный чистый
			// compiler применяет selector и проверку предка, сохраняя прежнюю семантику.
			result = append(result, object)
		}
	}
	return result, ctx.Err()
}

// Обычные метки и область вложенного потомка берутся из удержанного зеркала,
// как в DescendantsOf. Защищённые метки берутся из собственной строки проекта.
func (p *resourceParentCapture) captureNestedProjectShape(ctx context.Context, direct domain.MirrorObject) (domain.MirrorObject, error) {
	if direct.ObjectType != "iam.project" {
		return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
	}
	graph, found, err := p.captureObjectProjectionFrom(ctx, direct.ObjectType, direct.ObjectID, resourceSourceMirror)
	if err != nil {
		return domain.MirrorObject{}, err
	}
	if !found {
		return domain.MirrorObject{}, kaname.ErrSourceUnconfirmed
	}
	graph.AccessLabels = direct.AccessLabels
	return graph, nil
}

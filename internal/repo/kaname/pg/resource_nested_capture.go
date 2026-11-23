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
	RuleFP        string   `json:"rule_fp"`
	ContainerType string   `json:"container_type"`
	ContainerIDs  []string `json:"container_ids"`
}

func resourceNestedDescendantsSQL(key resourceSourceKey, limit int) (string, []any, error) {
	var predicate resourceNestedPredicate
	if key.kind != resourceSourceNestedDescendants || !nativeQuestionToken(key.typ) || !nativeQuestionToken(key.id) || limit < 1 || json.Unmarshal([]byte(key.projection), &predicate) != nil || !nativeQuestionToken(predicate.RuleFP) || !nativeQuestionToken(predicate.ContainerType) || len(predicate.ContainerIDs) == 0 {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	for _, id := range predicate.ContainerIDs {
		if !nativeQuestionToken(id) {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
	}
	// Не DISTINCT/ORDER BY до LIMIT: сохраняется каждая строка соединения и её
	// версия; координаты дедуплицируются только после полного bounded census.
	return `SELECT jsonb_build_array(cc.xmin::text,cc.ctid::text,to_jsonb(cc),
 pe.xmin::text,pe.ctid::text,to_jsonb(pe),co.xmin::text,co.ctid::text,to_jsonb(co),
 m.xmin::text,m.ctid::text,to_jsonb(m))::text,
 jsonb_build_object('object_type',m.object_type,'object_id',m.object_id)::text
 FROM kaname.catalog_resource cc
 JOIN kaname.resource_parent_edge pe ON pe.parent_type=cc.object_type AND pe.parent_id=ANY($2::text[])
 JOIN kaname.catalog_resource co ON co.object_type=pe.object_type AND co.live
 JOIN kaname.resource_mirror m ON m.object_type=co.dotted AND m.object_id=pe.object_id
 WHERE cc.dotted=$1 AND cc.live AND m.object_type=$3 LIMIT $4`, []any{predicate.ContainerType, predicate.ContainerIDs, key.typ, limit}, nil
}

func (p *resourceParentCapture) captureNestedObjectCandidates(ctx context.Context, bs reconcile.BindingScope, selector domain.RuleSelector, includeParents bool) ([]domain.MirrorObject, error) {
	owner, err := reconcile.CapturedNestedOwnerSelector(selector)
	if err != nil {
		return nil, err
	}
	containers, err := p.captureSelectorPredicate(ctx, bs.BindingID, owner, bs.Scope, bs.Target, selector.RuleFP, true)
	if err != nil {
		return nil, err
	}
	var ids []string
	var result []domain.MirrorObject
	for _, container := range containers {
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
	if len(ids) == 0 {
		return nil, nil
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	raw, err := json.Marshal(resourceNestedPredicate{RuleFP: selector.RuleFP, ContainerType: selector.Container.Type, ContainerIDs: ids})
	if err != nil {
		return nil, err
	}
	types := slices.Clone(selector.ObjectTypes)
	slices.Sort(types)
	types = slices.Compact(types)
	if err = p.source.budget.Charge(len(ids)+len(types), 0); err != nil {
		return nil, err
	}
	seen := map[domain.ResourceRef]bool{}
	for _, typ := range types {
		rows, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceNestedDescendants, typ: typ, id: string(bs.BindingID), projection: string(raw)})
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
			// Предварительный набор может быть шире ветви ребёнка. Окончательный чистый
			// compiler применяет selector и проверку предка, сохраняя прежнюю семантику.
			result = append(result, object)
		}
	}
	return result, ctx.Err()
}

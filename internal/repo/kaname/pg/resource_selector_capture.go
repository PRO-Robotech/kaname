// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Предикат создаётся только из captured selector и binding scope. Он сохраняет
// широкий NAMES/LABELS census для прежнего REJECTED audit чужой области; ANCHOR
// ограничен областью либо точной целью, как matchByArm. Это не allow и не LIMIT
// вместо полноты: общий reader отвергает sentinel сверх остатка бюджета.
type resourceSelectorPredicate struct {
	Container    bool               `json:"container"`
	RuleFP       string             `json:"rule_fp"`
	Targets      []string           `json:"targets"`
	Arm          domain.Arm         `json:"arm"`
	Names        []string           `json:"names"`
	Labels       map[string]string  `json:"labels"`
	Scope        domain.ScopeAnchor `json:"scope"`
	AccessLabels map[string]string  `json:"access_labels,omitempty"`
}

func resourceSelectorObjectsSQL(key resourceSourceKey, limit int) (string, []any, error) {
	var predicate resourceSelectorPredicate
	if key.kind != resourceSourceSelectorObjects || !nativeQuestionToken(key.typ) || !nativeQuestionToken(key.id) || limit < 1 || json.Unmarshal([]byte(key.projection), &predicate) != nil {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	if !nativeQuestionToken(predicate.RuleFP) {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	arm := ""
	switch predicate.Arm {
	case domain.ArmAnchor:
		arm = "anchor"
	case domain.ArmNames:
		arm = "names"
	case domain.ArmLabels:
		arm = "labels"
	case domain.ArmAccessLabels:
		arm = "access_labels"
	default:
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	// The new predicate has its own namespace; an ordinary arm cannot carry it.
	if predicate.Arm == domain.ArmAccessLabels {
		if len(predicate.AccessLabels) == 0 || len(predicate.AccessLabels) > 16 || len(predicate.Labels) != 0 || len(predicate.Names) != 0 {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
		for key, value := range predicate.AccessLabels {
			if domain.LabelKey(key).Validate() != nil || domain.LabelVal(value).Validate() != nil {
				return "", nil, kaname.ErrSourceUnconfirmed
			}
		}
	} else if len(predicate.AccessLabels) != 0 {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	if predicate.Scope.Type != "account" && predicate.Scope.Type != "project" && predicate.Scope.Type != "cluster" {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	if !nativeQuestionToken(predicate.Scope.ID) {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	for _, id := range append(slices.Clone(predicate.Names), predicate.Targets...) {
		if !nativeQuestionToken(id) {
			return "", nil, kaname.ErrSourceUnconfirmed
		}
	}
	labels, err := json.Marshal(predicate.Labels)
	if err != nil {
		return "", nil, err
	}
	if predicate.Labels == nil {
		labels = []byte("{}")
	}
	accessLabels, err := json.Marshal(predicate.AccessLabels)
	if err != nil {
		return "", nil, err
	}
	if predicate.AccessLabels == nil {
		accessLabels = []byte("{}")
	}
	if predicate.Targets == nil {
		predicate.Targets = []string{}
	}
	// Параметры типизированы во всех ветвях: один SQL shape для каждой таблицы.
	args := []any{key.typ, limit, arm, predicate.Names, labels, predicate.Scope.Type, predicate.Scope.ID, predicate.Targets, accessLabels}
	source := "kaname.resource_mirror o LEFT JOIN kaname.projects p ON p.id=o.parent_project_id"
	identity := "o.object_id"
	typeFilter := "o.object_type=$1"
	account := "COALESCE(NULLIF(o.parent_account_id,''),p.account_id,'')=$7::text"
	project := "o.parent_project_id=$7::text"
	state := "jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o),p.xmin::text,p.ctid::text,to_jsonb(p))::text"
	if spec, ok := iamDirectScanSpecs[key.typ]; ok {
		source = spec.table + " o " + spec.join
		identity = "o.id"
		typeFilter = "$1::text<>''"
		account = spec.parentAccountExpr + "=$7::text"
		if key.typ == "iam.user" {
			account = "EXISTS(SELECT 1 FROM kaname.memberships membership WHERE membership.user_id=o.id AND membership.account_id=$7::text)"
		}
		project = spec.parentProjectExpr + "=$7::text"
		state = "jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o))::text"
		if spec.join != "" {
			state = "jsonb_build_array(o.xmin::text,o.ctid::text,to_jsonb(o),p.xmin::text,p.ctid::text,to_jsonb(p))::text"
		}
	} else if domain.FeedSourceForType(key.typ) == domain.FeedIAMDirect {
		return "", nil, kaname.ErrSourceUnconfirmed
	}
	query := "SELECT " + state + ",jsonb_build_object('object_type',$1::text,'object_id'," + identity + ")::text FROM " + source + " WHERE " + typeFilter + " AND (($3::text='names' AND " + identity + "=ANY($4::text[])) OR ($3::text='labels' AND o.labels @> $5::jsonb) OR ($3::text='access_labels' AND o.access_labels @> $9::jsonb) OR ($3::text='anchor' AND ($6::text='cluster' OR ($6::text='account' AND (" + account + ")) OR ($6::text='project' AND (" + project + "))))) AND (cardinality($8::text[])=0 OR " + identity + "=ANY($8::text[])) LIMIT $2"
	return query, args, nil
}

func (p *resourceParentCapture) captureSelectorObjects(ctx context.Context, binding domain.AccessBindingID, selector domain.RuleSelector, scope domain.ScopeAnchor, target domain.AccessTarget) ([]domain.MirrorObject, error) {
	return p.captureSelectorPredicate(ctx, binding, selector, scope, target, selector.RuleFP, false)
}

// Для owner-ветви сохраняем fingerprint исходного nested selector. Сервер
// сверяет его container columns; синтетический owner FP не выдаётся за PK.
func (p *resourceParentCapture) captureSelectorPredicate(ctx context.Context, binding domain.AccessBindingID, selector domain.RuleSelector, scope domain.ScopeAnchor, target domain.AccessTarget, sourceFP string, container bool) ([]domain.MirrorObject, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || binding == "" || selector.RuleFP == "" || !nativeQuestionToken(sourceFP) || selector.Container != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	types := slices.Clone(selector.ObjectTypes)
	slices.Sort(types)
	types = slices.Compact(types)
	if err := p.source.budget.Charge(len(types)+len(selector.ResourceNames)+len(selector.MatchLabels)+len(selector.MatchAccessLabels)+len(target.Resources), 0); err != nil {
		return nil, err
	}
	var result []domain.MirrorObject
	for _, typ := range types {
		predicate := resourceSelectorPredicate{RuleFP: sourceFP, Container: container, Arm: selector.Arm, Names: selector.ResourceNames, Labels: selector.MatchLabels, Scope: scope, AccessLabels: selector.MatchAccessLabels}
		if len(target.Resources) > 0 {
			predicate.Targets = target.ResourceIDsForTypes([]string{typ})
			if len(predicate.Targets) == 0 {
				continue
			}
		} else {
			predicate.Targets = []string{}
		}
		if selector.Arm == domain.ArmAnchor && len(target.Resources) > 0 {
			predicate.Arm = domain.ArmNames
			predicate.Names = target.ResourceIDsForTypes([]string{typ})
			if len(predicate.Names) == 0 {
				continue
			}
		}
		raw, err := json.Marshal(predicate)
		if err != nil {
			return nil, err
		}
		key := resourceSourceKey{kind: resourceSourceSelectorObjects, typ: typ, id: string(binding), projection: string(raw)}
		rows, err := p.source.read(ctx, p.tx, key)
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
			if len(target.Resources) > 0 && !target.Contains(typ, coordinate.ID) {
				return nil, kaname.ErrSourceUnconfirmed
			}
			object, present, err := p.captureObjectProjection(ctx, typ, coordinate.ID)
			if err != nil {
				return nil, err
			}
			if !present {
				return nil, kaname.ErrSourceUnconfirmed
			}
			result = append(result, object)
		}
	}
	return result, ctx.Err()
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"maps"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/resourceeffect"
)

// Владелец формирует вход по удержанным источникам. Строки привязки,
// роли и селекторов декодируются один раз на все её координаты.
type metadataAccessLabelDesiredEnvelope struct {
	Bindings    map[string]metadataAccessLabelDesiredBinding `json:"bindings"`
	Coordinates map[string]metadataAccessLabelDesiredGraph   `json:"coordinates"`
}

type metadataAccessLabelDesiredBinding struct {
	Binding      json.RawMessage   `json:"binding"`
	SubjectRows  []json.RawMessage `json:"subject_rows"`
	Role         json.RawMessage   `json:"role"`
	SelectorRows []json.RawMessage `json:"selector_rows"`
}

type metadataAccessLabelDesiredProjection struct {
	ObjectType      string          `json:"object_type"`
	ObjectID        string          `json:"object_id"`
	Present         *bool           `json:"present"`
	Projection      json.RawMessage `json:"projection"`
	CurrentAccounts []string        `json:"current_accounts"`
	CurrentProject  *string         `json:"current_project"`
}

type metadataAccessLabelDesiredGraph struct {
	metadataAccessLabelDesiredProjection
	// [] подтверждает отсутствие предков. Поле обязательно.
	Ancestors []metadataAccessLabelDesiredProjection `json:"ancestors"`
}

type metadataAccessLabelDesiredBindingScope struct {
	Scope    reconcile.BindingScope
	Eligible bool
}

// Компилирует предложения по NEW-проекциям, подготовленным в SQL.
// Владелец сверяет каждый массив с удержанным OLD и той же NEW-проекцией.
func compileMetadataAccessLabelDesired(ctx context.Context, facts *catalog.Facts, raw json.RawMessage, budget *relverdict.AdministrativeReadBudget) (json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if facts == nil || budget == nil || len(raw) == 0 || len(raw) > 64*1024*1024 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var envelope metadataAccessLabelDesiredEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	if envelope.Bindings == nil || envelope.Coordinates == nil || len(envelope.Bindings) > 4096 || len(envelope.Coordinates) > 4096 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	bindings := make(map[string]metadataAccessLabelDesiredBindingScope, len(envelope.Bindings))
	for _, id := range slices.Sorted(maps.Keys(envelope.Bindings)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		in := envelope.Bindings[id]
		if !nativeQuestionToken(id) || in.SubjectRows == nil || in.SelectorRows == nil || len(in.SubjectRows) > 4096 || len(in.SelectorRows) > 4096 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		binding, err := resourceCapturedBinding(in.Binding)
		if err != nil {
			return nil, err
		}
		if string(binding.ID) != id || (binding.Status != domain.AccessBindingStatusActive && binding.Status != domain.AccessBindingStatusPending && binding.Status != domain.AccessBindingStatusRevoked) {
			return nil, kaname.ErrSourceUnconfirmed
		}
		subjectRows, err := metadataDesiredSourceRows(in.SubjectRows)
		if err != nil {
			return nil, err
		}
		binding.Subjects, err = resourceCapturedSubjects(binding, subjectRows)
		if err != nil {
			return nil, err
		}
		var role domain.Role
		if binding.RoleID != "" {
			selectorRows, err := metadataDesiredSourceRows(in.SelectorRows)
			if err != nil {
				return nil, err
			}
			role, err = resourceCapturedMaterializingRole(in.Role, selectorRows)
			if err != nil {
				return nil, err
			}
			if role.ID != binding.RoleID {
				return nil, kaname.ErrSourceUnconfirmed
			}
		} else if len(in.SelectorRows) != 0 || string(in.Role) != "null" {
			return nil, kaname.ErrSourceUnconfirmed
		}
		// Статус проверяется после чтения всех обязательных полей.
		scope := bindingScopeFrom(facts, binding, role)
		bindings[id] = metadataAccessLabelDesiredBindingScope{Scope: scope, Eligible: binding.Status == domain.AccessBindingStatusActive && binding.RoleID != "" && role.Lifecycle.State == domain.RoleLifecycleDeclared}
		if err := budget.Charge(1, 0); err != nil {
			return nil, kaname.ErrSourceReadLimit
		}
	}
	result := make(map[string][]reconcile.DesiredMember, len(envelope.Coordinates))
	for _, key := range slices.Sorted(maps.Keys(envelope.Coordinates)) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var coordinate []string
		if err := json.Unmarshal([]byte(key), &coordinate); err != nil || len(coordinate) != 3 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		binding, known := bindings[coordinate[0]]
		graph := envelope.Coordinates[key]
		if !known || graph.ObjectType != coordinate[1] || graph.ObjectID != coordinate[2] || graph.Ancestors == nil || len(graph.Ancestors) > 4 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		object, present, err := metadataDesiredProjection(graph.metadataAccessLabelDesiredProjection)
		if err != nil {
			return nil, err
		}
		ancestors := make([]domain.MirrorObject, 0, len(graph.Ancestors))
		seen := map[domain.ResourceRef]bool{{Type: object.ObjectType, ID: object.ObjectID}: true}
		for _, projection := range graph.Ancestors {
			ancestor, found, err := metadataDesiredProjection(projection)
			if err != nil {
				return nil, err
			}
			ref := domain.ResourceRef{Type: ancestor.ObjectType, ID: ancestor.ObjectID}
			if !found || seen[ref] {
				return nil, kaname.ErrSourceUnconfirmed
			}
			seen[ref] = true
			ancestors = append(ancestors, ancestor)
		}
		if (!present || domain.FeedSourceForType(object.ObjectType) == domain.FeedIAMDirect) && len(ancestors) != 0 {
			return nil, kaname.ErrSourceUnconfirmed
		}
		// Пустой вклад допускается для подтверждённой неактивности
		// или полного свидетельства об отсутствии объекта.
		if !present || !binding.Eligible {
			if err := budget.Charge(1, 0); err != nil {
				return nil, kaname.ErrSourceReadLimit
			}
			result[key] = []reconcile.DesiredMember{}
			continue
		}
		scope := binding.Scope
		desired, err := resourceeffect.CompileObjectDesired(facts, resourceeffect.ObjectBinding{
			BindingID: scope.BindingID, RoleID: scope.RoleID, Scope: scope.Scope, Subjects: scope.Subjects,
			Policy: scope.Policy, Selectors: scope.Selectors, ScopeSelfVerbs: scope.ScopeSelfVerbs, Target: scope.Target, Active: scope.Active,
		}, object, ancestors)
		if err != nil {
			return nil, err
		}
		if len(desired) > 4096 {
			return nil, kaname.ErrSourceReadLimit
		}
		cost := 1 + len(desired)
		for _, member := range desired {
			if len(member.Tuples) > 100000 || cost > 100000-len(member.Tuples) {
				return nil, kaname.ErrSourceReadLimit
			}
			cost += len(member.Tuples)
		}
		if err := budget.Charge(cost, 0); err != nil {
			return nil, kaname.ErrSourceReadLimit
		}
		members := make([]reconcile.DesiredMember, 0, len(desired))
		for _, member := range desired {
			if member.ObjectType != object.ObjectType || member.ObjectID != object.ObjectID {
				return nil, kaname.ErrSourceUnconfirmed
			}
			members = append(members, reconcile.DesiredMember{Derivation: member.Derivation, RuleFP: member.RuleFP, ObjectType: member.ObjectType, ObjectID: member.ObjectID, Status: member.Status, Tuples: slices.Clone(member.Tuples)})
		}
		// SQL сверяет текст ключа целиком, включая пробелы в JSONB.
		result[key] = members
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if len(encoded) > 8*1024*1024 {
		return nil, kaname.ErrSourceReadLimit
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return encoded, nil
}

func metadataDesiredSourceRows(raw []json.RawMessage) ([]resourceSourceRow, error) {
	if raw == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	rows := make([]resourceSourceRow, 0, len(raw))
	for _, value := range raw {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(value, &object); err != nil || object == nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
		// Общему декодеру требуется только значение строки.
		rows = append(rows, resourceSourceRow{value: value})
	}
	return rows, nil
}

func metadataDesiredProjection(p metadataAccessLabelDesiredProjection) (domain.MirrorObject, bool, error) {
	empty := domain.MirrorObject{}
	if !nativeQuestionToken(p.ObjectType) || !nativeQuestionToken(p.ObjectID) || p.Present == nil || p.CurrentAccounts == nil || p.CurrentProject == nil || len(p.CurrentAccounts) > 4096 || !slices.IsSorted(p.CurrentAccounts) {
		return empty, false, kaname.ErrSourceUnconfirmed
	}
	for i, id := range p.CurrentAccounts {
		if !nativeQuestionToken(id) || (i > 0 && p.CurrentAccounts[i-1] == id) {
			return empty, false, kaname.ErrSourceUnconfirmed
		}
	}
	if *p.CurrentProject != "" && !nativeQuestionToken(*p.CurrentProject) {
		return empty, false, kaname.ErrSourceUnconfirmed
	}
	out := domain.MirrorObject{ObjectType: p.ObjectType, ObjectID: p.ObjectID, ParentProjectID: *p.CurrentProject, ParentAccountIDs: slices.Clone(p.CurrentAccounts)}
	if !*p.Present {
		if string(p.Projection) != "null" || len(p.CurrentAccounts) != 0 || *p.CurrentProject != "" {
			return empty, false, kaname.ErrSourceUnconfirmed
		}
		return out, false, nil
	}
	var row struct {
		ID           string            `json:"id"`
		ObjectType   string            `json:"object_type"`
		ObjectID     string            `json:"object_id"`
		Labels       map[string]string `json:"labels"`
		AccessLabels map[string]string `json:"access_labels"`
		CreatorType  string            `json:"created_by_type"`
		CreatorID    string            `json:"created_by_id"`
	}
	if err := json.Unmarshal(p.Projection, &row); err != nil {
		return empty, false, err
	}
	if domain.FeedSourceForType(p.ObjectType) == domain.FeedIAMDirect {
		if row.ID != p.ObjectID {
			return empty, false, kaname.ErrSourceUnconfirmed
		}
	} else if row.ObjectType != p.ObjectType || row.ObjectID != p.ObjectID {
		return empty, false, kaname.ErrSourceUnconfirmed
	}
	out.Labels = maps.Clone(row.Labels)
	out.AccessLabels = maps.Clone(row.AccessLabels)
	if p.ObjectType == "iam.serviceAccount" && row.CreatorType != "" && row.CreatorID != "" {
		out.CreatedBy = row.CreatorType + ":" + row.CreatorID
	}

	return out, true, nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"cmp"
	"context"
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Полный binding нужен только по прежнему nested-container маршруту. Набор
// кандидатов включает исчезнувшие members и ledger: отсутствие живого mirror
// не удаляет старые координаты до вычисления отзыва. Это ещё RR input, не право
// применить команды и не подтверждение финальной живости после ожиданий.
func (c *resourceOutputCapture) captureWholeBindingDiff(ctx context.Context, parents *resourceParentCapture, facts *catalog.Facts, id, changedType string, additive bool) (reconcile.CapturedObjectDiff, []*resourceOutputCapture, error) {
	var empty reconcile.CapturedObjectDiff
	if c == nil || parents == nil || parents.source == nil || parents.source.sealed || facts == nil {
		return empty, nil, kaname.ErrSourceUnconfirmed
	}
	binding, ok := c.bindings[id]
	if !ok {
		return empty, nil, kaname.ErrSourceUnconfirmed
	}
	role, ok := c.roles[string(binding.RoleID)]
	if binding.RoleID != "" && !ok {
		return empty, nil, kaname.ErrSourceUnconfirmed
	}
	bs := bindingScopeFrom(facts, binding, role)
	whole, _ := reconcile.CapturedObjectDependencyShape(bs, changedType)
	if !whole || !bs.Active {
		return empty, nil, kaname.ErrSourceUnconfirmed
	}
	members, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: id})
	if err != nil {
		return empty, nil, err
	}
	ledger, err := parents.source.read(ctx, parents.tx, resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: id})
	if err != nil {
		return empty, nil, err
	}
	coordinates, fullLedger, err := resourceBindingDiffCoordinates(id, members, ledger)
	if err != nil {
		return empty, nil, err
	}
	hasHuman := slices.ContainsFunc(bs.Subjects, func(subject domain.Subject) bool {
		return subject.Type == domain.SubjectTypeUser
	})
	for _, selector := range bs.Selectors {
		// То же исключение классов и пустого набора глаголов, что у live traversal.
		if len(domain.GrantRecipients(bs.Subjects, selector.Verbs, selector.Container != nil)) == 0 {
			continue
		}
		var objects []domain.MirrorObject
		if selector.Container != nil {
			includeParents := hasHuman && len(facts.ChildRegistrationActions(selector)) != 0
			objects, err = parents.captureNestedObjectCandidates(ctx, bs, selector, includeParents)
		} else {
			objects, err = parents.captureSelectorObjects(ctx, bs.BindingID, selector, bs.Scope, bs.Target)
		}
		if err != nil {
			return empty, nil, err
		}
		for _, object := range objects {
			coordinates[domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}] = true
		}
	}
	// Якорный member выводится полным materializer даже без content selector.
	// ContainerVerb может дать parent tuple даже при retired mapping якоря.
	// Его существование и владелец ниже подтверждаются обычной IAM projection.
	if bs.Scope.Type == "account" || bs.Scope.Type == "project" {
		coordinates[domain.ResourceRef{Type: "iam." + bs.Scope.Type, ID: bs.Scope.ID}] = true
	}
	if err = parents.source.budget.Charge(len(coordinates), 0); err != nil {
		return empty, nil, err
	}
	keys := make([]domain.ResourceRef, 0, len(coordinates))
	for key := range coordinates {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b domain.ResourceRef) int {
		if n := cmp.Compare(a.Type, b.Type); n != 0 {
			return n
		}
		return cmp.Compare(a.ID, b.ID)
	})
	result := reconcile.CapturedObjectDiff{Binding: bs, Ledger: fullLedger, Additive: additive, Live: map[reconcile.MemberCoord]bool{}}
	var outputs []*resourceOutputCapture
	for _, key := range keys {
		if err = ctx.Err(); err != nil {
			return empty, nil, err
		}
		object, present, err := parents.captureObjectProjection(ctx, key.Type, key.ID)
		if err != nil {
			return empty, nil, err
		}
		if !present {
			object = domain.MirrorObject{ObjectType: key.Type, ObjectID: key.ID}
		}
		catalogCapture, err := parents.catalog(ctx, key.Type)
		if err != nil {
			return empty, nil, err
		}
		catalogRow, known := catalogCapture.selected()
		if !known || catalogRow.identity.Dotted != key.Type {
			return empty, nil, kaname.ErrSourceUnconfirmed
		}
		output, err := captureResourceOutput(ctx, parents, catalogRow, key.ID)
		if err != nil {
			return empty, nil, err
		}
		// Нулевые holders всё равно должны получить явно захваченную выдачу,
		// выбранную полным nested traversal, а не повторным live candidate query.
		output.bindings[id] = binding
		output.selected = map[string]bool{id: true}
		if binding.RoleID != "" {
			output.roles[string(binding.RoleID)] = role
		}
		ancestors, err := parents.captureObjectAncestors(ctx, key.Type, key.ID, present)
		if err != nil {
			return empty, nil, err
		}
		inputs, err := output.coordinateDiffInputs(ctx, parents, facts, object, present, ancestors, additive)
		if err != nil {
			return empty, nil, err
		}
		found := false
		for _, input := range inputs {
			if string(input.Binding.BindingID) != id {
				continue
			}
			found = true
			result.Current = append(result.Current, input.Current...)
			result.Desired = append(result.Desired, input.Desired...)
			for coordinate, live := range input.Live {
				result.Live[coordinate] = live
			}
		}
		if !found {
			return empty, nil, kaname.ErrSourceUnconfirmed
		}
		outputs = append(outputs, output)
	}
	return result, outputs, ctx.Err()
}

// Структурные ledger rows имеют обе пустые member-координаты. Они сохраняются
// в полном ledger, как в существующем LedgerTuples, но не превращаются в
// фиктивный ресурс. Неполная пара или чужой binding — повреждённый источник.
func resourceBindingDiffCoordinates(binding string, members, ledger []resourceSourceRow) (map[domain.ResourceRef]bool, []reconcile.LedgerRow, error) {
	if !nativeQuestionToken(binding) {
		return nil, nil, kaname.ErrSourceUnconfirmed
	}
	coordinates := map[domain.ResourceRef]bool{}
	for _, captured := range members {
		var row struct {
			Binding string `json:"binding_id"`
			Type    string `json:"object_type"`
			ID      string `json:"object_id"`
		}
		if json.Unmarshal(captured.value, &row) != nil || row.Binding != binding || !nativeQuestionToken(row.Type) || !nativeQuestionToken(row.ID) {
			return nil, nil, kaname.ErrSourceUnconfirmed
		}
		coordinates[domain.ResourceRef{Type: row.Type, ID: row.ID}] = true
	}
	var rows []reconcile.LedgerRow
	for _, captured := range ledger {
		var row struct {
			Binding  string `json:"binding_id"`
			Type     string `json:"member_object_type"`
			ID       string `json:"member_object_id"`
			User     string `json:"fga_user"`
			Relation string `json:"relation"`
			Object   string `json:"object"`
		}
		if json.Unmarshal(captured.value, &row) != nil || row.Binding != binding || row.User == "" || row.Relation == "" || row.Object == "" || (row.Type == "") != (row.ID == "") {
			return nil, nil, kaname.ErrSourceUnconfirmed
		}
		if row.Type != "" {
			if !nativeQuestionToken(row.Type) || !nativeQuestionToken(row.ID) {
				return nil, nil, kaname.ErrSourceUnconfirmed
			}
			coordinates[domain.ResourceRef{Type: row.Type, ID: row.ID}] = true
		}
		rows = append(rows, reconcile.LedgerRow{Member: reconcile.MemberCoord{ObjectType: row.Type, ObjectID: row.ID}, Tuple: domain.MembershipTuple{User: row.User, Relation: row.Relation, Object: row.Object}})
	}
	return coordinates, rows, nil
}

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
	coordinates, fullLedger, err := parents.captureBindingDiffHistory(ctx, id)
	if err != nil {
		return empty, nil, err
	}
	keys, err := parents.captureBindingDiffKeys(ctx, facts, coordinates, bs)
	if err != nil {
		return empty, nil, err
	}
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

func (p *resourceParentCapture) captureBindingDiffHistory(ctx context.Context, id string) (map[domain.ResourceRef]bool, []reconcile.LedgerRow, error) {
	members, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBindingMembers, typ: "binding", id: id})
	if err != nil {
		return nil, nil, err
	}
	ledger, err := p.source.read(ctx, p.tx, resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: id})
	if err != nil {
		return nil, nil, err
	}
	return resourceBindingDiffCoordinates(id, members, ledger)
}

// captureBindingDiffKeys сохраняет старые координаты журнала и объединяет
// их с кандидатами каждого переданного набора селекторов в том же снимке.
// Предикаты RR удерживаются по отдельности; совпадение ключа объекта
// не подменяет доказательство полноты ни одного из исходных предикатов.
func (p *resourceParentCapture) captureBindingDiffKeys(ctx context.Context, facts *catalog.Facts, coordinates map[domain.ResourceRef]bool, scopes ...reconcile.BindingScope) ([]domain.ResourceRef, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil || coordinates == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for _, scope := range scopes {
		if err := p.captureBindingDiffScope(ctx, facts, coordinates, scope, resourceSourceSelectorObjects); err != nil {
			return nil, err
		}
	}
	return p.finishBindingDiffKeys(ctx, coordinates)
}

func (p *resourceParentCapture) captureBindingDiffScope(
	ctx context.Context, facts *catalog.Facts, coordinates map[domain.ResourceRef]bool, scope reconcile.BindingScope, kind resourceSourceKind,
) error {
	source := resourceSourceKey{kind: kind, id: string(scope.BindingID)}
	hasHuman := slices.ContainsFunc(scope.Subjects, func(subject domain.Subject) bool {
		return subject.Type == domain.SubjectTypeUser
	})
	for _, selector := range scope.Selectors {
		// Те же получатели, что у полного materializer.
		if len(domain.GrantRecipients(scope.Subjects, selector.Verbs, selector.Container != nil)) == 0 {
			continue
		}
		var objects []domain.MirrorObject
		var err error
		if selector.Container != nil {
			includeParents := hasHuman && len(facts.ChildRegistrationActions(selector)) != 0
			objects, err = p.captureNestedCandidatesFrom(ctx, source, scope, selector, includeParents)
		} else {
			objects, err = p.captureSelectorFrom(ctx, source, selector, scope.Scope, scope.Target, selector.RuleFP, false)
		}
		if err != nil {
			return err
		}
		for _, object := range objects {
			coordinates[domain.ResourceRef{Type: object.ObjectType, ID: object.ObjectID}] = true
		}
	}
	// scope_self и контейнерные действия могут меняться даже тогда,
	// когда ни один предикат содержимого не выбрал объект.
	if scope.Scope.Type == "account" || scope.Scope.Type == "project" {
		coordinates[domain.ResourceRef{Type: "iam." + scope.Scope.Type, ID: scope.Scope.ID}] = true
	}
	return ctx.Err()
}

func (p *resourceParentCapture) finishBindingDiffKeys(ctx context.Context, coordinates map[domain.ResourceRef]bool) ([]domain.ResourceRef, error) {
	if err := p.source.budget.Charge(len(coordinates), 0); err != nil {
		return nil, err
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
	return keys, ctx.Err()
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

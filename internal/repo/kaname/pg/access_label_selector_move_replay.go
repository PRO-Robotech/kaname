// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// После проверки SQL запоминаем образ и операции внутри того же RR.
type accessLabelMoveRRProof struct {
	source  *resourceSourceCapture
	role    domain.RoleID
	version string
	rules   []byte
	image   json.RawMessage
	moves   []selectorMovePosition
	updates accessLabelMoveObjectUpdates
	copies  json.RawMessage
}

func (p *resourceParentCapture) rememberAccessLabelMoveRR(c accessLabelSelectorMoveCapture) (*accessLabelMoveRRProof, error) {
	rules, err := rulesToJSON(c.ProposedRules)
	if err != nil {
		return nil, err
	}
	moves := make([]selectorMovePosition, 0, len(c.Moves))
	for _, move := range c.Moves {
		rule, child := move.Position()
		moves = append(moves, selectorMovePosition{Rule: rule, Child: child})
	}
	return &accessLabelMoveRRProof{source: p.source, role: c.Before.ID, version: c.Before.ResourceVersion,
		rules: rules, image: slices.Clone(c.ProposedImage), moves: moves, updates: maps.Clone(c.copyUpdates),
		copies: slices.Clone(c.copyPlan)}, nil
}

// Передаётся только роль и точная редакция правил из RR. Предикаты являются
// предложением для закрытого SQL владельца роли. Одного snapshot replay
// недостаточно для защиты от вставки после чтения.
type accessLabelMoveSourceReplay struct {
	parents    *resourceParentCapture
	role       domain.Role
	version    string
	rules      []byte
	image      json.RawMessage
	predicates []resourcePredicateProtection
	updates    accessLabelMoveObjectUpdates
	copyPlan   json.RawMessage
}

func (p *resourceParentCapture) sealAccessLabelMoveReplay(
	captured accessLabelSelectorMoveCapture,
) (*accessLabelMoveSourceReplay, error) {
	if p == nil || p.source == nil || p.source.sealed || p.source.budget == nil ||
		(p.source.metadataParents != nil && p.source.metadataParents != p) || captured.Before.ID == "" || captured.Before.ResourceVersion == "" || len(captured.Moves) == 0 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	proof := captured.proof
	if proof == nil || proof.source != p.source || proof.role != captured.Before.ID || proof.version != captured.Before.ResourceVersion ||
		!bytes.Equal(proof.image, captured.ProposedImage) || len(proof.moves) != len(captured.Moves) ||
		!maps.Equal(proof.updates, captured.copyUpdates) || !bytes.Equal(proof.copies, captured.copyPlan) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for i, move := range captured.Moves {
		rule, child := move.Position()
		if proof.moves[i] != (selectorMovePosition{Rule: rule, Child: child}) {
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	key := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(captured.Before.ID)}
	rows := p.source.entries[key]
	if len(rows) != 1 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	var state []json.RawMessage
	var xmin string
	if json.Unmarshal([]byte(rows[0].state), &state) != nil || len(state) != 3 ||
		json.Unmarshal(state[0], &xmin) != nil || xmin != captured.Before.ResourceVersion {
		return nil, kaname.ErrSourceUnconfirmed
	}
	held, err := resourceCapturedRole(rows[0].value)
	if err != nil || held.ID != captured.Before.ID || held.AccountID != captured.Before.AccountID ||
		held.ProjectID != captured.Before.ProjectID || held.ClusterID != captured.Before.ClusterID ||
		held.IsSystem != captured.Before.IsSystem || held.OwnerModule != captured.Before.OwnerModule {
		return nil, kaname.ErrSourceUnconfirmed
	}
	original, err := rulesToJSON(held.Rules)
	if err != nil {
		return nil, err
	}
	capturedBefore, err := rulesToJSON(captured.Before.Rules)
	if err != nil || !bytes.Equal(original, capturedBefore) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	expected, err := rulesToJSON(captured.ProposedRules)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(proof.rules, expected) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	scope := domain.ScopeAnchor{Type: "account", ID: string(held.AccountID)}
	if held.ProjectID != "" {
		scope = domain.ScopeAnchor{Type: "project", ID: string(held.ProjectID)}
	}
	out := &accessLabelMoveSourceReplay{
		parents: p, role: held, version: xmin, rules: expected, image: slices.Clone(proof.image), updates: maps.Clone(proof.updates), copyPlan: slices.Clone(proof.copies),
	}
	count := len(captured.Carriers) + len(captured.Collateral)
	if err = p.source.budget.Charge(count, 0); err != nil {
		return nil, err
	}
	bindings := make(map[string]reconcile.BindingScope, count)
	for i, carriers := range [][]accessLabelSelectorMoveScope{captured.Carriers, captured.Collateral} {
		for _, carrier := range carriers {
			scope, binding := carrier.Proposed, carrier.Carrier.Binding
			id := string(scope.BindingID)
			if !nativeQuestionToken(id) || scope.BindingID != binding.ID || scope.RoleID != string(binding.RoleID) ||
				(binding.RoleID == held.ID) != (i == 0) || scope.Scope != scopeAnchorFor(binding) ||
				scope.Target.Digest() != binding.Target.Digest() {
				return nil, kaname.ErrSourceUnconfirmed
			}
			if _, exists := bindings[id]; exists {
				return nil, kaname.ErrSourceUnconfirmed
			}
			bindings[id] = scope
		}
	}
	for source := range p.source.entries {
		var protection resourcePredicateProtection
		switch source.kind {
		case resourceSourceSelectorObjects, resourceSourceNestedDescendants:
			protection, err = classifyResourcePredicate(source)
		case resourceSourceRoleSelectorObjects, resourceSourceRoleNestedDescendants:
			protection, err = classifyAccessLabelMoveRolePredicate(source, held.ID, scope)
		case resourceSourceRoleProposedSelectorObjects, resourceSourceRoleProposedNestedDescendants:
			protection, err = classifyAccessLabelMoveProposedPredicate(source, bindings[source.id])
		default:
			continue
		}
		if err != nil {
			return nil, err
		}
		if err = p.source.budget.Charge(1+len(protection.Objects)+len(protection.Scopes)+len(protection.Children), 0); err != nil {
			return nil, err
		}
		out.predicates = append(out.predicates, protection)
	}
	slices.SortFunc(out.predicates, func(a, b resourcePredicateProtection) int {
		return strings.Compare(a.Source, b.Source)
	})
	// У всех обособленных предикатов один старый список каталогов.
	p.source.metadataParents = p
	if err = p.source.seal(); err != nil {
		return nil, err
	}
	return out, nil
}

func classifyAccessLabelMoveRolePredicate(key resourceSourceKey, role domain.RoleID, scope domain.ScopeAnchor) (resourcePredicateProtection, error) {
	var out resourcePredicateProtection
	if key.id != string(role) || !nativeQuestionToken(scope.ID) || (scope.Type != "project" && scope.Type != "account") {
		return out, kaname.ErrSourceUnconfirmed
	}
	source, err := resourcePredicateIdentity(key)
	if err != nil {
		return out, err
	}
	out.Source = source
	out.Scopes = []domain.ScopeAnchor{scope}
	switch key.kind {
	case resourceSourceRoleSelectorObjects:
		var selector resourceSelectorPredicate
		if json.Unmarshal([]byte(key.projection), &selector) != nil || selector.Scope != scope {
			return out, kaname.ErrSourceUnconfirmed
		}
		if _, _, err = resourceSelectorObjectsSQL(key, 1); err != nil {
			return out, err
		}
	case resourceSourceRoleNestedDescendants:
		var nested resourceNestedPredicate
		if json.Unmarshal([]byte(key.projection), &nested) != nil || nested.Scope == nil || *nested.Scope != scope {
			return out, kaname.ErrSourceUnconfirmed
		}
		if _, _, err = resourceNestedDescendantsSQL(key, 1); err != nil {
			return out, err
		}
		for _, id := range slices.Compact(slices.Sorted(slices.Values(nested.ContainerIDs))) {
			out.Children = append(out.Children, domain.ResourceRef{Type: nested.ContainerType, ID: id})
		}
	default:
		return out, kaname.ErrSourceUnconfirmed
	}
	return out, nil
}

// Границы STORE совпадают с обычной выдачей. Происхождение предложенного
// fingerprint при этом проверяет отдельная программа переноса.
func classifyAccessLabelMoveProposedPredicate(key resourceSourceKey, scope reconcile.BindingScope) (resourcePredicateProtection, error) {
	var empty resourcePredicateProtection
	if !nativeQuestionToken(key.id) || key.id != string(scope.BindingID) || scope.RoleID == "" {
		return empty, kaname.ErrSourceUnconfirmed
	}
	base := key
	var fp string
	switch key.kind {
	case resourceSourceRoleProposedSelectorObjects:
		var selector resourceSelectorPredicate
		if json.Unmarshal([]byte(key.projection), &selector) != nil || selector.Scope != scope.Scope {
			return empty, kaname.ErrSourceUnconfirmed
		}
		fp = selector.RuleFP
		base.kind = resourceSourceSelectorObjects
	case resourceSourceRoleProposedNestedDescendants:
		var nested resourceNestedPredicate
		if json.Unmarshal([]byte(key.projection), &nested) != nil {
			return empty, kaname.ErrSourceUnconfirmed
		}
		fp = nested.RuleFP
		base.kind = resourceSourceNestedDescendants
	default:
		return empty, kaname.ErrSourceUnconfirmed
	}
	if !slices.ContainsFunc(scope.Selectors, func(selector domain.RuleSelector) bool { return selector.RuleFP == fp }) {
		return empty, kaname.ErrSourceUnconfirmed
	}
	out, err := classifyResourcePredicate(base)
	if err != nil {
		return empty, err
	}
	out.Source, err = resourcePredicateIdentity(key)
	return out, err
}

// Вызов после owner prewait. Проверяет неизменность запроса и RR-источников
// на той же RC-транзакции, до финальных часов. SQL владелец отдельно
// подтверждает полноту предикатов и удерживает producer guards. Для записи
// возвращается точный образ PostgreSQL со всеми неизменёнными полями.
func (s *accessLabelMoveSourceReplay) recheck(
	ctx context.Context, w *authorityWriteTx, request kaname.RoleMutationRequest,
) (json.RawMessage, error) {
	if err := s.prepareRequest(ctx, w, request); err != nil {
		return nil, err
	}
	if err := s.parents.source.recheck(ctx, w); err != nil {
		return nil, err
	}
	return slices.Clone(s.image), nil
}

// Запрос подтверждается до SQL prewait. Чтение RR-источников выполняется
// после получения замков, чтобы не повторять весь census по двум часам.
func (s *accessLabelMoveSourceReplay) prepareRequest(
	ctx context.Context, w *authorityWriteTx, request kaname.RoleMutationRequest,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s == nil || s.parents == nil || s.parents.source == nil || request.Role.ID != s.role.ID || request.Role.AccountID != s.role.AccountID ||
		request.Role.ProjectID != s.role.ProjectID || request.Role.ClusterID != s.role.ClusterID ||
		request.Role.IsSystem != s.role.IsSystem || request.Role.OwnerModule != s.role.OwnerModule ||
		request.Create || !request.Update || !request.Rules || request.ExpectedVersion != s.version ||
		!slices.Equal(request.UpdateMask, []string{"rules"}) {
		return kaname.ErrSourceUnconfirmed
	}
	rules, err := rulesToJSON(request.Role.Rules)
	if err != nil {
		return err
	}
	if !bytes.Equal(rules, s.rules) {
		return kaname.ErrSourceUnconfirmed
	}
	return s.parents.source.lifetime.prepare(w)
}

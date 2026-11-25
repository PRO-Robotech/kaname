// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Admission вычисляет proposed image, не разрешает mutation. Полный gate
// и owner content stamp выполняются worker в той же prepared попытке.
func (s rolePolicySelection) projectAdmissionRules(facts *catalog.Facts, rules domain.Rules, policy domain.RulePolicy) (catalog.GrantProjection, error) {
	if s.configured {
		if factory, ok := s.factory.(kaname.RoleMutationWriterFactory); ok && factory != nil {
			return facts.ProjectRoleMutationRules(rules, policy)
		}
	}
	if roleRulesHaveAccessLabelSelectors(rules) {
		return catalog.GrantProjection{}, iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared role authoring unavailable")
	}
	return facts.ProjectGrantRules(rules, policy)
}

// Writer возвращает всю сохранённую проекцию, включая каждую capability.
// Это внутренний порт: он не расширяет общий catalog authoring API.
type preparedRoleMutationProjector interface {
	ProjectRoleMutationRules(context.Context, domain.Role) (catalog.GrantProjection, error)
}

func projectWriterRoleRules(ctx context.Context, w Writer, role domain.Role, fallback catalog.Source) (catalog.GrantProjection, error) {
	if prepared, ok := w.(preparedRoleMutationProjector); ok && prepared != nil {
		return prepared.ProjectRoleMutationRules(ctx, role)
	}
	required, err := roleRulesRequirePreparedAuthoring(role.Rules)
	if err != nil {
		return catalog.GrantProjection{}, shared.MapValidationErr(err)
	}
	if required {
		return catalog.GrantProjection{}, iamerr.Wrapf(iamerr.ErrUnavailable, "Prepared role projection unavailable")
	}
	facts, err := writerRoleFacts(w, fallback)
	if err != nil {
		return catalog.GrantProjection{}, err
	}
	projection, err := facts.ProjectGrantRules(role.Rules, domain.PolicyOfRole(role.IsSystem, role.OwnerModule))
	if err != nil {
		return catalog.GrantProjection{}, shared.MapValidationErr(err)
	}
	return projection, nil
}

func roleRulesHaveExplicitApply(rules domain.Rules) (bool, error) {
	_, caps, err := domain.SplitGrantCapabilityRules(rules)
	if err != nil {
		return false, err
	}
	for _, cap := range caps {
		if cap.Kind == domain.GrantCapabilityApplyAccessLabel {
			return true, nil
		}
	}
	return false, nil
}

// Защищённый селектор и явное полномочие apply допускаются только через
// подготовленную запись роли. Это условие применяется при приёме, в worker
// и при построении проекции.
func roleRulesRequirePreparedAuthoring(rules domain.Rules) (bool, error) {
	apply, err := roleRulesHaveExplicitApply(rules)
	if err != nil {
		return false, err
	}
	return apply || roleRulesHaveAccessLabelSelectors(rules), nil
}

func roleRulesHaveAccessLabelSelectors(rules domain.Rules) bool {
	for _, rule := range rules {
		if rule.MatchAccessLabels != nil || roleRulesHaveAccessLabelSelectors(rule.Children) {
			return true
		}
	}
	return false
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// compileChildRegistration выдаёт именованное право на выбранном родителе.
// Каталог подтверждает явную декларацию, конкретный тип и форму вложенного
// правила; отбор родителя задают владелец правила, цель и область выдачи.
// Наличие детей не входит в условие: право необходимо до первой регистрации.
func (c *Compiler) compileChildRegistration(s *Set, b Binding, sel domain.RuleSelector, p Provenance) {
	if b.Recipient.Type != domain.SubjectTypeUser || sel.Container == nil {
		return
	}
	actions := c.facts.ChildRegistrationActions(sel)
	if len(actions) == 0 {
		return
	}
	p.Primitive = "child_registration"
	parentType, ok := c.facts.FGAObjectType(sel.Container.Type)
	if !ok {
		s.obligations = append(s.obligations, Obligation{"catalog_type", sel.Container.Type, p})
		return
	}
	region, err := selectorRegion(sel.Container.Arm, sel.Container.ResourceNames, sel.Container.MatchLabels)
	if err != nil {
		s.obligations = append(s.obligations, Obligation{"selector", err.Error(), p})
		return
	}
	region, selected := intersectTarget(region, sel.Container.Type, b.Target)
	if !selected {
		return
	}
	scope := b.Scope
	constraints := []Constraint{{Type: parentType, Region: region, Within: &scope}}
	for _, action := range actions {
		decl, declared := c.plans.RelationSubjects(parentType, action.Relation)
		if action.ParentType != parentType || !declared || !decl.IsDirect() || !decl.AcceptsKind(authzmodel.KindUser) {
			s.obligations = append(s.obligations, Obligation{"child_registration_model", parentType + "." + action.Relation, p})
			continue
		}
		c.derive(s, parentType, action.Relation, constraints, Condition{}, p)
	}
}

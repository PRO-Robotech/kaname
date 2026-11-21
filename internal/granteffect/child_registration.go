// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

func validateChildRegistrationModel(plans *authzmodel.Plans, facts *catalog.Facts, row catalog.ResourceRow) error {
	if row.ChildRegistration == nil {
		return nil
	}
	dotted := row.Module + "." + row.Resource
	policy, found := facts.ChildRegistration(dotted)
	relation, declared := plans.RelationSubjects(policy.Path.ParentType, policy.Path.ParentAction)
	if !found || !declared || !relation.IsDirect() || !relation.AcceptsKind(authzmodel.KindUser) ||
		!plans.EffectDirectAccepts(policy.Path.ChildType, "parent", policy.Path.ParentType, "", "") {
		return fmt.Errorf("каталог %s: модель не подтверждает право пользователя и указатель parent", dotted)
	}
	if row.ChildRegistration.Verb == "create" && !relation.AcceptsKind(authzmodel.KindServiceAccount) {
		return fmt.Errorf("каталог %s: действие create должно сохранять прямой допуск служебной учётки", dotted)
	}
	return nil
}

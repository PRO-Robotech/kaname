// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/catalog"
)

func validateChildRegistrationModel(plans *authzmodel.Plans, facts *catalog.Facts, row catalog.ResourceRow) error {
	if row.ChildRegistration == nil {
		return nil
	}
	dotted := row.Module + "." + row.Resource
	policy, found := facts.ChildRegistration(dotted)
	if !found || !plans.EffectDirectAccepts(policy.Path.ParentType, policy.Path.ParentAction, "user", "", "") ||
		!plans.EffectDirectAccepts(policy.Path.ChildType, "parent", policy.Path.ParentType, "", "") {
		return fmt.Errorf("каталог %s: модель не подтверждает право пользователя и указатель parent", dotted)
	}
	if policy.Verb == "create" && !plans.EffectDirectAccepts(policy.Path.ParentType, policy.Path.ParentAction, "service_account", "", "") {
		return fmt.Errorf("каталог %s: действие create должно сохранять прямой допуск служебной учётки", dotted)
	}
	// Отдельное действие проверяется на точном родителе. Альтернативный
	// вывод через чтение, владение или предка позволил бы создать потомка
	// без выдачи объявленного глагола.
	plan, err := plans.Plan(policy.Path.ParentType, policy.Path.ParentAction)
	if err != nil || !plan.Expressible() || len(plan.Conditioned) != 0 || len(plan.Atoms) != 1 ||
		plan.Atoms[0].Kind != authzplan.AtomFact || plan.Atoms[0].ParentType != "" || plan.Atoms[0].Relation != policy.Path.ParentAction {
		return fmt.Errorf("каталог %s: право регистрации должно выводиться только из объявленного отношения на родителе", dotted)
	}
	return nil
}

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
	if !found || !plans.EffectDirectAccepts(policy.Path.ParentType, policy.Path.ParentAction, "user", "", "") ||
		!plans.EffectDirectAccepts(policy.Path.ChildType, "parent", policy.Path.ParentType, "", "") {
		return fmt.Errorf("каталог %s: модель не подтверждает право пользователя и указатель parent", dotted)
	}
	if policy.Verb == "create" && !plans.EffectDirectAccepts(policy.Path.ParentType, policy.Path.ParentAction, "service_account", "", "") {
		return fmt.Errorf("каталог %s: действие create должно сохранять прямой допуск служебной учётки", dotted)
	}
	return nil
}

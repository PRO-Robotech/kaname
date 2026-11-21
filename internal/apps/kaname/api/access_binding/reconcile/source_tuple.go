// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ProducesObjectTuple проверяет ровно тот вывод, которым полный и точечный
// reconcile выпускают кортеж. Ledger и наличие relation_fact не являются
// аргументами этой функции. Вызывающий подтверждает живость binding/role/catalog.
func ProducesObjectTuple(cat *catalog.Facts, bs BindingScope, object domain.MirrorObject, ancestors []domain.MirrorObject, tuple domain.MembershipTuple) (bool, error) {
	desired, err := desiredMembersForObject(cat, bs, object, ancestors)
	if err != nil {
		return false, err
	}
	if !object.IsContainedIn(bs.Scope) {
		return false, nil
	}
	for _, member := range desired {
		for _, candidate := range member.Tuples {
			if candidate == tuple {
				return true, nil
			}
		}
	}
	return false, nil
}

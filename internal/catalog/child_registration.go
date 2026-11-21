// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package catalog

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ChildRegistrationPolicy связывает форму ID и пределы с именованной
// записью действия на родителе из того же снимка каталога.
type ChildRegistrationPolicy struct {
	Path          domain.UserChildPathPolicy
	MaxChildren   int32
	MaxCreates    int32
	WindowSeconds int32
}

// ChildRegistration читает явный допуск для живого точечного типа.
func (f *Facts) ChildRegistration(dotted string) (ChildRegistrationPolicy, bool) {
	if f == nil {
		return ChildRegistrationPolicy{}, false
	}
	policy, ok := f.childRegistrations[dotted]
	return policy, ok
}

func childRegistrationPolicies(rows []ResourceRow, actions map[string]map[string]ContainerGrant) (map[string]ChildRegistrationPolicy, error) {
	if !slices.ContainsFunc(rows, func(r ResourceRow) bool { return r.ChildRegistration != nil }) {
		return nil, nil
	}
	typeOwners := make(map[string]string, len(rows))
	for _, row := range rows {
		if _, duplicate := typeOwners[row.ObjectType]; duplicate {
			typeOwners[row.ObjectType] = ""
		} else {
			typeOwners[row.ObjectType] = row.Module
		}
	}
	policies := make(map[string]ChildRegistrationPolicy)
	for _, row := range rows {
		rule := row.ChildRegistration
		if rule == nil {
			continue
		}
		dotted := row.Module + "." + row.Resource
		action, declared := actions[dotted][rule.Verb]
		path := domain.UserChildPathPolicy{
			ChildType: row.ObjectType, ParentType: action.ParentType, ParentAction: action.Relation,
			ParentSegments: int(rule.ParentSegments),
		}
		parent := slices.Index(row.ParentNames, "parent")
		if !declared || row.Module == "" || typeOwners[path.ChildType] != row.Module ||
			typeOwners[path.ParentType] != row.Module || strings.HasPrefix(action.Relation, "v_") ||
			len(row.ParentNames) != len(row.ParentTypes) || parent < 0 ||
			row.ParentTypes[parent] != path.ParentType || slices.Contains(row.ParentNames[parent+1:], "parent") ||
			!path.IsValid() || rule.MaxChildren <= 0 || rule.MaxCreates <= 0 || rule.WindowSeconds <= 0 {
			return nil, fmt.Errorf("каталог %s: несогласованная политика регистрации потомков", dotted)
		}
		policies[dotted] = ChildRegistrationPolicy{
			Path: path, MaxChildren: rule.MaxChildren, MaxCreates: rule.MaxCreates, WindowSeconds: rule.WindowSeconds,
		}
	}
	return policies, nil
}

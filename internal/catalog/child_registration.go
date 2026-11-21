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
	Verb          string
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

// ChildRegistrationParentDotted разрешает тип родителя только для точного
// действия, включённого политикой регистрации в этом снимке.
func (f *Facts) ChildRegistrationParentDotted(parentType, action string) (string, bool) {
	if f == nil {
		return "", false
	}
	dotted, ok := f.childRegistrationParents[[2]string{parentType, action}]
	return dotted, ok
}

// ChildRegistrationActions возвращает только действия, которые явно названы
// вложенным правилом на точном типе родителя. Отбор самого родителя и субъекта
// остаётся у применителя. Фильтр по ещё не созданному потомку нельзя расширять
// до права создать произвольного потомка.
func (f *Facts) ChildRegistrationActions(sel domain.RuleSelector) []ContainerGrant {
	if f == nil || len(f.childRegistrations) == 0 || sel.Container == nil ||
		sel.Arm != domain.ArmAnchor || sel.CreatedBySubject ||
		len(sel.ResourceNames) != 0 || len(sel.MatchLabels) != 0 {
		return nil
	}
	parentType, live := f.FGAObjectType(sel.Container.Type)
	if !live {
		return nil
	}
	var out []ContainerGrant
	for _, dotted := range sel.ObjectTypes {
		policy, enabled := f.ChildRegistration(dotted)
		if !enabled || policy.Path.ParentType != parentType ||
			!slices.ContainsFunc(sel.Verbs, func(verb string) bool {
				return domain.NormalizeVerb(verb) == policy.Verb
			}) {
			continue
		}
		grant := ContainerGrant{Verb: policy.Verb, ParentType: parentType, Relation: policy.Path.ParentAction}
		if !slices.Contains(out, grant) {
			out = append(out, grant)
		}
	}
	return out
}

func childRegistrationPolicies(rows []ResourceRow, actions map[string]map[string]ContainerGrant) (map[string]ChildRegistrationPolicy, map[[2]string]string, error) {
	if !slices.ContainsFunc(rows, func(r ResourceRow) bool { return r.ChildRegistration != nil }) {
		return nil, nil, nil
	}
	typeOwners := make(map[string]ResourceRow, len(rows))
	for _, row := range rows {
		if _, duplicate := typeOwners[row.ObjectType]; duplicate {
			typeOwners[row.ObjectType] = ResourceRow{}
		} else {
			typeOwners[row.ObjectType] = row
		}
	}
	policies := make(map[string]ChildRegistrationPolicy)
	parents := make(map[[2]string]string)
	for _, row := range rows {
		rule := row.ChildRegistration
		if rule == nil {
			continue
		}
		dotted := row.Module + "." + row.Resource
		verb := domain.NormalizeVerb(rule.Verb)
		action, declared := actions[dotted][verb]
		path := domain.UserChildPathPolicy{
			ChildType: row.ObjectType, ParentType: action.ParentType, ParentAction: action.Relation,
			ParentSegments: int(rule.ParentSegments),
		}
		parent := slices.Index(row.ParentNames, "parent")
		parentRow := typeOwners[path.ParentType]
		if !declared || row.Module == "" || typeOwners[path.ChildType].Module != row.Module ||
			parentRow.Module != row.Module || strings.HasPrefix(action.Relation, "v_") ||
			len(row.ParentNames) != len(row.ParentTypes) || parent < 0 ||
			row.ParentTypes[parent] != path.ParentType || slices.Contains(row.ParentNames[parent+1:], "parent") ||
			!path.IsValid() || rule.MaxChildren <= 0 || rule.MaxCreates <= 0 || rule.WindowSeconds <= 0 {
			return nil, nil, fmt.Errorf("каталог %s: несогласованная политика регистрации потомков", dotted)
		}
		policies[dotted] = ChildRegistrationPolicy{
			Verb: verb, Path: path, MaxChildren: rule.MaxChildren,
			MaxCreates: rule.MaxCreates, WindowSeconds: rule.WindowSeconds,
		}
		parents[[2]string{path.ParentType, path.ParentAction}] = parentRow.Module + "." + parentRow.Resource
	}
	return policies, parents, nil
}

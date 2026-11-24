// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

// GrantCapabilityPlan проверяет точный скомпилированный план и его объявление.
// Вычисляемый псевдоним, условие или новый вид субъекта не получают SQL-ветвь.
func (p *Plans) GrantCapabilityPlan(objectType, relation string) error {
	expected := grantcapability.CreateRelation
	switch objectType {
	case grantcapability.ScopeObjectType:
	case grantcapability.RoleObjectType:
		expected = grantcapability.BindRelation
	default:
		return fmt.Errorf("authzmodel: not a grant capability type")
	}
	if relation != expected {
		return fmt.Errorf("authzmodel: unsupported grant capability relation")
	}
	plan, err := p.Plan(objectType, relation)
	if err != nil {
		return err
	}
	if len(plan.Conditioned) != 0 || len(plan.Atoms) != 1 || plan.Atoms[0].Kind != authzplan.AtomFact || plan.Atoms[0].ParentType != "" || plan.Atoms[0].Relation != relation {
		return fmt.Errorf("authzmodel: unsupported grant capability plan")
	}
	typ := p.model.Type(objectType)
	if typ == nil || len(typ.Relations) != 1 {
		return fmt.Errorf("authzmodel: unsupported grant capability type declaration")
	}
	decl := typ.Rel(relation)
	if decl == nil || len(decl.Terms) != 1 || decl.Terms[0].Kind != authzplan.TermDirect {
		return fmt.Errorf("authzmodel: capability requires one direct declaration")
	}
	expectedSubjects := map[string]bool{"user": true, "service_account": true, "group#member": true}
	for _, subject := range decl.Terms[0].Direct {
		key := subject.String()
		if !expectedSubjects[key] {
			return fmt.Errorf("authzmodel: unsupported capability subject")
		}
		delete(expectedSubjects, key)
	}
	if len(expectedSubjects) != 0 {
		return fmt.Errorf("authzmodel: incomplete capability subject declaration")
	}
	return nil
}

func reservedGrantType(name string) bool {
	return grantcapability.IsInternalObjectType(name)
}

// Доставленные типы не переопределяют канон (Д1/Д7) и не используют внутренние
// координаты как прямые субъекты, множества субъектов или указатели.
func grantCapabilityReferenceFindings(m *authzplan.Model, newNames map[string]bool) []Finding {
	var out []Finding
	for _, typ := range m.Types {
		if !newNames[typ.Name] {
			continue
		}
		for _, rel := range typ.Relations {
			for _, term := range rel.Terms {
				for _, subject := range term.Direct {
					if reservedGrantType(subject.Type) {
						out = append(out, Finding{Rule: RuleGrantCapability, Type: typ.Name, Relation: rel.Name, Term: subject.String(), Text: "internal grant coordinates are reserved"})
					}
				}
			}
		}
	}
	return out
}

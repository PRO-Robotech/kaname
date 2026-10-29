// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// read_projection_test.go — ответ ЧТЕНИЯ роли несёт вычисленное состояние
// (kaname#874, ND-02 «И»: `declaredSegments` = 4 у роли с вложенным правилом).
//
// `Get` и `List` прикладывают целость, состояния правил и жизненное состояние
// (`attachIntegrity`); ответ ОПЕРАЦИИ (`Create`, `Update`) их не несёт намеренно
// (`domain.Role.WithoutComputedState`). Проба держит, что проекция ответа
// операции не уехала на путь чтения: там она обнуляла посчитанное, и
// `declaredSegments`, `health`, `ruleStates` на чтении были нулевыми всегда.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func readProjectionRole() domain.Role {
	return domain.Role{
		ID: "rolb812261cfaa239694", ClusterID: domain.ClusterSingletonID, Name: "registry.reader",
		IsSystem: true, TypeVerbs: func(_, _ string) ([]string, bool) { return []string{"get", "list"}, true },
		Rules: domain.Rules{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"},
			Children: []domain.Rule{{Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}}}},
		Integrity:  domain.HealthOf(4, 0),
		Holding:    domain.PreviewHoldingOf(nil, nil),
		RuleStates: domain.RuleStatesOf(nil, nil, nil),
	}
}

func TestRoleRead_ND02_ReadAnswerCarriesTheComputedState(t *testing.T) {
	r := readProjectionRole()
	r.RuleStates = domain.RuleStatesOf(r.Rules, nil, nil)
	pb, err := roleToPb(r)
	if err != nil {
		t.Fatalf("проекция чтения: %v", err)
	}
	if pb.GetDeclaredSegments() != 4 {
		t.Errorf("declaredSegments на чтении = %d, ждали 4", pb.GetDeclaredSegments())
	}
	if len(pb.GetRuleStates()) != 1 || len(pb.GetRuleStates()[0].GetChildren()) != 1 {
		t.Errorf("ruleStates на чтении %v, ждали одно правило с одним вложенным", pb.GetRuleStates())
	}
	if len(pb.GetRules()) != 1 || len(pb.GetRules()[0].GetChildren()) != 1 {
		t.Errorf("rules[0].children на чтении %v", pb.GetRules())
	}

	// Близнец: ответ операции вычисленного состояния не несёт.
	any, err := marshalRole(r)
	if err != nil {
		t.Fatalf("проекция операции: %v", err)
	}
	if !any.MessageIs(pb) {
		t.Fatalf("ответ операции — не роль")
	}
	op := pb.ProtoReflect().New().Interface()
	if err := any.UnmarshalTo(op); err != nil {
		t.Fatalf("разбор ответа операции: %v", err)
	}
	if got := op.(interface{ GetDeclaredSegments() int32 }).GetDeclaredSegments(); got != 0 {
		t.Errorf("ответ операции несёт declaredSegments = %d — посчитано не на его снимке", got)
	}
}

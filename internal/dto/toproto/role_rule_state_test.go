// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// role_rule_state_test.go — постатейное состояние правила доезжает до контракта.
//
// Приёмка `services/iam/docs/engineering/acceptance/rule-state-names-withdrawn-apart-from-unresolved.md`,
// сценарии MOD-RS-02, MOD-RS-03, MOD-RS-07, MOD-RS-10.
//
// Утверждается ПЕРЕВОД, а не решение: какое состояние несёт правило, решает
// домен. Эта проба ловит другой класс — значение, которое ПИШУТ и не ЧИТАЮТ:
// поле, посчитанное доменом и не выставленное на wire, невидимо отовсюду.

import (
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// roleWithStates — роль в форме, какой её отдаёт чтение.
func roleWithStates(states []domain.RuleState) domain.Role {
	return domain.Role{
		ID:    domain.RoleID("rol00000000000000000"),
		Name:  "проба",
		Rules: domain.Rules{{Module: "vpc", Resources: []string{"gateway"}, Verbs: []string{"delete"}}},
		// Набор глаголов типа провязан — иначе проекция ОТКАЗЫВАЕТ, и отказ съел бы
		// предмет этих проб (#1994). Дублёр отвечает ровно тем, что объявляет живая
		// строка каталога, и ничем сверх.
		TypeVerbs: func(module, resource string) ([]string, bool) {
			if module == "vpc" && resource == "gateway" {
				return []string{"get", "delete"}, true
			}
			return nil, false
		},
		RuleStates: states,
	}
}

// MOD-RS-02 / MOD-RS-03 — ОБА состояния доезжают, и они РАЗНЫЕ на wire. Проба
// парная намеренно: утверждение об одном значении зеленело бы на переводчике,
// возвращающем одну и ту же величину на любой вход.
func TestRoleToPb_MODRS0203_WithdrawnAndUnresolvedAreDistinctOnTheWire(t *testing.T) {
	withdrawn := mustRolePb(t, roleWithStates([]domain.RuleState{
		{RuleIndex: 0, State: domain.RuleLifecycleWithdrawn, Segments: 1, Lost: 1, Explained: 1},
	}))
	unresolved := mustRolePb(t, roleWithStates([]domain.RuleState{
		{RuleIndex: 0, State: domain.RuleLifecycleUnresolved, Segments: 1, Lost: 1},
	}))

	if len(withdrawn.GetRuleStates()) != 1 || len(unresolved.GetRuleStates()) != 1 {
		t.Fatalf("записей %d и %d, ожидалось по одной",
			len(withdrawn.GetRuleStates()), len(unresolved.GetRuleStates()))
	}
	gotW := withdrawn.GetRuleStates()[0].GetState()
	gotU := unresolved.GetRuleStates()[0].GetState()
	if gotW != iamv1.RuleLifecycle_RULE_LIFECYCLE_WITHDRAWN {
		t.Fatalf("отозванное приехало как %v", gotW)
	}
	if gotU != iamv1.RuleLifecycle_RULE_LIFECYCLE_UNRESOLVED {
		t.Fatalf("неразрешённое приехало как %v", gotU)
	}
	if gotW == gotU {
		t.Fatal("два разных состояния приехали одним значением — различие потеряно на переводе")
	}
}

// MOD-RS-04 — обе величины смешанного случая доезжают вместе со словом. Без них
// слово схлопывало бы состав.
func TestRoleToPb_MODRS04_MixedCountersReachTheWire(t *testing.T) {
	pb := mustRolePb(t, roleWithStates([]domain.RuleState{
		{RuleIndex: 0, State: domain.RuleLifecycleUnresolved, Segments: 2, Lost: 2, Explained: 1},
	}))
	st := pb.GetRuleStates()[0]
	if st.GetSegments() != 2 || st.GetLostSegments() != 2 || st.GetExplainedSegments() != 1 {
		t.Fatalf("счётчики %d/%d/%d, ожидалось 2/2/1",
			st.GetSegments(), st.GetLostSegments(), st.GetExplainedSegments())
	}
	// Необъяснённое выводится вычитанием — и оно обязано быть видно.
	if st.GetLostSegments()-st.GetExplainedSegments() != 1 {
		t.Fatal("необъяснённая потеря исчезла: слово схлопнуло состав")
	}
}

// MOD-RS-10 — ключ доезжает и указывает на своё правило.
func TestRoleToPb_MODRS10_RuleIndexReachesTheWire(t *testing.T) {
	pb := mustRolePb(t, roleWithStates([]domain.RuleState{
		{RuleIndex: 0, State: domain.RuleLifecycleActive},
		{RuleIndex: 1, State: domain.RuleLifecycleWithdrawn, Segments: 1, Lost: 1, Explained: 1},
	}))
	got := pb.GetRuleStates()
	if len(got) != 2 {
		t.Fatalf("записей %d, ожидалось 2", len(got))
	}
	if got[0].GetRuleIndex() != 0 || got[1].GetRuleIndex() != 1 {
		t.Fatalf("ключи %d и %d, ожидались 0 и 1", got[0].GetRuleIndex(), got[1].GetRuleIndex())
	}
}

// MOD-RS-07 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к утверждениям выше и утверждение само по
// себе: ответ, которому состояние не вычисляли, несёт ПУСТОЙ список, а не
// список из нулевых вариантов. Иначе «не вычислено» стало бы неотличимо от
// «правило не действует».
func TestRoleToPb_MODRS07_NotComputedIsAnEmptyListNotZeroValues(t *testing.T) {
	pb := mustRolePb(t, roleWithStates(nil))
	if len(pb.GetRuleStates()) != 0 {
		t.Fatalf("невычисленное состояние приехало %d записями", len(pb.GetRuleStates()))
	}
	if pb.GetHealth() != iamv1.RoleHealth_ROLE_HEALTH_UNSPECIFIED {
		t.Fatalf("целость %v — контроль негоден: ответ операции её не несёт", pb.GetHealth())
	}
}

// mustRolePb — перевод роли в контрактную форму. Отказ роняет пробу: «не смог
// перевести» не есть «поля нет».
func mustRolePb(t *testing.T, r domain.Role) *iamv1.Role {
	t.Helper()
	pb, err := roleObj{}.toPb(r)
	if err != nil {
		t.Fatalf("перевод роли отказал: %v", err)
	}
	return pb
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// tuples_nlb_membership_test.go — NLB-TGT-1: роль, объявляющая управление составом
// группы целей, ПРОИЗВОДИТ соответствующие кортежи.
//
// Слабая форма этого утверждения («намерение эмитировано») осталась бы зелёной ровно
// на том дефекте, ради которого написана под-фаза: глагол вне набора типа проходит
// через эмиттер молча, и роль выдаётся, ничего не давая. Поэтому утверждается
// ИМЕННО отношение, которое примет владелец модели, — и утверждается парой с
// отрицанием: держатель управления составом НЕ получает изменения самой группы.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// TestRuleObjectTuples_TargetGroupMembershipVerbsMaterialize — несущее утверждение.
func TestRuleObjectTuples_TargetGroupMembershipVerbsMaterialize(t *testing.T) {
	// Авторское написание — ровно то, что лежит в системной роли
	// `loadbalancer.target_manager` (миграция 0031).
	got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a",
		[]string{"addTargets", "removeTargets"}, "loadbalancer.targetGroups", "tgr_1")
	if !ok {
		t.Fatalf("эмиссия не состоялась вовсе — утверждения ниже были бы бессодержательны")
	}
	rels := relationsOf(got)

	for _, want := range []string{"v_addtargets", "v_removetargets"} {
		if !containsRel(rels, want) {
			t.Errorf("роль управления составом не произвела %q: %v.\n"+
				"Тогда право выдано и не даёт ничего: обе точки решения спрашивают отношение, "+
				"которого материализация не производит ни при каких условиях", want, rels)
		}
	}

	// ОТРИЦАНИЕ в том же прогоне: управление составом не притащило изменение группы.
	// Ради этого различения под-фаза и существует — без него «реализовали» было бы
	// неотличимо от «расширили право редактирования ещё одним именем».
	for _, bad := range []string{"v_update", "v_delete"} {
		if containsRel(rels, bad) {
			t.Errorf("роль управления составом получила %q: %v — различение не состоялось, "+
				"держатель управления составом правит саму группу", bad, rels)
		}
	}
}

// TestRuleObjectTuples_MembershipVerbsAreScopedToTheirType — набор остался атрибутом
// ТИПА: те же глаголы на соседнем типе не порождают ничего.
//
// Без этой пары «объявили у типа» неотличимо от «вернули глобальный словарь», при
// котором глагол поехал бы висячим отношением на все прочие типы.
func TestRuleObjectTuples_MembershipVerbsAreScopedToTheirType(t *testing.T) {
	got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a",
		[]string{"addTargets", "removeTargets"}, "vpc.network", "net_1")
	if !ok {
		t.Fatalf("эмиссия на соседнем типе не состоялась — отрицание было бы бессодержательным")
	}
	rels := relationsOf(got)
	for _, bad := range []string{"v_addtargets", "v_removetargets"} {
		if containsRel(rels, bad) {
			t.Errorf("глагол управления составом породил %q на vpc.network: %v.\n"+
				"Тип его не объявляет — это висячий кортеж, отвергаемый владельцем модели "+
				"окончательно, и строка навсегда блокирует свою партицию очереди", bad, rels)
		}
	}
	// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ: эмиссия на этом типе вообще работает — ярусный кортеж
	// правило по-прежнему даёт, значит отрицание выше про отношение, а не про мертвечину.
	if !containsRel(rels, "editor") {
		t.Errorf("на vpc.network не эмитировано ни одного ярусного кортежа: %v — "+
			"отрицание выше зеленело бы просто оттого, что эмиссия мертва", rels)
	}
}

// TestRuleObjectTuples_TargetGroupWildcardCoversMembership — подстановка `*` на группе
// целей разворачивается в набор ЕЁ типа, то есть роль-администратор управление
// составом не теряет.
//
// Иначе под-фаза сузила бы существующий доступ: сегодня `*.*`-роль правит группу и,
// значит, управляет её составом; после раскола она обязана управлять им по-прежнему.
func TestRuleObjectTuples_TargetGroupWildcardCoversMembership(t *testing.T) {
	got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a", []string{"*"}, "loadbalancer.targetGroups", "tgr_1")
	if !ok {
		t.Fatalf("эмиссия подстановки не состоялась вовсе")
	}
	rels := relationsOf(got)
	for _, want := range []string{"v_addtargets", "v_removetargets", "v_update", "v_delete"} {
		if !containsRel(rels, want) {
			t.Errorf("подстановка `*` на группе целей не дала %q: %v — "+
				"роль-администратор потеряла бы то, что имела", want, rels)
		}
	}
}

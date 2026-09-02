// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package reconcile

// tuples_normalize_test.go — имя отношения собирается из ПРИВЕДЁННОГО глагола.
//
// Вторая половина разрыва, и наблюдаемая. Проверка принадлежности приводила регистр,
// а имя отношения собиралось из АВТОРСКОГО написания правила: `Update` проходило
// проверку и адресовало `v_Update` — отношение, которого в модели нет. Владелец
// модели такую запись отвергает окончательно, а отказ классифицируется как
// постоянный: строка навсегда блокирует свою партицию очереди.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

func TestRuleObjectTuples_RelationNameUsesNormalizedVerb(t *testing.T) {
	got, ok := ruleObjectTuples(catalogfixture.Facts(), "user:usr_a", []string{"Update", "Get"}, "vpc.network", "net_1")
	if !ok {
		t.Fatalf("эмиссия не состоялась вовсе — утверждения ниже были бы бессодержательными")
	}
	rels := relationsOf(got)

	// ОТРИЦАНИЕ: отношения из авторского написания не существует.
	for _, bad := range []string{"v_Update", "v_Get"} {
		if containsRel(rels, bad) {
			t.Errorf("эмитировано отношение %q из авторского написания: %v.\n"+
				"Такого отношения в модели нет: запись отвергается окончательно, а отказ "+
				"считается постоянным — строка навсегда блокирует свою партицию очереди", bad, rels)
		}
	}
	// ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ в том же прогоне.
	for _, want := range []string{"v_update", "v_get"} {
		if !containsRel(rels, want) {
			t.Errorf("отношение %q не эмитировано: %v — тогда отрицание выше ничего не утверждает", want, rels)
		}
	}
}

func TestScopeSelfTuples_RelationNameUsesNormalizedVerb(t *testing.T) {
	got, ok := scopeSelfTuples(catalogfixture.Facts(), "user:usr_a", "account", "acc_1", []string{"Get"})
	if !ok {
		t.Fatalf("эмиссия якоря не состоялась вовсе")
	}
	rels := relationsOf(got)
	if containsRel(rels, "v_Get") {
		t.Errorf("якорь получил v_Get из авторского написания: %v", rels)
	}
	if !containsRel(rels, "v_get") {
		t.Errorf("якорь не получил v_get: %v", rels)
	}
}

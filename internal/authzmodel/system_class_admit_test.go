// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

// system_class_admit_test.go — модуль не вносит системный класс в модель
// (приёмка anonymous-and-authenticated-are-subject-classes.md, отпечаток
// ae9ba373…0427f51 (редакция 4), SC-37; задача PRO-Robotech/kaname#829).
//
// Отказ тот же, что у подстановки `user:*` по соседу
// composed-model-admits-only-what-it-owns.md: находка Д3 называет тип и
// отношение. Близнец — тот же блок без класса — находок Д3 не даёт.

import (
	"strings"
	"testing"
)

const scTwinDecl = "define v_get: [user, service_account, group#member] or super_admin"

func TestSystemClass_SC37_ModuleDoesNotBringAClassIntoTheModel(t *testing.T) {
	if n := len(findingsOf(mustAdmit(t, compose(twin(t))), RuleD3)); n != 0 {
		t.Fatalf("SC-37 близнец: блок без класса обязан пройти без Д3, находок %d", n)
	}
	for _, term := range []string{"system_class", "system_class:anonymous", "system_class:authenticated"} {
		t.Run(term, func(t *testing.T) {
			block := swapDecl(twin(t), scTwinDecl,
				"define v_get: [user, service_account, "+term+"] or super_admin")
			rep, err := Admit(compose(block))
			if err != nil {
				t.Fatalf("SC-37: допуск вернул ошибку вместо отчёта с находкой Д3: %v", err)
			}
			got := findingsOf(rep, RuleD3)
			if len(got) != 1 {
				t.Fatalf("SC-37: класс %q в отношении модуля обязан быть находкой Д3, получено %v", term, rules(rep))
			}
			if got[0].Type != "acme_widget" || got[0].Relation != "v_get" {
				t.Fatalf("SC-37: находка обязана называть тип и отношение, получено %+v", got[0])
			}
			if !strings.Contains(got[0].Term, "system_class") {
				t.Fatalf("SC-37: находка обязана называть запись субъекта, получено %q", got[0].Term)
			}
		})
	}
}

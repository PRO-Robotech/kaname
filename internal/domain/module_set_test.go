// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// module_set_test.go — the domain OWNS the closed module-set: IsKnownModule is
// the single source of truth a Rule.Validate consults to reject an unknown
// module on the request-path.

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestIsKnownModule_ClosedSet — the two halves of the closed platform module-set:
// everything the set DECLARES is known, and a list of near-misses is not. geo is
// NOT a module (Geography moved to its own service, not in authzmap.objectTypes).
// `nlb` is NOT the token — the load-balancer module is named `loadbalancer`. The
// wildcard `*` is NOT a "known module" (it is a system-only marker handled
// separately by Rule.Validate, not by IsKnownModule).
//
// Положительная половина ВЫВОДИТСЯ из KnownModules, а не выписывается. Прежняя
// редакция несла собственный перечень из ПЯТИ имён и заголовок «EXACTLY» — но
// утверждала ЧЛЕНСТВО каждого, а не равенство наборов, поэтому шестое имя
// (storage) добавилось, ничего не покраснив, и заголовок стал ложью. Точный
// состав пинит module_set_drift_test.go — второго места об одном предмете здесь
// не заводится; здесь проверяется, что объявленное и признаваемое совпадают.
func TestIsKnownModule_ClosedSet(t *testing.T) {
	known := domain.KnownModules()
	if len(known) == 0 {
		t.Fatal("KnownModules() пуст — обход беспредметен, «ноль находок» получено даром")
	}
	for _, m := range known {
		if !domain.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = false, want true (объявлен в KnownModules)", m)
		}
	}
	t.Logf("перепись: модулей объявлено %d (%v)", len(known), known)

	unknown := []string{"banana", "geo", "nlb", "loadbalancers", "iAm", "", "*", "vpc "}
	for _, m := range unknown {
		if domain.IsKnownModule(m) {
			t.Errorf("IsKnownModule(%q) = true, want false (NOT in closed set)", m)
		}
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"testing"
)

func TestNativeDiscoveryAndProtectedSourcesShareExhaustion(t *testing.T) {
	shared := &relverdict.AdministrativeReadBudget{}
	// Остаток общего census, затем два независимых native root budgets.
	if err := shared.Charge(99998, 0); err != nil {
		t.Fatal(err)
	}
	first := &nativeReadBudget{shared: shared}
	second := &nativeReadBudget{shared: shared}
	if err := first.charge(1, 0); err != nil {
		t.Fatal(err)
	}
	if err := second.charge(1, 0); err != nil {
		t.Fatal(err)
	}
	if err := second.charge(1, 0); !errors.Is(err, kaname.ErrSourceReadLimit) {
		t.Fatalf("new root reset shared budget: %v", err)
	}
	w := &authorityWriteTx{nativeRead: &protectedNativeRead{budget: shared}}
	if err := w.ChargeSourceRead(kaname.SourceReadCost{Rows: 1}); !errors.Is(err, kaname.ErrSourceReadLimit) {
		t.Fatalf("protected collector reset RR budget: %v", err)
	}
}

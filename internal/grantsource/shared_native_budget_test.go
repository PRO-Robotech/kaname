// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantsource

import (
	"errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"testing"
)

func TestSourceCollectionsShareWriterBudgetWithoutReset(t *testing.T) {
	remaining := 2
	charge := func(c kaname.SourceReadCost) error {
		if c.Rows > remaining {
			return errors.New("exhausted")
		}
		remaining -= c.Rows
		return nil
	}
	first := &sourceBudget{shared: charge}
	second := &sourceBudget{shared: charge}
	if !first.charge(1) || !second.chargeCost(kaname.SourceReadCost{Rows: 1, Reads: 1}) {
		t.Fatal("valid source lost")
	}
	if first.charge(1) || second.chargeCost(kaname.SourceReadCost{Rows: 1, Reads: 1}) {
		t.Fatal("new collection reset writer allowance")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// dropguard_integration_test.go — iam's drops are decided by a counter.
//
// Every table this service has dropped was dropped on the strength of a paragraph
// in the migration. Those paragraphs were true when written, and none of them is
// checked, so none of them stays true on its own. This replays the chain into an
// empty Postgres, pauses at the version immediately before each drop, and COUNTS —
// comparing each number for equality with the one declared in dropguard.json.
//
// A table that could not be counted is reported as unverified, never as empty.
package migrations_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/internal/dropguard/dropguardtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

func TestIntegration_IamDropsAreMeasured(t *testing.T) {
	rep := dropguardtest.Run(t, dropguardtest.Options{
		Service:      "iam",
		FS:           migrations.FS,
		ManifestPath: "dropguard.json",
	})

	// The count is a ratchet on the chain, and it catches something Reconcile
	// cannot. Reconcile refuses a drop whose number is unstated, so a drop can
	// never land alone — but a drop and its declaration land together in one
	// commit, and internally they agree. Nothing outside the migrations directory
	// moves, so nothing in the diff says the chain grew. This number is that
	// something: it cannot change by itself, so a drop that appeared without it
	// moving is a drop nobody looked at.
	if rep.DropsInChain != 19 {
		t.Errorf("iam chain holds %d Up-section drop(s), expected 19; a drop that appeared without this number moving is a drop nobody looked at", rep.DropsInChain)
	}

	// And the retire of the subscription-cursor table is named, so that removing
	// the migration together with its declaration cannot leave the gate green on
	// a chain that quietly got the invitation back (PRO-Robotech/kacho#1148).
	if _, ok := rep.Rows["20260828114800/kacho_iam.watch_cursors"]; !ok {
		t.Errorf("20260828114800/kacho_iam.watch_cursors was never counted — the retire of the server-side subscription cursors rests on a number this run did not produce")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// dropguard_integration_test.go — iam's chain drops nothing, and that is DECLARED.
//
// # What this file used to assert, and why it stopped being assertable
//
// iam's chain used to be 171 migrations, twenty of which dropped a table. Each of
// those drops carried a declared row count in dropguard.json, and this run replayed
// the chain into an empty Postgres, paused at the version immediately before each
// drop, and counted.
//
// The chain has since been squashed into ONE primary migration. A squashed chain is
// a STATE, not a history: it creates what the service has and drops nothing, because
// there is no earlier version for a drop to act on. So the twenty counts have no
// subject left — not "they became hard to check", but "the statements they described
// are not in the tree at all". Keeping them would be twenty exemptions with nothing
// left to exempt, which is the blind spot the guard itself refuses (`expired-declaration`).
// The manifest was therefore retired together with them.
//
// # What this run still asserts, which is not nothing
//
//  1. THE COUNT IS A RATCHET, and zero is a number like any other. `DropsExpected: 0`
//     is declared, not inferred: add a DROP TABLE to iam's chain and the count moves
//     off zero and this goes red, exactly as adding the twenty-first drop would have.
//  2. THE CHAIN REPLAYS TO HEAD against a real Postgres. For a chain squashed out of
//     171 files this is the load-bearing half: the primary migration is new text, and
//     "it applies" is a property nothing else in this package establishes.
//  3. THE MANIFEST STAYS RETIRED. An absent manifest is accepted only for a chain
//     that drops nothing; reintroduce one with entries and Reconcile refuses each
//     entry that has no drop behind it.
package migrations_test

import (
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/dropguard"
	"github.com/PRO-Robotech/kacho/pkg/dropguard/dropguardtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

func TestIntegration_IamDropsAreMeasured(t *testing.T) {
	rep := dropguardtest.Run(t, dropguardtest.Options{
		Service:      "iam",
		FS:           migrations.FS,
		ManifestPath: "dropguard.json",

		// See the file header: zero is the declared, ratcheting count of a chain
		// that is one state rather than a history.
		DropsExpected: 0,
	})

	if rep.FilesScanned == 0 {
		t.Fatal("no migration file was read — a chain that drops nothing and a chain that was never read produce the same count of drops, and only this number tells them apart")
	}
	t.Logf("перепись: прочитано файлов миграций %d, снятий в цепи %d, объявлено %d",
		rep.FilesScanned, rep.DropsInChain, 0)
}

// TestIntegration_IamChainNeverBringsBackTheSubscriptionCursorTable — the retire of
// the server-side subscription cursors, asserted on what the tree PRODUCES.
//
// # Why this is a separate test and not the line it replaces
//
// It used to be one line inside the run above: the drop of `kaname.watch_cursors`
// had to appear among the counted rows, so that deleting the migration together with
// its declaration could not leave the gate green on a chain that had quietly got the
// table back (PRO-Robotech/kacho#1148).
//
// That referent was the DROP — a statement in the history. The history is gone, so
// asserting on it would assert on nothing. The property it protected is not gone: the
// table must not be in iam's schema. Squashing the chain turned that property from
// "some migration drops it" into "no migration creates it", and the second form is
// both checkable and stronger — it does not depend on a drop existing to undo a
// create.
//
// The inventory is asked rather than the file text, because the inventory already
// parses CREATE TABLE per migration and knows the difference between a statement and
// a mention of one in prose.
func TestIntegration_IamChainNeverBringsBackTheSubscriptionCursorTable(t *testing.T) {
	inv, err := dropguard.Inventory("iam", migrations.FS)
	if err != nil {
		t.Fatalf("inventory: %v — the chain could not be read, and a chain that was not read is not a chain that is clean", err)
	}

	// Control in the other direction. Without it, "the table is not created" would
	// be green on a chain the parser stopped reading, on an empty embedded FS, and
	// on a rename of CREATE TABLE syntax the parser no longer recognises.
	const anchor = "kaname.accounts"
	if !inv.CreatesTable(anchor) {
		t.Fatalf("the anchor table %q is not created anywhere in %d migration file(s): the parser is not reading CREATE TABLE in this chain, so the absence asserted below would be an absence of reading",
			anchor, inv.FilesScanned)
	}

	for _, table := range []string{"kaname.watch_cursors", "watch_cursors"} {
		if inv.CreatesTable(table) {
			t.Errorf("%s is created by migration(s) %v — the server-side subscription cursor table is back, and the decision that retired it (PRO-Robotech/kacho#1148) was undone without anyone saying so",
				table, inv.CreateVersions(table))
		}
	}

	t.Logf("перепись: прочитано файлов миграций %d, якорь %s создаётся, курсорной таблицы подписки в цепи нет",
		inv.FilesScanned, anchor)
}

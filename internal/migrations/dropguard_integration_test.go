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
	dropguardtest.Run(t, dropguardtest.Options{
		Service:      "iam",
		FS:           migrations.FS,
		ManifestPath: "dropguard.json",
	})
}

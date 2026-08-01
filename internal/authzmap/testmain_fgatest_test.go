// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// TestMain terminates the one OpenFGA this package shares.
//
// The nine model proofs here — the account-owner refinement, the super-admin
// cascade, the nlb/storage project pointers — used to boot a container EACH. They
// now take a store on the one server the test binary owns; see
// testsupport/fgatest for why a store is the isolation a separate container gave.
//
// The server starts lazily, so a -short run that skips every proof starts nothing
// and this TestMain terminates nothing. Its only job is to take the container
// down as soon as the package is finished, rather than leaving it to the
// testcontainers reaper at process exit.
func TestMain(m *testing.M) {
	os.Exit(fgatest.Run(m.Run))
}

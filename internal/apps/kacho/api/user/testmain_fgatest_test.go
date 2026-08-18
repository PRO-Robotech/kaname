// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// TestMain hands this package ONE OpenFGA for the whole binary instead of one
// per test, and terminates it afterwards.
//
// Nothing starts here: the server boots on FIRST USE. This package is
// overwhelmingly unit tests over fake ports, and under -short the one test that
// wants an engine skips — so a run that needs no engine pays for none. Postgres
// is deliberately NOT wired: no test here talks to a database, and a harness
// nobody uses is a container nobody needed.
func TestMain(m *testing.M) {
	os.Exit(fgatest.Run(m.Run))
}

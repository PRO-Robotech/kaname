// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

import (
	"flag"
	"fmt"
	"os"
	"testing"
)

// TestMain adds a CI enforcement hook for the testcontainers integration /
// concurrency / DB-trigger proofs in this package. Every such test individually
// skips under `-short` (the sole silent-skip vector — none gate on a separate
// Docker probe; without `-short` a missing Docker daemon makes the container
// start FAIL, not skip). A full CI run invoked with `-short` would therefore
// silently drop every CAS / UNIQUE / EXCLUDE / trigger race proof that
// data-integrity.md #10/#12 requires a concurrent-goroutine test to prove, while
// the suite still reports green (a skipped test is neither red nor green).
//
// When KACHO_IAM_REQUIRE_INTEGRATION is set (the CI integration lane), running
// with `-short` is refused hard so the proofs cannot vanish from the pipeline.
// Locally / offline the var is unset and `-short` still skips, mirroring the
// FGA-gate enforcement (internal/authzmap/fga_model_drift_test.go).
func TestMain(m *testing.M) {
	flag.Parse()
	if os.Getenv("KACHO_IAM_REQUIRE_INTEGRATION") != "" && testing.Short() {
		fmt.Fprintln(os.Stderr,
			"KACHO_IAM_REQUIRE_INTEGRATION set but -short given: refusing to skip integration/concurrency/DB-trigger proofs")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

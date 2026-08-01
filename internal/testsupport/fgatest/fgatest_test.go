// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fgatest_test.go — the premise the "one container per package" gate stands on,
// for the OpenFGA half.
//
// internal/repohygiene/containerperpackage_test.go counts how many distinct test
// functions of a package transitively reach a container start. A helper that
// starts ONE server for the whole binary and hands out cheap per-test isolation
// is not what that gate is about — but "it starts once" and "the tests are still
// isolated" are assumptions, and assumptions are checked HERE, by BEHAVIOUR,
// rather than by reading the helper. Drift and it goes red here, instead of going
// quiet there. internal/pgtest/pgtest_test.go does exactly this for Postgres.
//
// The package is external (`fgatest_test`) on purpose: the calls then go through
// the package name, exactly as real consumers write them.
//
// It is deliberately ONE test function, not three. The three claims below are
// three claims about the SAME pair of harnesses — separating them would not only
// pay for the proof twice, it would make this package itself look, to the gate
// above, like a package that starts a container per test.
package fgatest_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// The probe subject/object. `cluster` declares `system_admin: [user,
// service_account]` in the canonical model — a plain direct userset, so an allow
// here means the tuple was found and nothing else.
const (
	probeSubject  = "user:fgatest-isolation-probe"
	probeRelation = "system_admin"
	probeObject   = "cluster:fgatest-isolation"
)

// TestOneServerManyStores — exactly what the shared-server harness claims: two
// harnesses in one process reach the SAME server and get DIFFERENT stores, and a
// tuple written through one is invisible through the other.
//
// All three halves are needed together. Same server without different stores
// would mean the tests share a tuple space — isolation lost, and lost silently,
// because a stray tuple usually only shows up as somebody else's flake. Different
// stores without the same server would mean the container is still per call — the
// whole point of the change gone, while every assertion here still passed.
func TestOneServerManyStores(t *testing.T) {
	// No -short guard of its own: fgatest.New skips under -short as its first
	// statement, and a second guard here could only drift from it.
	first := fgatest.New(t)
	second := fgatest.New(t)

	if first.Client.Endpoint != second.Client.Endpoint {
		t.Errorf("two harnesses came from DIFFERENT servers (%s and %s) — fgatest is still "+
			"starting a container per call, and the packages that call it pay for one each",
			first.Client.Endpoint, second.Client.Endpoint)
	}
	if first.Client.StoreID == second.Client.StoreID {
		t.Errorf("two harnesses were handed the SAME store (%s) — tests would see each "+
			"other's tuples", first.Client.StoreID)
	}

	ctx := context.Background()
	first.Write(t, probeSubject, probeRelation, probeObject)

	// The positive half FIRST. Without it "not visible in the second" would stay
	// green even if the write never landed anywhere at all — a negative on its own
	// is loudest exactly when everything is broken.
	allowed, err := first.Client.CheckConsistent(ctx, probeSubject, probeRelation, probeObject)
	require.NoError(t, err, "Check against the store the tuple was written to")
	if !allowed {
		t.Fatalf("the tuple is not visible in its OWN store (%s) — the probe proves nothing "+
			"about isolation", first.Client.StoreID)
	}

	allowed, err = second.Client.CheckConsistent(ctx, probeSubject, probeRelation, probeObject)
	require.NoError(t, err, "Check against the other store")
	if allowed {
		t.Errorf("a tuple written through the first harness (store %s) answers ALLOW through "+
			"the second (store %s) — the isolation a separate container used to give is gone",
			first.Client.StoreID, second.Client.StoreID)
	}
}

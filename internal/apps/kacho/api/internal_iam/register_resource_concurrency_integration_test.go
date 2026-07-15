// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// register_resource_concurrency_integration_test.go — SEC-C A-06 (ban #10).
//
// Two concurrent RegisterResource calls with an identical tuple must BOTH
// succeed (no INTERNAL leak, no panic). The owner-tuple is at-least-once via
// transactional outbox + drainer: each call enqueues its own outbox row and the
// drainer collapses duplicates through FGA already_exists→ErrAlreadyApplied
// (fga_applier.go), yielding exactly one effective FGA tuple. The race-safety
// invariant under test is "concurrent enqueue never errors / never double-applies".
//
// Skipped under `go test -short`.
package internal_iam_test

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	internaliam "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/internal_iam"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func TestRegisterResource_A06_ConcurrentRegisterIdempotent(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, kachopg.NewTestPostgres(t))
	require.NoError(t, err)
	defer pool.Close()

	uc := internaliam.NewRegisterResourceUseCase(
		kachopg.NewFGAOutboxEmitter(),
		kachopg.NewResourceMirrorEmitter(),
		kachopg.NewPoolTxBeginner(pool),
	)

	req := &iamv1.RegisterResourceRequest{
		SubjectId: "project:prj-1", Relation: "parent", Object: "vpc_network:enp00000000000000002",
	}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			errs[i] = uc.Register(ctx, req)
		}(i)
	}
	wg.Wait()

	for i, e := range errs {
		require.NoError(t, e, "concurrent register #%d must succeed (idempotent, no INTERNAL leak)", i)
	}

	// All N enqueued (at-least-once); the drainer idempotently collapses them.
	var count int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.fga_outbox
		  WHERE payload->>'object' = 'vpc_network:enp00000000000000002'`).Scan(&count))
	require.Equal(t, n, count, "each concurrent call enqueues its own outbox row")
}

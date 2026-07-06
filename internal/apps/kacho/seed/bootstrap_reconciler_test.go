// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// bootstrap_reconciler_test.go — Bug B unit tests for the startup bootstrap
// reconciler loop.
//
// RunBootstrapAdmin is idempotent + graceful: it skips when the bootstrap
// user is not yet registered (the Kratos identity is mirrored into
// kacho_iam.users only on first login / fixture upsert, which happens AFTER
// kacho-iam boots). A single startup invocation therefore races the user
// row and usually skips — the cluster-admin tuple is never written.
//
// BootstrapReconciler closes that gap: it re-runs the seed on an interval
// until it commits the grant (Skipped=false) or the run errors fatally, then
// stops. These tests pin the loop semantics with an injected runner (no DB).

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBootstrapReconciler_RetriesUntilGrantCommitted(t *testing.T) {
	var calls atomic.Int64
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		n := calls.Add(1)
		if n < 3 {
			// User not registered yet — graceful skip, keep retrying.
			return BootstrapAdminResult{Skipped: true, SkipReason: "user not registered"}, nil
		}
		// User appeared — grant + outbox committed.
		return BootstrapAdminResult{Skipped: false, GrantID: "cag_x", FGAOutboxID: "fga_1", UserID: "usr_boot"}, nil
	}

	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := rec.Run(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, calls.Load(), int64(3), "must retry the skipping runs until the grant commits")
}

func TestBootstrapReconciler_StopsAfterSuccess(t *testing.T) {
	var calls atomic.Int64
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		calls.Add(1)
		return BootstrapAdminResult{Skipped: false, GrantID: "cag_x", UserID: "usr_boot"}, nil
	}
	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	require.NoError(t, rec.Run(ctx))
	// Run drives the loop synchronously in THIS goroutine and returns the moment
	// it stops — there is no background worker that could keep calling `run`
	// afterwards. So the call count is final the instant Run returns: exactly one
	// invocation proves it stopped on the first committed grant (a "fails to stop"
	// regression would loop forever and never return, tripping the ctx deadline).
	assert.Equal(t, int64(1), calls.Load(), "reconciler must stop after the first committed grant")
}

func TestBootstrapReconciler_EmailEmpty_NoOp(t *testing.T) {
	var calls atomic.Int64
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		calls.Add(1)
		// email-empty skip is terminal — there is no email to ever resolve.
		return BootstrapAdminResult{Skipped: true, SkipReason: "email empty"}, nil
	}
	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	require.NoError(t, rec.Run(ctx))
	// Run is synchronous (see StopsAfterSuccess): the count is final when it
	// returns, so a single invocation proves the terminal "email empty" skip
	// short-circuited instead of entering the retry loop.
	assert.Equal(t, int64(1), calls.Load(), "email-empty must short-circuit to a single no-op run (no busy retry loop)")
}

func TestBootstrapReconciler_ContextCancel_Stops(t *testing.T) {
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		return BootstrapAdminResult{Skipped: true, SkipReason: "user not registered"}, nil
	}
	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Returns nil (clean shutdown) when the parent context is cancelled while
	// still skipping — it is not a fatal error, just "never converged".
	err := rec.Run(ctx)
	require.NoError(t, err)
}

func TestBootstrapReconciler_TransientError_Retries(t *testing.T) {
	var calls atomic.Int64
	run := func(ctx context.Context) (BootstrapAdminResult, error) {
		n := calls.Add(1)
		if n < 2 {
			return BootstrapAdminResult{}, errors.New("transient DB error")
		}
		return BootstrapAdminResult{Skipped: false, GrantID: "cag_x", UserID: "usr_boot"}, nil
	}
	rec := NewBootstrapReconciler(run, BootstrapReconcilerConfig{Interval: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	require.NoError(t, rec.Run(ctx))
	assert.GreaterOrEqual(t, calls.Load(), int64(2), "transient errors must be retried, not fatal")
}

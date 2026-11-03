// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

func rid02AwaitBoundary(t *testing.T, f *installationNativeWorld, child *rid02OwnedChild, stage string) rid02ChildEvent {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 25*time.Second)
	defer cancel()
	return child.await(t, ctx, stage)
}
func rid02RequireTerminalRefusal(t *testing.T, f *installationNativeWorld, label string, r rid02CrashRecord) {
	t.Helper()
	input := r.Input
	input.Action = "terminal-refusal"
	input.Operation = r.Operation
	input.Proposed = r.Proposed
	before, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, r.Operation)
	require.NoError(t, err)
	require.True(t, before.Done)
	child := startRID02Child(t, f, label, input)
	rid02AwaitBoundary(t, f, child, "terminal-refused")
	child.wait(t, false)
	after, err := operations.NewRepo(f.given.pool, "kaname").Get(f.given.ctx, r.Operation)
	require.NoError(t, err)
	require.Equal(t, before, after, "fresh verified late writer cannot change terminal result")
}
func ridNativeCancellationReconcilerOverlap(t *testing.T) {
	f, inputs := rid02StageCrashWorld(t)
	normal := operations.NewRepo(f.given.pool, "kaname")
	// Normal ownership-scoped Operation.Cancel under freshly verified standing C;
	// old worker is resumed well before its four-minute deadline.
	cancelInput := inputs[0]
	cancelInput.Boundary = "before-writer"
	cancelChild := startRID02Child(t, f, "authorized-cancel", cancelInput)
	event := rid02AwaitBoundary(t, f, cancelChild, "before-writer")
	cancelledRecord := rid02Pending(t, f, cancelInput, event.Operation, false)
	started := time.Now()
	cancelChild.release(t, "cancel")
	rid02AwaitBoundary(t, f, cancelChild, "worker-finished")
	cancelChild.wait(t, false)
	require.Less(t, time.Since(started), time.Minute, "cancellation overlap must execute with live worker context")
	cancelled, err := normal.Get(f.given.ctx, event.Operation)
	require.NoError(t, err)
	require.True(t, cancelled.Done)
	require.NotNil(t, cancelled.Error)
	require.Equal(t, int32(codes.Canceled), cancelled.Error.Code)
	require.Nil(t, cancelled.Response)
	var count int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, cancelInput.Input.AccountID, cancelInput.Input.DelegateID).Scan(&count))
	require.Zero(t, count)
	rid02RequireTerminalRefusal(t, f, "cancelled-terminal-refusal", cancelledRecord)

	// Stagger three distinct real Operations, then share ONE actual five-minute
	// grace. Native serve was stopped before staging orphans; only this Sweep is
	// allowed to consume them. Neither worker timeout nor DB idle timeout changes.
	var records []rid02CrashRecord
	var live []*rid02OwnedChild
	for i, stage := range []string{"before-writer", "after-commit-before-terminal", "before-writer"} {
		input := inputs[i+1]
		input.Boundary = stage
		child := startRID02Child(t, f, "overlap-"+string(rune('a'+i)), input)
		e := rid02AwaitBoundary(t, f, child, stage)
		records = append(records, rid02Pending(t, f, input, e.Operation, i == 1))
		if i == 2 {
			require.NoError(t, child.kill())
			child.wait(t, true)
		} else {
			live = append(live, child)
		}
	}
	reconciler, _, observer := rid02Recovery(t, f)
	n, err := reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	rid02WaitOrphanGrace(t, f, records)
	// Inverse ordering is explicitly a REAL repository protocol proof, not a
	// claim that the old four-minute worker can successfully execute at five.
	// LockPendingInstallationOperation holds the orphan row for <25s, preserving
	// the production sixty-second idle transaction guard.
	locked := records[2]
	lockInput := locked.Input
	lockInput.Action = "lock-pending"
	lockInput.Operation = locked.Operation
	lockInput.Proposed = locked.Proposed
	locker := startRID02Child(t, f, "inverse-real-writer-lock", lockInput)
	rid02AwaitBoundary(t, f, locker, "row-locked")
	sweepCtx, sweepCancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	n, err = reconciler.Sweep(sweepCtx)
	sweepCancel()
	require.NoError(t, err)
	require.Equal(t, 2, n, "actual Sweep must skip exact real-writer locked orphan and recover other two")
	pending, err := normal.Get(f.given.ctx, locked.Operation)
	require.NoError(t, err)
	require.False(t, pending.Done)
	require.EqualValues(t, 2, observer.primary.Load())
	locker.release(t, "continue")
	locker.wait(t, false)
	n, err = reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Equal(t, 1, n, "released real writer allows primary recovery")
	for i, r := range records {
		terminal, err := normal.Get(f.given.ctx, r.Operation)
		require.NoError(t, err)
		require.True(t, terminal.Done)
		if r.Committed {
			requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, r.Operation, r.Input.Input.AccountID, f.creator.ID, r.Proposed)
		} else {
			require.NotNil(t, terminal.Error)
			require.Equal(t, int32(codes.Internal), terminal.Error.Code)
			require.Equal(t, "operation interrupted before completion", terminal.Error.Message)
			require.Nil(t, terminal.Response)
		}
		if i < len(live) {
			live[i].release(t, "continue")
			rid02AwaitBoundary(t, f, live[i], "worker-finished")
			live[i].wait(t, false)
			if r.Committed {
				attempts := live[i].terminalAttempts(t)
				require.Len(t, attempts, 1, "real Run must complete exactly one terminal CAS attempt")
				a := attempts[0]
				require.True(t, a.ContextLiveBefore, "actual MarkDone attempt context must be live")
				require.True(t, a.ContextLiveAfter)
				require.True(t, a.ReadBeforeOK)
				require.True(t, a.ReadAfterOK)
				require.False(t, a.Started.IsZero())
				require.False(t, a.Finished.Before(a.Started))
				require.True(t, a.AlreadyDone, "real MarkDone must return ErrAlreadyDone, not deadline refusal")
				expected, err := json.Marshal(terminal)
				require.NoError(t, err)
				require.Equal(t, string(expected), string(a.Before), "all persisted Operation fields before actual CAS")
				require.Equal(t, string(expected), string(a.After), "all persisted Operation fields after actual CAS")
			}
			after, err := normal.Get(f.given.ctx, r.Operation)
			require.NoError(t, err)
			require.Equal(t, terminal, after, "late original worker terminal attempt cannot resurrect or overwrite recovered result")
		}
		// Expired old worker context is NOT evidence of this independent fresh
		// context check: actual verified C + real writer rejects terminal state.
		rid02RequireTerminalRefusal(t, f, "recovered-terminal-refusal-"+string(rune('a'+i)), r)
	}
	n, err = reconciler.Sweep(f.given.ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	after, err := normal.Get(f.given.ctx, cancelledRecord.Operation)
	require.NoError(t, err)
	require.Equal(t, cancelled, after)
	rid02PublicRecoveredCensus(t, f, append([]rid02CrashRecord{cancelledRecord}, records...))
	f.requireSameCredential(t)
}

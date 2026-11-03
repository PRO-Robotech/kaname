// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// nil preserves the existing bridge's caller/default behavior. A budgeted
// observer checks the actual deadline as well as cancellation, including timer lag.
func ridNewmanBudgetCheck(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if ctx.Err() != nil {
		return errors.New("Newman observation budget expired")
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return errors.New("Newman observation budget expired")
	}
	return nil
}

type ridNewmanBudgetWriter interface {
	Write([]byte) (int, error)
	SetWriteDeadline(time.Time) error
}

// written is true ONLY after the real Encode succeeds, even if the subsequent
// deadline check rejects acceptance. Cleanup must not send a second permit then.
func ridNewmanBudgetWrite(ctx context.Context, out ridNewmanBudgetWriter, action string, cap time.Duration) (written bool, err error) {
	if err = ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	deadline := time.Now().Add(cap)
	if ctx != nil {
		if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
			deadline = parent
		}
	}
	if err = out.SetWriteDeadline(deadline); err != nil {
		return false, err
	}
	if err = ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	if err = json.NewEncoder(out).Encode(action); err != nil {
		return false, err
	}
	return true, ridNewmanBudgetCheck(ctx)
}

type rid06CriticalActions struct {
	Await, Pending, Revoke, Boundary func(context.Context) error
	Release                          func(context.Context) (bool, error)
}

// This is the actual optional-observer controller, shared by all four worlds.
// A failed check never advances to the next stage; cleanup/reap is owned outside.
func rid06RunCritical(ctx context.Context, actions rid06CriticalActions) (bool, error) {
	for _, stage := range []func(context.Context) error{actions.Await, actions.Pending, actions.Revoke, actions.Boundary} {
		if err := ridNewmanBudgetCheck(ctx); err != nil {
			return false, err
		}
		if err := stage(ctx); err != nil {
			return false, err
		}
		if err := ridNewmanBudgetCheck(ctx); err != nil {
			return false, err
		}
	}
	if err := ridNewmanBudgetCheck(ctx); err != nil {
		return false, err
	}
	written, err := actions.Release(ctx)
	if err != nil {
		return written, err
	}
	return written, ridNewmanBudgetCheck(ctx)
}

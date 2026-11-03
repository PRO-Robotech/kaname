// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/observability"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

const rid06ChildInputEnv = "KANAME_RID06_FULL_STARTUP_CHILD_INPUT"

type rid06ChildInput struct {
	ConfigPath  string `json:"configPath"`
	Creator     string `json:"creator"`
	PairOrdinal int64  `json:"pairOrdinal"`
}

// Instrumented TEST executable running the actual complete startup root. This
// is not the published executable, a new product command, or a direct Execute
// surrogate. Config, authentication, delivery, guards, listeners and shutdown
// are the same full root used by ordinary runServe(cfg).
func TestRID06OwnedFullStartupChild(t *testing.T) {
	path := os.Getenv(rid06ChildInputEnv)
	if path == "" {
		t.Skip("private owned full-startup child entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
		require.NotNil(t, f)
		return f
	}
	// Inherited ExtraFiles are not automatically pollable os.Pipe handles.
	// Mark only these owned IPC ends nonblocking BEFORE NewFile so deadlines
	// register with the Go poller. Cleanup is installed before asserting errors.
	eventModeErr := syscall.SetNonblock(3, true)
	events := own(3, "rid06-events")
	require.NoError(t, eventModeErr)
	controlModeErr := syscall.SetNonblock(4, true)
	control := own(4, "rid06-control")
	require.NoError(t, controlModeErr)
	inventory := own(5, "rid06-anonymous-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid06ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.Positive(t, input.PairOrdinal)
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	var mu sync.Mutex
	var captureErr error
	// Capture occurs synchronously at actual production issuance, BEFORE any
	// subsequent failure. Only anonymous FD5 receives secrets, never receipts/logs.
	observe := func(pem, token string) {
		mu.Lock()
		defer mu.Unlock()
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, token})
		}
	}
	observationError := func() error {
		mu.Lock()
		defer mu.Unlock()
		if captureErr != nil {
			return fmt.Errorf("anonymous secret capture failed")
		}
		return nil
	}
	decorator := func(real kanamerepo.Repository) kanamerepo.Repository {
		r := &rid06FullStartupRepo{ridBoundaryRepo: &ridBoundaryRepo{Repository: real}}
		r.beforePair = func(ctx context.Context, arrival ridArrival) error {
			if arrival.Writer != input.PairOrdinal {
				return nil
			}
			if err := observationError(); err != nil {
				return err
			}
			principal, ok := operations.PrincipalFromContextOK(ctx)
			if !ok || principal.Type != "service_account" || principal.ID != input.Creator {
				return fmt.Errorf("full startup boundary lacks actual creator identity")
			}
			// No pair lock is held here. Only this attempt's pending Operation row is
			// locked by the real writer, so independent O can commit ordinary Revoke.
			deadline := time.Now().Add(20 * time.Second)
			if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
				deadline = d
			}
			if err := events.SetWriteDeadline(deadline); err != nil {
				return err
			}
			if err := control.SetReadDeadline(deadline); err != nil {
				return err
			}
			stop := context.AfterFunc(ctx, func() { _ = control.SetReadDeadline(time.Now()) })
			defer stop()
			if err := json.NewEncoder(events).Encode(rid02ChildEvent{Stage: "before-pair", Operation: arrival.OperationID, PID: os.Getpid()}); err != nil {
				return err
			}
			var action string
			if err := json.NewDecoder(control).Decode(&action); err != nil {
				return fmt.Errorf("owned before-pair control failed: %w", err)
			}
			if action != "continue" {
				return fmt.Errorf("unexpected owned before-pair action")
			}
			return ctx.Err()
		}
		return r
	}
	err = runServe(cfg, installationServeDependencies{decorateInstallationRepository: decorator, observeCredential: observe})
	require.NoError(t, observationError())
	if err != nil {
		observability.NewSlogger(os.Stderr).Error("kaname exited with error", "err", err)
		t.Error("actual complete startup returned failure; structured private result retained")
	}
}

// Repository embedding alone loses this optional primary port. Forward it to
// the actual repository; never substitute a reader or a primary result.
type rid06FullStartupRepo struct{ *ridBoundaryRepo }

func (r *rid06FullStartupRepo) ReaderFromPrimary(ctx context.Context) (kanamerepo.Reader, error) {
	p, ok := r.Repository.(interface {
		ReaderFromPrimary(context.Context) (kanamerepo.Reader, error)
	})
	if !ok {
		return nil, fmt.Errorf("actual repository lacks primary reader")
	}
	return p.ReaderFromPrimary(ctx)
}

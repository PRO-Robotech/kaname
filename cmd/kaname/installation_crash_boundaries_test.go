// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"google.golang.org/protobuf/types/known/anypb"
)

// PRIVATE child-driver foundation. A boundary only announces and waits on an
// owned IPC control; it cannot return a fabricated DB result or impersonate C.
// The owned child entrypoint supplies actual production authentication; its
// parent observes persistence and kills the exact process at the selected point.
type rid02Boundary func(context.Context, string, string) error

type rid02ObservedOperation struct {
	mu       sync.Mutex
	id       string
	attempts []rid02TerminalAttempt
}

func (s *rid02ObservedOperation) set(id string) { s.mu.Lock(); defer s.mu.Unlock(); s.id = id }
func (s *rid02ObservedOperation) get() string   { s.mu.Lock(); defer s.mu.Unlock(); return s.id }

// These are observations around the REAL repository CAS, not substitute writes.
type rid02TerminalAttempt struct {
	Started, Finished                   time.Time
	ContextLiveBefore, ContextLiveAfter bool
	ReadBeforeOK, ReadAfterOK           bool
	AlreadyDone                         bool
	Before, After                       json.RawMessage
}

func (s *rid02ObservedOperation) record(a rid02TerminalAttempt) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts = append(s.attempts, a)
}
func (s *rid02ObservedOperation) terminalAttempts() []rid02TerminalAttempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]rid02TerminalAttempt(nil), s.attempts...)
}

type rid02CrashRepo struct {
	kanamerepo.Repository
	operation *rid02ObservedOperation
	boundary  rid02Boundary
}

func (r *rid02CrashRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	id := r.operation.get()
	if id == "" {
		return nil, fmt.Errorf("crash fixture has no ordinary persisted Operation")
	}
	if err := r.boundary(ctx, "before-writer", id); err != nil {
		return nil, err
	}
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	cap, ok := w.(installationTransactionControl)
	if !ok {
		_ = w.Rollback(ctx)
		return nil, fmt.Errorf("actual writer lacks installation transaction capability")
	}
	return &rid02CrashWriter{Writer: w, installation: cap, operation: id, boundary: r.boundary}, nil
}

// Forward the primary port as well. Repository embedding alone would silently
// lose it and turn a test seam into a different recovery implementation.
func (r *rid02CrashRepo) ReaderFromPrimary(ctx context.Context) (kanamerepo.Reader, error) {
	primary, ok := r.Repository.(interface {
		ReaderFromPrimary(context.Context) (kanamerepo.Reader, error)
	})
	if !ok {
		return nil, fmt.Errorf("actual repository lacks primary reader")
	}
	return primary.ReaderFromPrimary(ctx)
}

type rid02CrashWriter struct {
	kanamerepo.Writer
	installation installationTransactionControl
	operation    string
	boundary     rid02Boundary
}

func (w *rid02CrashWriter) LockPendingInstallationOperation(ctx context.Context, id, account, proposed string) error {
	return w.installation.LockPendingInstallationOperation(ctx, id, account, proposed)
}
func (w *rid02CrashWriter) RequireInstallationAuthority(ctx context.Context, plans *authzmodel.Plans) error {
	return w.installation.RequireInstallationAuthority(ctx, plans)
}
func (w *rid02CrashWriter) BindInstallationOperation(ctx context.Context, id string, metadata *anypb.Any, winner string) error {
	return w.installation.BindInstallationOperation(ctx, id, metadata, winner)
}
func (w *rid02CrashWriter) Commit(ctx context.Context) error {
	if err := w.boundary(ctx, "before-commit", w.operation); err != nil {
		return err
	}
	if err := w.Writer.Commit(ctx); err != nil {
		return err
	}
	// No SQL transaction remains open here. The owned IPC pause precedes return
	// from the operation function, so operations.Run has NOT yet created its
	// fresh terminal attempt context. The original worker deadline is unchanged.
	return w.boundary(ctx, "after-commit-before-terminal", w.operation)
}

type rid02CrashOperations struct {
	operations.Repo
	observed *rid02ObservedOperation
}

func (r *rid02CrashOperations) Create(ctx context.Context, op operations.Operation) error {
	if err := r.Repo.Create(ctx, op); err != nil {
		return err
	}
	r.observed.set(op.ID)
	return nil
}

// This method intentionally remains present: dropping the optional worker
// executionClaimer would remove the normal terminal-state guard from the test.
func (r *rid02CrashOperations) ClaimForExecution(ctx context.Context, id string) (bool, error) {
	actual, ok := r.Repo.(interface {
		ClaimForExecution(context.Context, string) (bool, error)
	})
	if !ok {
		return false, fmt.Errorf("normal Operations repository lacks execution claim")
	}
	return actual.ClaimForExecution(ctx, id)
}
func (r *rid02CrashOperations) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	a := rid02TerminalAttempt{}
	before, err := r.Repo.Get(ctx, id)
	a.ReadBeforeOK = err == nil
	if err == nil {
		a.Before, err = json.Marshal(before)
		a.ReadBeforeOK = err == nil
	}
	a.Started = time.Now()
	a.ContextLiveBefore = ctx.Err() == nil
	// Never replace, renew or detach this context: it must come from real Run.
	err = r.Repo.MarkDone(ctx, id, response)
	a.Finished = time.Now()
	a.ContextLiveAfter = ctx.Err() == nil
	a.AlreadyDone = errors.Is(err, operations.ErrAlreadyDone)
	after, readErr := r.Repo.Get(ctx, id)
	a.ReadAfterOK = readErr == nil
	if readErr == nil {
		a.After, readErr = json.Marshal(after)
		a.ReadAfterOK = readErr == nil
	}
	r.observed.record(a)
	return err
}

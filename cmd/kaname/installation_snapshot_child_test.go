// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const rid08ChildInputEnv = "KANAME_RID08_SNAPSHOT_CHILD_INPUT"

type rid08ChildInput struct {
	ConfigPath, EvidenceDir        string
	PauseSnapshot, FaultSecondPage bool
}
type rid08SnapshotObservation struct {
	Accounts        []domain.AccountID
	System          domain.AccountID
	PageSize, Pages int
	CompletedAt     time.Time
	ContextLive     bool
}
type rid08PageObservation struct {
	Page                   int
	ContextLive            bool
	ReadOnlyRepeatableRead bool
	ObservedAt             time.Time
	Fault                  bool
}

// This safe receipt contains no arbitrary returned-error message. It records
// the status of the ACTUAL runServe return, never a separately mapped surrogate.
type rid08ReturnedStatus struct {
	ErrorPresent   bool  `json:"errorPresent"`
	Code           int32 `json:"code"`
	MessageMatches bool  `json:"messageMatches"`
}

// Only the owned test executable selects these dependencies. The entrypoint
// executes the SAME complete runServe with real authn, full manifests and writers.
func TestRID08OwnedSnapshotStartupChild(t *testing.T) {
	path := os.Getenv(rid08ChildInputEnv)
	if path == "" {
		t.Skip("private owned snapshot startup entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
		require.NotNil(t, f)
		return f
	}
	eventErr := syscall.SetNonblock(3, true)
	events := own(3, "rid08-events")
	require.NoError(t, eventErr)
	controlErr := syscall.SetNonblock(4, true)
	control := own(4, "rid08-control")
	require.NoError(t, controlErr)
	inventory := own(5, "rid08-anonymous-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid08ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	var mu sync.Mutex
	var captureErr error
	observer := func(pem, token string) {
		mu.Lock()
		defer mu.Unlock()
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, token})
		}
	}
	captureOK := func() error {
		mu.Lock()
		defer mu.Unlock()
		if captureErr != nil {
			return fmt.Errorf("anonymous startup secret capture failed")
		}
		return nil
	}
	emit := func(ctx context.Context, stage string) error {
		if err := captureOK(); err != nil {
			return err
		}
		deadline := time.Now().Add(30 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err := events.SetWriteDeadline(deadline); err != nil {
			return err
		}
		return json.NewEncoder(events).Encode(rid02ChildEvent{Stage: stage, PID: os.Getpid()})
	}
	pages := &rid08ObservedPages{dir: input.EvidenceDir, fault: input.FaultSecondPage, emit: emit}
	decorate := func(real *kanamepg.InstallationReader) installationReadSource {
		return &rid08ObservedReader{installationReadSource: real.WithPageFactory(pages), pages: pages, input: input, events: emit, control: control}
	}
	err = runServe(cfg, installationServeDependencies{decorateInstallationReader: decorate, installationPageSize: 2, observeCredential: observer})
	returned := status.Convert(err)
	observed := rid08ReturnedStatus{ErrorPresent: err != nil, Code: int32(returned.Code()), MessageMatches: returned.Message() == "internal error"}
	// Do not log or persist an unexpected arbitrary message, including in a
	// failed assertion. The production structured result remains independently
	// required by the parent; this receipt verifies its formerly hidden cause.
	safeStatus, receiptErr := json.Marshal(observed)
	require.NoError(t, receiptErr)
	require.NoError(t, os.WriteFile(filepath.Join(input.EvidenceDir, "actual-returned-status.json"), safeStatus, 0600))
	require.NoError(t, captureOK())
	if input.FaultSecondPage {
		require.True(t, observed.ErrorPresent, "actual full startup unexpectedly returned no error")
		require.Equal(t, int32(codes.Internal), observed.Code, "actual full startup status code mismatch")
		require.True(t, observed.MessageMatches, "actual full startup message mismatch; arbitrary text withheld")
	}
	if err != nil {
		t.Error("actual snapshot startup failed; safe status receipt and structured outcome retained")
	}
}

type rid08ObservedPages struct {
	dir   string
	fault bool
	calls int
	emit  func(context.Context, string) error
}

func (p *rid08ObservedPages) BeginTx(ctx context.Context, tx pgx.Tx, options pgx.TxOptions) (pgx.Tx, error) {
	p.calls++
	observation := rid08PageObservation{Page: p.calls, ContextLive: ctx.Err() == nil, ReadOnlyRepeatableRead: options == (pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead}), ObservedAt: time.Now().UTC(), Fault: p.fault && p.calls == 2}
	raw, err := json.Marshal(observation)
	if err != nil {
		return nil, err
	}
	if err = os.WriteFile(filepath.Join(p.dir, fmt.Sprintf("page-%02d.json", p.calls)), raw, 0600); err != nil {
		return nil, err
	}
	if observation.Fault {
		if err = p.emit(ctx, "second-page-fault"); err != nil {
			return nil, err
		}
		// Fresh unknown non-sentinel error at the REAL second nested BeginTx boundary.
		// The previous page and coordinator were real; the reader owns their cleanup.
		return nil, fmt.Errorf("owned RID08 fresh second-page BeginTx failure")
	}
	return (kanamepg.NestedInstallationPages{}).BeginTx(ctx, tx, options)
}

type rid08ObservedReader struct {
	installationReadSource
	pages   *rid08ObservedPages
	input   rid08ChildInput
	events  func(context.Context, string) error
	control *os.File
}

func (r *rid08ObservedReader) InstallationAccounts(ctx context.Context, target string, size int) ([]domain.AccountID, domain.AccountID, error) {
	accounts, system, err := r.installationReadSource.InstallationAccounts(ctx, target, size)
	if err != nil {
		return accounts, system, err
	}
	// The real canonical reader has committed/released its RR transaction BEFORE
	// this observer. The returned membership is retained exactly, never replaced.
	observed := rid08SnapshotObservation{Accounts: append([]domain.AccountID(nil), accounts...), System: system, PageSize: size, Pages: r.pages.calls, CompletedAt: time.Now().UTC(), ContextLive: ctx.Err() == nil}
	raw, err := json.Marshal(observed)
	if err != nil {
		return nil, "", err
	}
	if err = os.WriteFile(filepath.Join(r.input.EvidenceDir, "canonical-snapshot.json"), raw, 0600); err != nil {
		return nil, "", err
	}
	if err = r.events(ctx, "snapshot-complete"); err != nil {
		return nil, "", err
	}
	if r.input.PauseSnapshot {
		deadline := time.Now().Add(30 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err = r.control.SetReadDeadline(deadline); err != nil {
			return nil, "", err
		}
		stop := context.AfterFunc(ctx, func() { _ = r.control.SetReadDeadline(time.Now()) })
		defer stop()
		var action string
		if err = json.NewDecoder(r.control).Decode(&action); err != nil {
			return nil, "", fmt.Errorf("owned snapshot continuation failed: %w", err)
		}
		if action != "continue" {
			return nil, "", fmt.Errorf("invalid owned snapshot continuation")
		}
	}
	return accounts, system, ctx.Err()
}

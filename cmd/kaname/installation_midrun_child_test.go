// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const rid10ChildEnv = "KANAME_RID10_FULL_STARTUP_CHILD_INPUT"

type rid10ChildInput struct{ ConfigPath, EvidenceDir, Creator, Mode string }
type rid10Returned struct {
	Code                                 int32
	MessageMatches, ControlOK, CaptureOK bool
	Completed                            int
	WriterArrivals                       int64
	FaultInjected, FaultContextLive      bool
}

func TestRID10OwnedMidrunStartupChild(t *testing.T) {
	path := os.Getenv(rid10ChildEnv)
	if path == "" {
		t.Skip("owned midrun full-startup test entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
		require.NotNil(t, f)
		return f
	}
	eerr := syscall.SetNonblock(3, true)
	events := own(3, "rid10-events")
	require.NoError(t, eerr)
	cerr := syscall.SetNonblock(4, true)
	control := own(4, "rid10-control")
	require.NoError(t, cerr)
	inventory := own(5, "rid10-anonymous-secrets")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	// К этому рукопожатию владения не приписывается утверждение об аутентификации.
	require.NoError(t, events.SetWriteDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, control.SetReadDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, json.NewEncoder(events).Encode(rid02ChildEvent{Stage: "midrun-preauth-armed", PID: os.Getpid()}))
	var action string
	require.NoError(t, json.NewDecoder(control).Decode(&action))
	require.True(t, action == "start")
	require.NoError(t, events.SetWriteDeadline(time.Time{}))
	require.NoError(t, control.SetReadDeadline(time.Time{}))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid10ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.Contains(t, []string{"fault", "retirement", "twin"}, input.Mode)
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	var mu sync.Mutex
	var captureErr, controlErr error
	completed := 0
	var writers int64
	injected, live := false, false
	observe := func(pem, token string) {
		mu.Lock()
		defer mu.Unlock()
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, token})
		}
	}
	write := func(name string, v any) error {
		b, e := json.Marshal(v)
		if e != nil {
			return e
		}
		return os.WriteFile(filepath.Join(input.EvidenceDir, name+".json"), b, 0600)
	}
	pause := func(ctx context.Context, stage, op string) error {
		deadline := time.Now().Add(60 * time.Second)
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if e := events.SetWriteDeadline(deadline); e != nil {
			return e
		}
		if e := control.SetReadDeadline(deadline); e != nil {
			return e
		}
		stop := context.AfterFunc(ctx, func() { _ = control.SetReadDeadline(time.Now()) })
		defer stop()
		if e := json.NewEncoder(events).Encode(rid02ChildEvent{Stage: stage, Operation: op, PID: os.Getpid()}); e != nil {
			return e
		}
		var release string
		if e := json.NewDecoder(control).Decode(&release); e != nil {
			return e
		}
		if release != "continue" {
			return fmt.Errorf("owned midrun control mismatch")
		}
		return ctx.Err()
	}
	recordControl := func(e error) error {
		if e != nil {
			mu.Lock()
			controlErr = e
			mu.Unlock()
			return fmt.Errorf("owned midrun fixture control failed")
		}
		return nil
	}
	after := func(ctx context.Context, pair installationCompletedPair) error {
		completed = pair.CompletedPairs
		if pair.CompletedPairs != 1 {
			return nil
		}
		if e := write("first-completed-pair", pair); e != nil {
			return recordControl(e)
		}
		return recordControl(pause(ctx, "first-pair-done", pair.OperationID))
	}
	decorator := func(real kanamerepo.Repository) kanamerepo.Repository {
		r := &rid06FullStartupRepo{ridBoundaryRepo: &ridBoundaryRepo{Repository: real}}
		r.beforeWriter = func(ctx context.Context, ordinal int64) error {
			mu.Lock()
			writers = ordinal
			mu.Unlock()
			if ordinal != 2 || input.Mode != "fault" {
				return nil
			}
			principal, ok := operations.PrincipalFromContextOK(ctx)
			if !ok || principal.Type != "service_account" || principal.ID != input.Creator {
				return recordControl(fmt.Errorf("actual creator mismatch"))
			}
			if ctx.Err() != nil {
				return recordControl(fmt.Errorf("writer context not live"))
			}
			if e := recordControl(pause(ctx, "second-writer-before-begin", "")); e != nil {
				return e
			}
			if ctx.Err() != nil {
				return recordControl(fmt.Errorf("writer context expired before injection"))
			}
			mu.Lock()
			live = true
			injected = true
			mu.Unlock()
			if e := write("fresh-writer-fault", map[string]any{"ordinal": ordinal, "contextLive": true, "creator": principal.ID, "freshUnknown": true, "sentinel": false}); e != nil {
				return recordControl(e)
			}
			// Свежая непрозрачная ошибка, без сигнального значения отмены/срока/недоступности.
			return errors.New("RID10 owned fresh second writer begin fault")
		}
		return r
	}
	err = runServe(cfg, installationServeDependencies{decorateInstallationRepository: decorator, observeCredential: observe, afterCompletedInstallationPair: after})
	code := status.Code(err)
	wantCode := codes.OK
	wantMessage := ""
	if input.Mode == "fault" {
		wantCode = codes.Internal
		wantMessage = "internal error"
	}
	if input.Mode == "retirement" {
		wantCode = codes.PermissionDenied
		wantMessage = "permission denied"
	}
	mu.Lock()
	receipt := rid10Returned{Code: int32(code), MessageMatches: code == wantCode && (err == nil || status.Convert(err).Message() == wantMessage), ControlOK: controlErr == nil, CaptureOK: captureErr == nil, Completed: completed, WriterArrivals: writers, FaultInjected: injected, FaultContextLive: live}
	mu.Unlock()
	require.NoError(t, write("actual-return", receipt))
	require.True(t, receipt.ControlOK, "fixture control failed, not an expected installation refusal")
	require.True(t, receipt.CaptureOK, "actual secret observation failed")
	if err != nil {
		t.Error("actual complete midrun startup returned failure; safe status receipt retained")
	}
}

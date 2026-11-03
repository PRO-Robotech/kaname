// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"
)

const ridWholeChildEnv = "KANAME_RID_WHOLE_DELIVERY_CHILD_INPUT"

type ridWholeChildInput struct{ ConfigPath, EvidenceDir string }
type ridWholeReturn struct {
	ErrorPresent                  bool
	Code                          int32
	CaptureComplete               bool
	CapturedRecords, IssuedTokens int
}

// Actual full startup; the ONLY optional dependency observes immutable real
// credentials. No reader/repository/fault/model/authority replacement exists.
func TestRIDWholeDeliveryOwnedStartupChild(t *testing.T) {
	path := os.Getenv(ridWholeChildEnv)
	if path == "" {
		t.Skip("owned whole-delivery test entrypoint")
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
	events := own(3, "whole-delivery-events")
	require.NoError(t, eventErr)
	controlErr := syscall.SetNonblock(4, true)
	control := own(4, "whole-delivery-control")
	require.NoError(t, controlErr)
	inventory := own(5, "whole-delivery-anonymous-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	// Pre-authentication barrier is BEFORE config parsing and actual runServe.
	// Parent can establish owned PID/start/argv/PGID and cgroup before a fast
	// expected refusal exits. This event claims no authentication/token issuance.
	deadline := time.Now().Add(15 * time.Second)
	if end, ok := t.Deadline(); ok && end.Before(deadline) {
		deadline = end
	}
	require.NoError(t, events.SetWriteDeadline(deadline))
	require.NoError(t, control.SetReadDeadline(deadline))
	require.NoError(t, json.NewEncoder(events).Encode(rid02ChildEvent{Stage: "whole-preauth-armed", PID: os.Getpid()}))
	var action string
	require.NoError(t, json.NewDecoder(control).Decode(&action), "owned startup release absent/EOF/deadline")
	require.True(t, action == "start-full-startup", "unexpected owned startup release")
	require.NoError(t, events.SetWriteDeadline(time.Time{}))
	require.NoError(t, control.SetReadDeadline(time.Time{}))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input ridWholeChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	var mu sync.Mutex
	var captureErr error
	records, tokens := 0, 0
	observe := func(pem, token string) {
		mu.Lock()
		defer mu.Unlock()
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, token})
			if captureErr == nil {
				records++
				if token != "" {
					tokens++
				}
			}
		}
	}
	err = runServe(cfg, installationServeDependencies{observeCredential: observe})
	mu.Lock()
	receipt := ridWholeReturn{ErrorPresent: err != nil, Code: int32(status.Code(err)), CaptureComplete: captureErr == nil, CapturedRecords: records, IssuedTokens: tokens}
	mu.Unlock()
	raw, marshalErr := json.Marshal(receipt)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(input.EvidenceDir, "actual-return.json"), raw, 0600))
	require.True(t, receipt.CaptureComplete, "anonymous actual secret observation failed")
	if err != nil {
		t.Error("actual complete delivery startup refused; structured result and safe return code retained")
	}
}

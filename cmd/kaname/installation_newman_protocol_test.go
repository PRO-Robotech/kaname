// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const ridNewmanPermitFrame = "RID_NEWMAN_PERMIT_V1\n"

type ridNewmanInputACK struct {
	Version int    `json:"version"`
	PID     int    `json:"pid"`
	CaseID  string `json:"caseId"`
	RunID   string `json:"runId"`
}

func ridNewmanDecodeACK(raw []byte, pid int, caseID, runID string) error {
	if len(raw) > 512 || len(raw) == 0 {
		return errors.New("invalid bounded Node input ACK")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return errors.New("invalid Node input ACK")
	}
	fields := map[string]json.RawMessage{}
	for dec.More() {
		key, err := dec.Token()
		if err != nil {
			return errors.New("invalid Node input ACK")
		}
		name, ok := key.(string)
		if !ok {
			return errors.New("invalid Node input ACK")
		}
		if _, exists := fields[name]; exists {
			return errors.New("repeated Node input ACK field")
		}
		var value json.RawMessage
		if dec.Decode(&value) != nil {
			return errors.New("invalid Node input ACK")
		}
		fields[name] = value
	}
	if _, err = dec.Token(); err != nil {
		return errors.New("invalid Node input ACK")
	}
	if _, err = dec.Token(); err != io.EOF {
		return errors.New("repeated or trailing Node input ACK")
	}
	if len(fields) != 4 {
		return errors.New("invalid Node input ACK fields")
	}
	for _, key := range []string{"version", "pid", "caseId", "runId"} {
		if _, ok := fields[key]; !ok {
			return errors.New("invalid Node input ACK fields")
		}
	}
	var ack ridNewmanInputACK
	if json.Unmarshal(fields["version"], &ack.Version) != nil || json.Unmarshal(fields["pid"], &ack.PID) != nil || json.Unmarshal(fields["caseId"], &ack.CaseID) != nil || json.Unmarshal(fields["runId"], &ack.RunID) != nil {
		return errors.New("invalid Node input ACK value")
	}
	if ack.Version != 1 || ack.PID != pid || ack.PID <= 0 || ack.CaseID != caseID || ack.RunID != runID {
		return errors.New("Node input ACK identity mismatch")
	}
	return nil
}
func ridNewmanAwaitACK(ctx context.Context, pipe *os.File, pid int, caseID, runID string) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return errors.New("Node ACK requires bounded context")
	}
	if pipe.SetReadDeadline(deadline) != nil {
		return errors.New("Node ACK deadline unavailable")
	}
	raw, err := io.ReadAll(io.LimitReader(pipe, 513))
	if err != nil {
		return errors.New("Node ACK unavailable or deadline expired")
	}
	if err = ctx.Err(); err != nil {
		return errors.New("Node ACK budget expired")
	}
	return ridNewmanDecodeACK(raw, pid, caseID, runID)
}
func ridNewmanNodeIdentity(t *testing.T, c *rid02OwnedChild) (int, string) {
	t.Helper()
	var x struct {
		PID   int    `json:"pid"`
		Start string `json:"starttime"`
	}
	raw, err := os.ReadFile(filepath.Join(c.dir, "newman", "process.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &x))
	require.Positive(t, x.PID)
	require.NotEmpty(t, x.Start)
	return x.PID, x.Start
}
func ridNewmanKillExactNode(t *testing.T, c *rid02OwnedChild, in ridNewmanToolInput) {
	t.Helper()
	ridNewmanParentObserveNodeStage(t, c, in, true)
	pid, start := ridNewmanNodeIdentity(t, c)
	actual, err := rid02ProcessStart(pid)
	require.NoError(t, err)
	require.Equal(t, start, actual)
	require.NoError(t, syscall.Kill(pid, syscall.SIGKILL))
}
func ridNewmanAbsenceObservation(ctx context.Context, start string, stat func() error, readStart func() (string, error)) (bool, error) {
	if ctx.Err() != nil {
		return false, errors.New("Node absence budget expired before iteration")
	}
	err := stat()
	if errors.Is(err, os.ErrNotExist) {
		if ctx.Err() != nil {
			return false, errors.New("Node absence budget expired before success")
		}
		return true, nil
	}
	if err != nil {
		return false, errors.New("Node absence metadata unavailable")
	}
	actual, err := readStart()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	} // временное исчезновение, требуем свежего наблюдения отсутствия
	if err != nil {
		return false, errors.New("Node start identity unavailable")
	}
	if actual != start {
		return false, errors.New("Node PID identity recycled before proven absence")
	}
	return false, nil // живой процесс ИЛИ зомби ещё существует
}
func ridNewmanAwaitNodeAbsent(t *testing.T, ctx context.Context, c *rid02OwnedChild) {
	t.Helper()
	pid, start := ridNewmanNodeIdentity(t, c)
	for {
		absent, err := ridNewmanAbsenceObservation(ctx, start, func() error { _, err := os.Stat("/proc/" + strconv.Itoa(pid)); return err }, func() (string, error) { return rid02ProcessStart(pid) })
		require.NoError(t, err)
		if absent {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatal("orphan or zombie Node not absent before bounded deadline")
		case <-time.After(25 * time.Millisecond):
		}
	}
}
func ridNewmanAssertNodeTerminal(t *testing.T, c *rid02OwnedChild, killed bool) {
	t.Helper()
	var terminal struct {
		Exited   bool   `json:"exited"`
		Signaled bool   `json:"signaled"`
		Signal   string `json:"signal"`
		ExitCode int    `json:"exitCode"`
	}
	raw, err := os.ReadFile(filepath.Join(c.dir, "newman", "terminal.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &terminal))
	require.True(t, terminal.Exited)
	if killed {
		require.True(t, terminal.Signaled)
		require.Equal(t, syscall.SIGKILL.String(), terminal.Signal)
		require.Equal(t, -1, terminal.ExitCode)
	} else {
		require.False(t, terminal.Signaled)
		require.Equal(t, 1, terminal.ExitCode)
	}
}

// Кадры разрешения — константы, они не подставляются из окружения/коллекции.
func ridNewmanPermitMessage(probe string) string {
	switch probe {
	case "reject-missing-permit":
		return "reject-node-permit"
	case "node-kill":
		return "observe-node-kill"
	default:
		return "permit-owned-node"
	}
}
func ridNewmanProbeLabel(probe string) string {
	return "protocol-probe-" + strings.ReplaceAll(probe, "_", "-")
}

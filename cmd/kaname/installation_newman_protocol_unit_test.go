// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

func TestRIDNewmanValidatedACKProtocol(t *testing.T) {
	good := `{"version":1,"pid":123,"caseId":"case","runId":"run"}` + "\n"
	for _, tc := range []struct {
		name, raw string
		want      bool
	}{
		{"complete", good, true}, {"empty", "", false}, {"wrong-version", `{"version":2,"pid":123,"caseId":"case","runId":"run"}`, false},
		{"wrong-pid", `{"version":1,"pid":124,"caseId":"case","runId":"run"}`, false},
		{"wrong-case", `{"version":1,"pid":123,"caseId":"other","runId":"run"}`, false},
		{"wrong-run", `{"version":1,"pid":123,"caseId":"case","runId":"other"}`, false},
		{"extra-field", `{"version":1,"pid":123,"caseId":"case","runId":"run","secret":"forbidden"}`, false},
		{"repeated-ACK", good + good, false},
		{"repeated-field", `{"version":1,"version":1,"pid":123,"caseId":"case","runId":"run"}`, false}, {"truncated", `{"version":1`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ridNewmanDecodeACK([]byte(tc.raw), 123, "case", "run")
			if tc.want {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
func TestRIDNewmanGroupKillAuditVerdict(t *testing.T) {
	for _, tc := range []struct {
		name           string
		extra          bool
		missingCheck   bool
		terminalAbsent bool
		want           bool
	}{
		{"exact-incomplete-terminal", false, false, true, true}, {"additional-audit-error", true, false, true, false}, {"incomplete-scan", false, true, true, false}, {"no-missing-terminal", false, false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := ridNewmanAuditResult{Checks: map[string]bool{}, Streams: rid02StreamScan{Requested: 4, Metadata: 4, Read: 4, SecretChecks: 4, JWTChecks: 4, PEMChecks: 4}}
			for _, key := range []string{"allFourStreams", "actualFD5Secrets", "nodeIdentity", "preStdinIdentity", "postACKIdentity", "nodeAbsent", "groupAbsent", "toolTree", "allToolIdentityReads"} {
				r.Checks[key] = true
			}
			if tc.terminalAbsent {
				r.Errors = append(r.Errors, ridNewmanAuditError{"MISSING_NODE_TERMINAL", "missing"})
			}
			if tc.extra {
				r.Errors = append(r.Errors, ridNewmanAuditError{"STREAM_AUDIT", "additional"})
			}
			if tc.missingCheck {
				r.Checks["allFourStreams"] = false
			}
			require.Equal(t, tc.want, ridNewmanGroupKillAccepted(r))
		})
	}
}
func TestRIDNewmanCommonStreamScanCounts(t *testing.T) {
	dir := t.TempDir()
	paths := []string{}
	for _, name := range []string{"outer-out", "outer-err", "inner-out", "inner-err"} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, []byte("safe\n"), 0600))
		paths = append(paths, p)
	}
	scan := rid02ScanStreams(paths, []string{"real-secret"})
	require.Empty(t, scan.Errors)
	require.Equal(t, 4, scan.Requested)
	require.Equal(t, 4, scan.Read)
	require.Equal(t, 4, scan.Metadata)
	require.Equal(t, 4, scan.JWTChecks)
	require.Equal(t, 4, scan.PEMChecks)
	require.Equal(t, 4, scan.SecretChecks)
	require.NoError(t, os.WriteFile(paths[3], []byte("real-secret"), 0600))
	scan = rid02ScanStreams(paths, []string{"real-secret"})
	require.NotEmpty(t, scan.Errors)
	require.Equal(t, 4, scan.Read)
}

func TestRIDNewmanTerminalIOClassification(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code string
	}{{"only-ENOENT-is-missing", os.ErrNotExist, "MISSING_NODE_TERMINAL"}, {"permission-is-unexpected", os.ErrPermission, "UNEXPECTED_NODE_TERMINAL_IO"}, {"other-IO-is-unexpected", errors.New("IO failure"), "UNEXPECTED_NODE_TERMINAL_IO"}} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.code, ridNewmanTerminalReadCode(tc.err)) })
	}
}
func TestRIDNewmanVerifiedToolRead(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tool")
	raw := []byte("frozen-tool")
	require.NoError(t, os.WriteFile(p, raw, 0600))
	digest := sha256.Sum256(raw)
	want := hex.EncodeToString(digest[:])
	t.Run("bounded-hash-success", func(t *testing.T) { require.True(t, ridNewmanVerifiedToolRead(p, want)) })
	t.Run("failed-read-not-completed", func(t *testing.T) { require.False(t, ridNewmanVerifiedToolRead(dir, want)) })
	t.Run("missing-read-not-completed", func(t *testing.T) { require.False(t, ridNewmanVerifiedToolRead(filepath.Join(dir, "missing"), want)) })
	t.Run("wrong-hash-not-completed", func(t *testing.T) { require.False(t, ridNewmanVerifiedToolRead(p, "wrong")) })
}
func TestRIDNewmanNodeAbsenceTransitions(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		statErr, startErr          error
		actual                     string
		cancelBefore, cancelInStat bool
		wantAbsent, wantErr        bool
	}{
		{"disappearance-between-reads", nil, os.ErrNotExist, "", false, false, false, false},
		{"confirmed-absent", os.ErrNotExist, nil, "", false, false, true, false},
		{"zombie-still-present", nil, nil, "old", false, false, false, false},
		{"start-reuse-rejected", nil, nil, "new", false, false, false, true},
		{"other-start-error-rejected", nil, os.ErrPermission, "", false, false, false, true},
		{"deadline-before-iteration", os.ErrNotExist, nil, "", true, false, false, true},
		{"deadline-before-success", os.ErrNotExist, nil, "", false, true, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.cancelBefore {
				cancel()
			}
			absent, err := ridNewmanAbsenceObservation(ctx, "old", func() error {
				if tc.cancelInStat {
					cancel()
				}
				return tc.statErr
			}, func() (string, error) { return tc.actual, tc.startErr })
			require.Equal(t, tc.wantAbsent, absent)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

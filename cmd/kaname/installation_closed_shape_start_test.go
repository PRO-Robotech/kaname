// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"fmt"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// RID09 ownership/FD5/preauth path with phase-exclusive input/evidence directories.
// Only directory names differ; no shared helper or production seam is modified.
func rid12Start(t *testing.T, f *installationNativeWorld, in rid09Input, phase string) *rid02OwnedChild {
	t.Helper()
	root := filepath.Join(f.session.Root, "rid12-input-"+phase)
	require.NoError(t, os.Mkdir(root, 0700))
	dir := filepath.Join(root, "delivery")
	_, err := in.Delivery.Write(dir, in.Reverse)
	require.NoError(t, err)
	body, err := yaml.Marshal(map[string]any{"manifests": map[string]any{"dir": dir, "required": true}, "moduleSeedInstaller": map[string]any{"credentialFile": f.creator.CredentialFile}})
	require.NoError(t, err)
	config := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(config, body, 0600))
	executable := rid06HashExecutable(t)
	child := startRIDInstallationChild(t, f, "rid12-startup-"+phase, ridWholeChildInput{ConfigPath: config, EvidenceDir: filepath.Join(f.session.Root, "rid12-startup-"+phase)}, f.session.Environment, ridWholeChildEnv, "TestRIDWholeDeliveryOwnedStartupChild", "3m")
	parentCG, err := os.ReadFile("/proc/self/cgroup")
	require.NoError(t, err)
	childCG, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", child.cmd.Process.Pid))
	require.NoError(t, err)
	require.True(t, bytes.Equal(parentCG, childCG))
	memory, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	require.NoError(t, err)
	require.Equal(t, "4294967296", strings.TrimSpace(string(memory)))
	swap, err := os.ReadFile("/sys/fs/cgroup/memory.swap.max")
	require.NoError(t, err)
	require.Equal(t, "0", strings.TrimSpace(string(swap)))
	t.Cleanup(func() { require.Equal(t, executable, rid06HashExecutable(t)) })
	rid08Write(t, child.dir, "full-startup-provenance", map[string]any{"instrumentedTestExecutableSHA256": executable, "baseProductionAppSHA256": f.session.BinarySHA256, "pid": child.cmd.Process.Pid, "starttime": child.start, "cgroup": string(childCG), "observerOnly": true, "repositoryReplaced": false, "readerReplaced": false, "reverse": in.Reverse, "M1SHA256": in.M1Digest, "M2SHA256": in.M2Digest})
	rid09ArmAndRelease(t, f, child)
	return child
}

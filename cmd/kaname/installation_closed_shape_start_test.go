// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// Путь RID09 владения/FD5/предварительной аутентификации с отдельными каталогами входов/доказательств для фаз.
// Отличаются только имена каталогов; общие помощники и производственные швы не меняются.
func rid12Start(t *testing.T, f *installationNativeWorld, in rid09Input, phase string) *rid02OwnedChild {
	t.Helper()
	root := filepath.Join(f.session.Root, "rid12-input-"+phase)
	require.NoError(t, os.Mkdir(root, 0700))
	dir := filepath.Join(root, "delivery")
	_, err := in.Delivery.Write(dir, in.Reverse)
	require.NoError(t, err)
	body, err := installruntime.FullStartupConfig(map[string]any{"manifests": map[string]any{"dir": dir, "required": true}, "moduleSeedInstaller": map[string]any{"credentialFile": f.creator.CredentialFile}}, f.writerPlan)
	require.NoError(t, err)
	config := filepath.Join(root, "config.yaml")
	require.NoError(t, os.WriteFile(config, body, 0600))
	ridRegistrationStartupProof(t, root, body, f.writerPlan)
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

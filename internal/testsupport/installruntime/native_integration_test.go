// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestNativeDelegationPublicMatrix запускается явно: все нативные процессы наследуют
// ограниченную cgroup вызывающего; endpoint Docker должен быть отдельно арендованным
// ретранслятором PostgreSQL на один контейнер. Потребитель не запускается, политика не меняется.
// Происхождение бинарных файлов/исходников задаётся независимо от этой ревизии фикстуры.
func TestNativeDelegationPublicMatrix(t *testing.T) {
	if os.Getenv("KANAME_NATIVE_ACCEPTANCE") != "1" {
		t.Skip("requires an explicitly leased native acceptance job")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 17*time.Minute)
	defer cancel()
	stand := PrepareNativeStand(t, ctx, "../../..", os.Getenv("KANAME_NATIVE_EVIDENCE"), true)
	root, evidence := stand.Root, stand.Evidence
	for _, key := range []string{"KANAME_NATIVE_BINARY", "KANAME_NATIVE_MIGRATOR"} {
		require.True(t, filepath.IsAbs(os.Getenv(key)), "%s must name an absolute prebuilt executable", key)
	}
	payload := exec.CommandContext(ctx, "python3", filepath.Join(root, "tests/authz-fixtures/native_runtime.py"),
		"--evidence", evidence, "--pg-port", stand.PGPort, "--binary", os.Getenv("KANAME_NATIVE_BINARY"),
		"--migrator", os.Getenv("KANAME_NATIVE_MIGRATOR"))
	payload.Dir = root
	// Даём полезной нагрузке собрать свои точные нативные группы процессов до эскалации Go.
	payload.Cancel = func() error { return payload.Process.Signal(syscall.SIGTERM) }
	payload.WaitDelay = 40 * time.Second
	log, err := os.OpenFile(filepath.Join(evidence, "payload.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	payload.Stdout, payload.Stderr = log, log
	err = payload.Run()
	require.NoError(t, log.Close())
	require.NoError(t, err, "native public matrix failed; private payload/step logs contain evidence")
}

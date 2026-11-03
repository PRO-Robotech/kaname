// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package installruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// TestNativeDelegationPublicMatrix is opt-in: all native processes inherit the
// caller's bounded cgroup; the Docker endpoint must be the separately leased,
// one-container PostgreSQL relay. It never starts a consumer or changes policy.
// Binary/source provenance is supplied independently from this fixture revision.
func TestNativeDelegationPublicMatrix(t *testing.T) {
	if os.Getenv("KANAME_NATIVE_ACCEPTANCE") != "1" {
		t.Skip("requires an explicitly leased native acceptance job")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Minute)
	defer cancel()
	root, err := filepath.Abs("../../..")
	require.NoError(t, err)
	evidence := os.Getenv("KANAME_NATIVE_EVIDENCE")
	require.True(t, filepath.IsAbs(evidence), "private absolute evidence directory is required")
	require.NoError(t, os.Mkdir(evidence, 0700), "each run needs a fresh evidence directory")
	for _, key := range []string{"KANAME_NATIVE_BINARY", "KANAME_NATIVE_MIGRATOR"} {
		require.True(t, filepath.IsAbs(os.Getenv(key)), "%s must name an absolute prebuilt executable", key)
	}
	// Generate exactly the existing stand PKI/configuration, before any container.
	prepare := exec.CommandContext(ctx, "bash", filepath.Join(root, ".github/scripts/stand-own.sh"), "prepare-native")
	var cleanEnvironment []string
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "KANAME_") {
			cleanEnvironment = append(cleanEnvironment, entry)
		}
	}
	prepare.Env = append(cleanEnvironment, "KANAME_STAND_REGISTRY_WORLD=1",
		"KANAME_STAND_PKI="+filepath.Join(evidence, "pki"),
		"KANAME_STAND_RUNDIR="+filepath.Join(evidence, "run"),
		"KANAME_STAND_BIN="+filepath.Join(evidence, "delivery"))
	prepared, err := prepare.CombinedOutput()
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "prepare.log"), prepared, 0600))
	require.NoError(t, err, "stand preparation failed; see private prepare.log")
	pg, err := postgres.Run(ctx, "postgres:16-alpine", postgres.WithDatabase("kaname"),
		postgres.WithUsername("kaname"), postgres.WithPassword("stand"), postgres.BasicWaitStrategies())
	require.NoError(t, err)
	// Register cleanup immediately; use a fresh deadline even after job failure.
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		err := pg.Terminate(cleanup)
		status := map[string]any{"containerId": pg.GetContainerID(), "terminateSucceeded": err == nil}
		raw, _ := json.Marshal(status)
		_ = os.WriteFile(filepath.Join(evidence, "pg-cleanup.json"), raw, 0600)
		if err != nil {
			t.Errorf("owned PostgreSQL termination: %v", err)
		}
	})
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	require.NoError(t, err)
	defer cli.Close()
	inspect, err := cli.ContainerInspect(ctx, pg.GetContainerID(), client.ContainerInspectOptions{})
	require.NoError(t, err)
	// Capture anonymous volume names while the exact owned container still exists.
	ownership, err := json.Marshal(map[string]any{"containerId": pg.GetContainerID(), "mounts": inspect.Container.Mounts})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(evidence, "pg-ownership.json"), ownership, 0600))
	for _, suffix := range []string{"crt", "key"} {
		material, err := os.ReadFile(filepath.Join(evidence, "pki", "pg."+suffix))
		require.NoError(t, err)
		// No secret in argv, Docker environment, log, host mount or socket.
		command := "umask 077; cat > /var/lib/postgresql/server." + suffix + "; chown postgres:postgres /var/lib/postgresql/server." + suffix
		require.NoError(t, ownedExec(ctx, cli, pg.GetContainerID(), []string{"sh", "-ec", command}, material))
	}
	for _, sql := range []string{
		"ALTER SYSTEM SET ssl_cert_file = '/var/lib/postgresql/server.crt'",
		"ALTER SYSTEM SET ssl_key_file = '/var/lib/postgresql/server.key'",
		"ALTER SYSTEM SET ssl = 'on'", "SELECT pg_reload_conf()",
	} {
		require.NoError(t, ownedExec(ctx, cli, pg.GetContainerID(), []string{"psql", "-U", "kaname", "-d", "kaname", "-v", "ON_ERROR_STOP=1", "-c", sql}, nil))
	}
	port, err := pg.MappedPort(ctx, "5432/tcp")
	require.NoError(t, err)
	payload := exec.CommandContext(ctx, "python3", filepath.Join(root, "tests/authz-fixtures/native_runtime.py"),
		"--evidence", evidence, "--pg-port", port.Port(), "--binary", os.Getenv("KANAME_NATIVE_BINARY"),
		"--migrator", os.Getenv("KANAME_NATIVE_MIGRATOR"))
	payload.Dir = root
	// Let the payload reap its exact native process groups before Go escalates.
	payload.Cancel = func() error { return payload.Process.Signal(syscall.SIGTERM) }
	payload.WaitDelay = 40 * time.Second
	log, err := os.OpenFile(filepath.Join(evidence, "payload.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	require.NoError(t, err)
	payload.Stdout, payload.Stderr = log, log
	err = payload.Run()
	require.NoError(t, log.Close())
	require.NoError(t, err, "native public matrix failed; private payload/step logs contain evidence")
}

// ownedExec uses the existing Docker SDK hijacked transport accepted by the
// reviewed relay. Draining to EOF BEFORE inspect prevents a false exit-code zero
// from an exec which has not started yet. Only the newly created owned ID enters.
func ownedExec(ctx context.Context, cli *client.Client, id string, command []string, stdin []byte) error {
	created, err := cli.ExecCreate(ctx, id, client.ExecCreateOptions{Cmd: command,
		AttachStdin: len(stdin) > 0, AttachStdout: true, AttachStderr: true, Privileged: false})
	if err != nil {
		return err
	}
	attached, err := cli.ExecAttach(ctx, created.ID, client.ExecAttachOptions{})
	if err != nil {
		return err
	}
	defer attached.Close()
	if len(stdin) > 0 {
		if _, err := io.Copy(attached.Conn, bytes.NewReader(stdin)); err != nil {
			return err
		}
		if err := attached.CloseWrite(); err != nil {
			return err
		}
	}
	if _, err := io.Copy(io.Discard, attached.Reader); err != nil {
		return err
	}
	result, err := cli.ExecInspect(ctx, created.ID, client.ExecInspectOptions{})
	if err != nil {
		return err
	}
	if result.Running || result.ExitCode != 0 {
		return fmt.Errorf("owned exec did not finish successfully: running=%v code=%d", result.Running, result.ExitCode)
	}
	return nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type rid02OwnedChild struct {
	cmd             *exec.Cmd
	start           string
	argv            []byte
	control         *os.File
	secretInventory *os.File
	events          chan rid02ChildEvent
	decodeError     chan error
	exited          chan struct{}
	waitErr         error
	dir             string
	world           *installationNativeWorld
	auditOnce       sync.Once
	seenEvent       bool
}

func rid02ProcessStart(pid int) (string, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	_, rest, ok := strings.Cut(string(raw), ") ")
	if !ok {
		return "", fmt.Errorf("invalid owned process stat")
	}
	fields := strings.Fields(rest)
	if len(fields) < 20 {
		return "", fmt.Errorf("incomplete owned process stat")
	}
	return fields[19], nil
}
func startRID02Child(t *testing.T, f *installationNativeWorld, label string, input rid02ChildInput) *rid02OwnedChild {
	return startRIDInstallationChild(t, f, label, input, f.session.Environment, rid02ChildInputEnv, "TestRID02OwnedInstallationChild", "12m")
}

// The same ownership/FD/reap protocol serves the full-startup instrumented child.
// Entry selection exists only in test source, never in production config or CLI.
func startRIDInstallationChild(t *testing.T, f *installationNativeWorld, label string, input any, environment []string, inputEnv, entry, timeout string) *rid02OwnedChild {
	t.Helper()
	dir := filepath.Join(f.session.Root, label)
	require.NoError(t, os.Mkdir(dir, 0700))
	path := filepath.Join(dir, "input.json")
	raw, err := json.Marshal(input)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0600))

	// Each acquired FD has cleanup registered before any fatal assertion.
	ownFD := func(f *os.File) {
		if f != nil {
			t.Cleanup(func() { _ = f.Close() })
		}
	}
	// This file is outside evidence and has no pathname before any child can
	// receive secrets. Parent/child death closes the only remaining references.
	secretInventory, err := os.CreateTemp("/tmp", "kaname-rid02-secret-*")
	ownFD(secretInventory)
	if err != nil {
		t.Fatal("private anonymous inventory allocation failed")
	}
	if os.Remove(secretInventory.Name()) != nil {
		t.Fatal("private inventory unlink failed before child start")
	}
	info, err := secretInventory.Stat()
	if err != nil {
		t.Fatal("private anonymous inventory stat failed")
	}
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600, "anonymous inventory must be private0600 regular file")
	stat, ok := info.Sys().(*syscall.Stat_t)
	require.True(t, ok && stat.Nlink == 0, "inventory must be unlinked before child start")
	er, ew, err := os.Pipe()
	ownFD(er)
	ownFD(ew)
	require.NoError(t, err)
	cr, cw, err := os.Pipe()
	ownFD(cr)
	ownFD(cw)
	require.NoError(t, err)
	stdout, err := os.OpenFile(filepath.Join(dir, "stdout"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	ownFD(stdout)
	require.NoError(t, err)
	stderr, err := os.OpenFile(filepath.Join(dir, "stderr"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	ownFD(stderr)
	require.NoError(t, err)
	cmd := exec.Command(os.Args[0], "-test.run=^"+entry+"$", "-test.timeout="+timeout, "-test.v")
	cmd.Env = append(append([]string{}, environment...), inputEnv+"="+path)
	cmd.ExtraFiles = []*os.File{ew, cr, secretInventory} // FD3 events, FD4 control, FD5 anonymous secret inventory.
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	c := &rid02OwnedChild{cmd: cmd, control: cw, secretInventory: secretInventory, events: make(chan rid02ChildEvent, 4), decodeError: make(chan error, 1), exited: make(chan struct{}), dir: dir, world: f}
	err = cmd.Start()
	if err == nil {
		// No assertion or ownership read may precede Wait/cleanup installation.
		go func() { c.waitErr = cmd.Wait(); close(c.exited) }()
		t.Cleanup(func() {
			select {
			case <-c.exited:
			default:
				// Before identity capture completes, os.Process is the Start-owned handle;
				// Kill uses that handle and never an unverified numeric process group.
				var killErr error
				if c.start == "" || len(c.argv) == 0 {
					killErr = cmd.Process.Kill()
				} else {
					killErr = c.kill()
				}
				if killErr != nil && !errors.Is(killErr, os.ErrProcessDone) && !errors.Is(killErr, os.ErrNotExist) && !errors.Is(killErr, syscall.ESRCH) {
					t.Errorf("owned child cleanup failed (type %T)", killErr)
				}
			}
			select {
			case <-c.exited:
				c.afterReap(t)
			case <-time.After(10 * time.Second):
				t.Error("owned child survives cleanup; complete-stream audit unavailable")
			}
		})
	}
	require.NoError(t, err)
	require.NoError(t, ew.Close())
	require.NoError(t, cr.Close())
	require.NoError(t, stdout.Close())
	require.NoError(t, stderr.Close())
	c.start, err = rid02ProcessStart(cmd.Process.Pid)
	require.NoError(t, err)
	c.argv, err = c.establishArgv(2 * time.Second)
	require.NoError(t, err)
	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	require.NoError(t, err)
	require.Equal(t, cmd.Process.Pid, pgid)
	go func() {
		defer er.Close()
		d := json.NewDecoder(er)
		for {
			var event rid02ChildEvent
			if err := d.Decode(&event); err != nil {
				c.decodeError <- err
				return
			}
			c.events <- event // At most boundary + worker-finished; buffer holds four.
		}
	}()
	ownership, err := json.Marshal(map[string]any{"pid": cmd.Process.Pid, "starttime": c.start, "argv": strings.Split(strings.TrimRight(string(c.argv), "\x00"), "\x00"), "group": pgid})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "ownership.json"), ownership, 0600))
	return c
}

// Establish the exact launched argv before retaining a successful identity.
// A successful early proc read can transiently contain no bytes. Only that
// empty snapshot is retryable; unexpected identity, exit or timeout is FAIL.
// Until this succeeds, cleanup retains the Start-owned os.Process handle.
func (c *rid02OwnedChild) establishArgv(limit time.Duration) ([]byte, error) {
	pid := c.cmd.Process.Pid
	expected := []byte(strings.Join(c.cmd.Args, "\x00") + "\x00")
	deadline := time.NewTimer(limit)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-c.exited:
			return nil, fmt.Errorf("owned child exited before identity establishment")
		default:
		}
		rawStat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return nil, err
		}
		_, rest, ok := strings.Cut(string(rawStat), ") ")
		fields := strings.Fields(rest)
		if !ok || len(fields) < 20 || fields[19] != c.start || fields[0] == "Z" || fields[0] == "X" || fields[0] == "x" {
			return nil, fmt.Errorf("owned child is not live with its captured starttime")
		}
		argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
		if err != nil {
			return nil, err
		}
		pgid, err := syscall.Getpgid(pid)
		if err != nil {
			return nil, err
		}
		if pgid != pid {
			return nil, fmt.Errorf("owned child process group changed during identity establishment")
		}
		if len(argv) != 0 {
			if !bytes.Equal(argv, expected) {
				return nil, fmt.Errorf("owned child argv differs from its exact launched command")
			}
			start, err := rid02ProcessStart(pid)
			if err != nil || start != c.start {
				return nil, fmt.Errorf("owned child starttime changed during identity establishment")
			}
			select {
			case <-c.exited:
				return nil, fmt.Errorf("owned child exited during identity establishment")
			default:
				return argv, nil
			}
		}
		select {
		case <-c.exited:
			return nil, fmt.Errorf("owned child exited before identity establishment")
		case <-deadline.C:
			return nil, fmt.Errorf("owned child exact argv was not established before deadline")
		case <-tick.C:
		}
	}
}
func (c *rid02OwnedChild) kill() error {
	start, err := rid02ProcessStart(c.cmd.Process.Pid)
	if err != nil {
		return err
	}
	if start != c.start {
		return fmt.Errorf("owned child starttime changed")
	}
	argv, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", c.cmd.Process.Pid))
	if err != nil {
		return err
	}
	if string(argv) != string(c.argv) {
		return fmt.Errorf("owned child argv changed")
	}
	pgid, err := syscall.Getpgid(c.cmd.Process.Pid)
	if err != nil {
		return err
	}
	if pgid != c.cmd.Process.Pid {
		return fmt.Errorf("owned process group changed")
	}
	return syscall.Kill(-pgid, syscall.SIGKILL)
}
func (c *rid02OwnedChild) await(t *testing.T, ctx context.Context, stage string) rid02ChildEvent {
	t.Helper()
	select {
	case e := <-c.events:
		c.seenEvent = true
		require.Equal(t, stage, e.Stage)
		require.Equal(t, c.cmd.Process.Pid, e.PID)
		require.NotEmpty(t, e.Operation)
		return e
	case err := <-c.decodeError:
		// The decoder may observe EOF immediately after the final buffered event.
		select {
		case e := <-c.events:
			c.seenEvent = true
			require.Equal(t, stage, e.Stage)
			require.Equal(t, c.cmd.Process.Pid, e.PID)
			require.NotEmpty(t, e.Operation)
			return e
		default:
		}
		t.Fatalf("child IPC failed before %s: %v; private stderr retained", stage, err)
	case <-ctx.Done():
		t.Fatalf("child boundary %s: %v", stage, ctx.Err())
	}
	return rid02ChildEvent{}
}
func (c *rid02OwnedChild) release(t *testing.T, action string) {
	t.Helper()
	require.NoError(t, json.NewEncoder(c.control).Encode(action))
}
func (c *rid02OwnedChild) wait(t *testing.T, killed bool) {
	t.Helper()
	select {
	case <-c.exited:
	case <-time.After(15 * time.Second):
		t.Fatal("owned child did not terminate")
	}
	c.afterReap(t)
	if !killed {
		require.NoError(t, c.waitErr)
		return
	}
	var exit *exec.ExitError
	require.ErrorAs(t, c.waitErr, &exit)
	status, ok := exit.Sys().(syscall.WaitStatus)
	require.True(t, ok)
	require.True(t, status.Signaled())
	require.Equal(t, syscall.SIGKILL, status.Signal())
}

func (c *rid02OwnedChild) terminalAttempts(t *testing.T) []rid02TerminalAttempt {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(c.dir, "terminal-attempts.json"))
	require.NoError(t, err)
	var attempts []rid02TerminalAttempt
	require.NoError(t, json.Unmarshal(raw, &attempts))
	return attempts
}

func (c *rid02OwnedChild) afterReap(t *testing.T) {
	t.Helper()
	c.auditOnce.Do(func() {
		// These absence assertions run after the single Wait on every exit path.
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", c.cmd.Process.Pid)); !errors.Is(err, os.ErrNotExist) {
			t.Error("owned child PID not proven absent after reap")
		}
		if err := syscall.Kill(-c.cmd.Process.Pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Error("owned child process group not proven absent after reap")
		}
		secrets := rid02WorldSecretMaterial(t, c.world)
		// Reap precedes Seek: child and parent share this open file description.
		// Retain each successfully decoded append-only record even if a killed
		// child left a final incomplete write; malformed inventory still fails.
		records, issuedTokens := 0, 0
		if _, err := c.secretInventory.Seek(0, io.SeekStart); err != nil {
			t.Error("anonymous child secret inventory seek failed")
		} else {
			decoder := json.NewDecoder(c.secretInventory)
			for {
				var issued []string
				err := decoder.Decode(&issued)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Error("anonymous child secret inventory is invalid")
					break
				}
				records++
				if len(issued) != 2 {
					t.Error("anonymous child secret record has invalid shape")
				}
				if len(issued) == 2 && issued[1] != "" {
					issuedTokens++
				}
				secrets = append(secrets, issued...)
			}
		}
		if c.seenEvent && (records == 0 || issuedTokens == 0) {
			t.Error("authenticated child has no actual issued-token inventory")
		}
		// An early startup failure can precede issuance. Neither that failure nor
		// malformed inventory skips both complete streams and structural checks.
		rid02CheckStreams(t, []string{filepath.Join(c.dir, "stdout"), filepath.Join(c.dir, "stderr")}, secrets)
		t.Logf("RID02 anonymous inventory audited: records=%d issuedTokens=%d streams=2", records, issuedTokens)
	})
}

func rid02WorldSecretMaterial(t *testing.T, f *installationNativeWorld) []string {
	t.Helper()
	secrets := append([]string{}, f.secrets...)
	secrets = append(secrets, f.creator.SecretMaterial()...)
	raw, err := os.ReadFile(f.creator.CredentialFile)
	if err != nil {
		t.Error("standing credential unavailable for complete-stream audit")
	} else {
		secrets = append(secrets, string(raw))
	}
	return secrets
}

// Real issued child tokens are captured privately. Native serve's internal
// issuance is deliberately opaque: in addition to all known real secret bytes,
// reject any compact signed JWT and any PEM private-key envelope in its output.
var rid02JWTInStream = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)
var rid02PEMInStream = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----`)

func rid02CheckStreams(t *testing.T, paths []string, secrets []string) {
	t.Helper()
	for stream, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("stream %d metadata unavailable", stream)
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Errorf("stream %d is not a private regular 0600 file", stream)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("stream %d unreadable", stream)
			continue
		}
		for material, secret := range secrets {
			if secret == "" {
				continue
			}
			encoded, _ := json.Marshal(secret)
			if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, encoded[1:len(encoded)-1]) {
				t.Errorf("stream %d contains secret material index %d", stream, material)
			}
		}
		if rid02JWTInStream.Match(raw) {
			t.Errorf("stream %d contains compact JWT material", stream)
		}
		if rid02PEMInStream.Match(raw) {
			t.Errorf("stream %d contains private PEM material", stream)
		}
	}
}

//go:build linux

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const emptyPlan = `{"registration-account-writers":{"assignments":[],"disabled":[],"retire-cluster-writer":false}}`
const assignedPlan = `{"registration-account-writers":{"assignments":[{"assignment_id":"stand-registry-acc11111111111111111","account_id":"acc11111111111111111","module":"registry"}],"disabled":[],"retire-cluster-writer":false}}`

// The test executable is the real subprocess on both sides of the activation
// gate. No PG, Docker, shell signal, or process-name lookup participates.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__activate" {
		os.Exit(activate())
	}
	if len(os.Args) > 1 && os.Args[1] == "serve" && os.Getenv("OWNER_FIXTURE_ROOT") != "" {
		os.Exit(fixtureService())
	}
	os.Exit(m.Run())
}
func fixtureService() int {
	root := os.Getenv("OWNER_FIXTURE_ROOT")
	phase := "phase1"
	if strings.HasSuffix(os.Getenv("KANAME_CONFIG_PATH"), ".phase0.json") {
		phase = "phase0"
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	body, err := os.ReadFile(os.Getenv("KANAME_CONFIG_PATH"))
	if err != nil {
		return 91
	}
	if err = exclusive(filepath.Join(root, phase+".config"), body); err != nil {
		return 92
	}
	if err = exclusive(filepath.Join(root, phase+".started"), []byte(strconv.Itoa(os.Getpid()))); err != nil {
		return 93
	}
	mode := os.Getenv("OWNER_FIXTURE_MODE")
	if strings.HasPrefix(mode, phase+"-exit-before-") {
		code, _ := strconv.Atoi(strings.TrimPrefix(mode, phase+"-exit-before-"))
		return code
	}
	var addresses []string
	if json.Unmarshal([]byte(os.Getenv("OWNER_FIXTURE_ADDRESSES")), &addresses) != nil {
		return 94
	}
	var listeners []net.Listener
	defer func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	}()
	for index, address := range addresses {
		if phase == "phase1" && strings.Contains(mode, "missing-eight") && index == 7 {
			continue
		}
		listener, err := net.Listen("tcp", address)
		if err != nil {
			return 95
		}
		listeners = append(listeners, listener)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}
	if err = exclusive(filepath.Join(root, phase+".listening"), []byte("ready")); err != nil {
		return 96
	}
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case sig := <-signals:
			if err = os.WriteFile(filepath.Join(root, phase+".signal"), []byte(sig.String()), 0600); err != nil {
				return 97
			}
			if strings.Contains(mode, phase+"-ignore") {
				continue
			}
			if strings.Contains(mode, phase+"-term-seven") {
				return 7
			}
			return 0
		case <-tick.C:
			if body, err := os.ReadFile(filepath.Join(root, phase+".exit")); err == nil {
				code, err := strconv.Atoi(string(body))
				if err != nil {
					return 98
				}
				return code
			}
		}
	}
}

type harness struct {
	t                            *testing.T
	root, binary, config, socket string
	signals                      chan os.Signal
	done                         chan int
	children                     []*child
	finished                     bool
	code                         int
}

func fixtureBinary(t *testing.T, root string) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(root, "kaname")
	if err = os.Link(self, binary); err != nil {
		// GOTMPDIR and the fixture directory may be on different filesystems.
		body, readErr := os.ReadFile(self)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if err = os.WriteFile(binary, body, 0700); err != nil {
			t.Fatal(err)
		}
	}
	return binary
}
func fixtureAddresses(t *testing.T) []string {
	t.Helper()
	var listeners []net.Listener
	var addresses []string
	for index := 0; index < 8; index++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		addresses = append(addresses, listener.Addr().String())
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	return addresses
}

// A race-instrumented Go executable normally sleeps for 1s on exit0. That
// detector delay is not service shutdown and exceeds this fixture's 300ms
// graceful deadline. Override only the child environment before runtime init;
// the parent, race instrumentation/reporting and lifecycle budgets stay intact.
func fixtureRaceEnvironment(environment []string) []string {
	childEnvironment := make([]string, 0, len(environment)+1)
	var options string
	for _, entry := range environment {
		if strings.HasPrefix(entry, "GORACE=") {
			options = strings.TrimPrefix(entry, "GORACE=")
			continue
		}
		childEnvironment = append(childEnvironment, entry)
	}
	// The final option overrides an inherited exit delay, retaining all other
	// race options, including reporting, halt_on_error and exitcode.
	childEnvironment = append(childEnvironment, "GORACE="+strings.TrimSpace(options+" atexit_sleep_ms=0"))
	return childEnvironment
}
func fixtureStartProcess(path string, args []string, attr *os.ProcAttr) (*os.Process, error) {
	childAttr := *attr
	childAttr.Env = fixtureRaceEnvironment(attr.Env)
	return os.StartProcess(path, args, &childAttr)
}
func fixtureLaunch(binary, config string) (*child, error) {
	return launchWith(binary, config, launchOps{pidfdCapability, fixtureStartProcess, 5 * time.Second})
}

func newHarness(t *testing.T, mode string, change func(*ownerOps)) *harness {
	t.Helper()
	root, err := os.MkdirTemp("", "rwo-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	h := &harness{t: t, root: root, binary: filepath.Join(root, "kaname"), config: filepath.Join(root, "registration-writers.json"), socket: filepath.Join(root, "registration-owner.sock"), signals: make(chan os.Signal, 4), done: make(chan int, 1)}
	fixtureBinary(t, root)
	if err = os.WriteFile(h.config, []byte(emptyPlan), 0600); err != nil {
		t.Fatal(err)
	}
	ops := defaults()
	ops.launch = fixtureLaunch
	ops.addresses = fixtureAddresses(t)
	ops.stop = stopPolicy{send, 300 * time.Millisecond, 300 * time.Millisecond}
	if change != nil {
		change(&ops)
	}
	start := ops.launch
	ops.launch = func(binary, config string) (*child, error) {
		c, err := start(binary, config)
		if c != nil {
			h.children = append(h.children, c)
		}
		return c, err
	}
	raw, _ := json.Marshal(ops.addresses)
	t.Setenv("OWNER_FIXTURE_ROOT", root)
	t.Setenv("OWNER_FIXTURE_MODE", mode)
	t.Setenv("OWNER_FIXTURE_ADDRESSES", string(raw))
	go func() { h.done <- serveWith(h.binary, h.config, h.socket, 1, h.signals, ops) }()
	t.Cleanup(func() {
		if !h.finished {
			h.signals <- syscall.SIGTERM
			h.finish()
		}
		for _, c := range h.children {
			if !c.reaped || !c.closed {
				t.Errorf("owned child leaked: reaped=%v closed=%v", c.reaped, c.closed)
			}
		}
	})
	h.waitFile("phase0.started")
	if !strings.HasPrefix(mode, "phase0-exit-before-") {
		h.waitFile("phase0.listening")
	}
	return h
}
func (h *harness) waitFile(name string) []byte {
	h.t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if body, err := os.ReadFile(filepath.Join(h.root, name)); err == nil {
			return body
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatalf("fixture did not produce %s", name)
	return nil
}
func (h *harness) finish() int {
	h.t.Helper()
	if !h.finished {
		select {
		case h.code = <-h.done:
			h.finished = true
		case <-time.After(8 * time.Second):
			h.t.Fatal("owner exceeded bounded finalization")
		}
	}
	return h.code
}
func (h *harness) assignment() string {
	h.t.Helper()
	if err := os.WriteFile(h.config, []byte(assignedPlan), 0600); err != nil {
		h.t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(assignedPlan))
	return hex.EncodeToString(digest[:])
}
func (h *harness) current() state {
	h.t.Helper()
	raw, err := os.ReadFile(h.socket + ".state")
	if err != nil {
		h.t.Fatal(err)
	}
	var s state
	if err = json.Unmarshal(raw, &s); err != nil {
		h.t.Fatal(err)
	}
	return s
}
func (h *harness) exchange(r request) (response, error) {
	conn, err := net.DialTimeout("unix", h.socket, time.Second)
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err = json.NewEncoder(conn).Encode(r); err != nil {
		return response{}, err
	}
	var answer response
	err = json.NewDecoder(conn).Decode(&answer)
	return answer, err
}
func (h *harness) noSignal() {
	h.t.Helper()
	if _, err := os.Stat(filepath.Join(h.root, "phase0.signal")); !os.IsNotExist(err) {
		h.t.Fatalf("refusal reached service signal: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.root, "phase1.started")); !os.IsNotExist(err) {
		h.t.Fatalf("refusal started assigned service: %v", err)
	}
}
func (h *harness) assertChildren(count int) {
	h.t.Helper()
	if len(h.children) != count {
		h.t.Fatalf("launch count=%d want=%d", len(h.children), count)
	}
	for _, c := range h.children {
		if !c.reaped || !c.closed {
			h.t.Fatalf("child not reaped/closed: %+v", c)
		}
	}
}

func TestProtocolFiniteTransitionAndRequestIsolation(t *testing.T) {
	h := newHarness(t, "", nil)
	h.waitFile("phase0.listening")
	if got := string(h.waitFile("phase0.config")); got != emptyPlan {
		t.Fatalf("phase0=%s", got)
	}
	sha := h.assignment()
	s := h.current()
	for _, r := range []request{
		{Instance: "foreign", Generation: 1, ConfigSHA256: sha},
		{Instance: s.Instance, Generation: 2, ConfigSHA256: sha},
		{Instance: s.Instance, Generation: 1, ConfigSHA256: strings.Repeat("0", 64)},
		{Instance: s.Instance, Generation: 1, ConfigSHA256: ""},
	} {
		answer, err := h.exchange(r)
		if err != nil || answer.Error == "" || answer.Generation == 2 {
			t.Fatalf("unsafe refusal: %+v %v", answer, err)
		}
		h.noSignal()
	}
	if err := restart(h.socket, sha); err != nil {
		t.Fatal(err)
	}
	if got := string(h.waitFile("phase1.config")); got != assignedPlan {
		t.Fatalf("phase1=%s", got)
	}
	if err := restart(h.socket, sha); err == nil {
		t.Fatal("second transition accepted")
	}
	h.signals <- syscall.SIGTERM
	if code := h.finish(); code != 0 {
		t.Fatalf("graceful owner code=%d", code)
	}
	h.assertChildren(2)
}
func TestProtocolSnapshotFailurePrecedesTERM(t *testing.T) {
	for _, kind := range []string{"write-failure", "existing-snapshot"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, "", func(ops *ownerOps) {
				if kind == "write-failure" {
					ops.snapshot = func(path string, body []byte) error {
						if strings.HasSuffix(path, ".phase1.json") {
							return errors.New("injected snapshot sync failure")
						}
						return exclusive(path, body)
					}
				}
			})
			h.waitFile("phase0.listening")
			if kind == "existing-snapshot" {
				if err := exclusive(h.config+".phase1.json", []byte("foreign evidence")); err != nil {
					t.Fatal(err)
				}
			}
			if err := restart(h.socket, h.assignment()); err == nil {
				t.Fatal("snapshot failure accepted")
			}
			h.noSignal()
			h.signals <- syscall.SIGTERM
			if code := h.finish(); code != 0 {
				t.Fatalf("cleanup code=%d", code)
			}
			h.assertChildren(1)
			if kind == "existing-snapshot" {
				body, err := os.ReadFile(h.config + ".phase1.json")
				if err != nil || string(body) != "foreign evidence" {
					t.Fatalf("snapshot clobbered: %q %v", body, err)
				}
			}
		})
	}
}
func TestProtocolAllEightRequiredAndCleanupReported(t *testing.T) {
	h := newHarness(t, "missing-eight phase1-ignore", nil)
	err := restart(h.socket, h.assignment())
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "forced cleanup") {
		t.Fatalf("missing listener/cleanup failure hidden: %v", err)
	}
	if code := h.finish(); code == 0 {
		t.Fatal("failed readiness green")
	}
	h.assertChildren(2)
}
func TestProtocolSignalsDuringTransition(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			var h *harness
			h = newHarness(t, "", func(ops *ownerOps) {
				original := ops.stop.send
				ops.stop.send = func(fd int, s syscall.Signal) error {
					if s == syscall.SIGTERM {
						h.signals <- sig
					}
					return original(fd, s)
				}
			})
			if err := restart(h.socket, h.assignment()); err == nil {
				t.Fatal("ACK after transition cancellation")
			}
			if code := h.finish(); code != 0 {
				t.Fatalf("clean cancellation code=%d", code)
			}
			h.assertChildren(1)
		})
	}
}
func TestProtocolExitCodesBeforeAndAfterACK(t *testing.T) {
	for _, phase := range []string{"phase0", "phase1"} {
		for _, code := range []int{0, 7} {
			t.Run(fmt.Sprintf("%s-before-%d", phase, code), func(t *testing.T) {
				h := newHarness(t, fmt.Sprintf("%s-exit-before-%d", phase, code), nil)
				if phase == "phase1" {
					if err := restart(h.socket, h.assignment()); err == nil {
						t.Fatal("ACK for exited child")
					}
				}
				want := code
				if want == 0 {
					want = 1
				}
				if got := h.finish(); got != want {
					t.Fatalf("exit=%d want=%d", got, want)
				}
				count := 1
				if phase == "phase1" {
					count = 2
				}
				h.assertChildren(count)
			})
		}
	}
	for _, code := range []int{0, 7} {
		t.Run(fmt.Sprintf("after-%d", code), func(t *testing.T) {
			h := newHarness(t, "", nil)
			if err := restart(h.socket, h.assignment()); err != nil {
				t.Fatal(err)
			}
			// kaname#1125: дочерний процесс не должен увидеть созданный, но ещё
			// пустой файл команды. Публикуем целое значение только после записи.
			exitPath := filepath.Join(h.root, "phase1.exit")
			pendingPath := exitPath + ".pending"
			if err := exclusive(pendingPath, []byte(strconv.Itoa(code))); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(pendingPath, exitPath); err != nil {
				t.Fatal(err)
			}
			want := code
			if want == 0 {
				want = 1
			}
			if got := h.finish(); got != want {
				t.Fatalf("post-ACK exit=%d want=%d", got, want)
			}
			h.assertChildren(2)
		})
	}
}
func TestProtocolPeerAndPrivateState(t *testing.T) {
	t.Run("foreign-kernel-peer", func(t *testing.T) {
		h := newHarness(t, "", func(ops *ownerOps) {
			// Read real SO_PEERCRED, compare with a different expected owner. This
			// exercises the denial on an actual Unix connection without setuid.
			ops.peer = func(conn net.Conn) error { return ownedPeerUID(conn, int64(os.Getuid()+1)) }
		})
		if err := restart(h.socket, h.assignment()); err == nil {
			t.Fatal("foreign peer accepted")
		}
		h.noSignal()
		h.signals <- syscall.SIGTERM
		if code := h.finish(); code != 0 {
			t.Fatalf("code=%d", code)
		}
	})
	for _, kind := range []string{"state-mode", "state-symlink", "stale-state", "socket-mode", "foreign-socket-path"} {
		t.Run(kind, func(t *testing.T) {
			h := newHarness(t, "", nil)
			sha := h.assignment()
			statePath := h.socket + ".state"
			switch kind {
			case "state-mode":
				if err := os.Chmod(statePath, 0600); err != nil {
					t.Fatal(err)
				}
			case "state-symlink":
				if err := os.Rename(statePath, statePath+".old"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(statePath+".old", statePath); err != nil {
					t.Fatal(err)
				}
			case "stale-state":
				s := h.current()
				s.Instance = "stale"
				raw, _ := json.Marshal(s)
				if err := os.Remove(statePath); err != nil {
					t.Fatal(err)
				}
				if err := exclusive(statePath, raw); err != nil {
					t.Fatal(err)
				}
			case "socket-mode":
				if err := os.Chmod(h.socket, 0666); err != nil {
					t.Fatal(err)
				}
			case "foreign-socket-path":
				if err := os.Remove(h.socket); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(h.socket, []byte("foreign replacement"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := restart(h.socket, sha); err == nil {
				t.Fatal("unsafe control state accepted")
			}
			h.noSignal()
			h.signals <- syscall.SIGTERM
			if code := h.finish(); code != 0 {
				t.Fatalf("code=%d", code)
			}
			if kind == "foreign-socket-path" {
				body, err := os.ReadFile(h.socket)
				if err != nil || string(body) != "foreign replacement" {
					t.Fatalf("foreign path removed: %q %v", body, err)
				}
			}
		})
	}
}

func TestActivationMissingPidfdNeverExecutesService(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OWNER_FIXTURE_ROOT", root)
	t.Setenv("OWNER_FIXTURE_MODE", "")
	raw, _ := json.Marshal(fixtureAddresses(t))
	t.Setenv("OWNER_FIXTURE_ADDRESSES", string(raw))
	config := filepath.Join(root, "registration-writers.json.phase0.json")
	if err := os.WriteFile(config, []byte(emptyPlan), 0600); err != nil {
		t.Fatal(err)
	}
	binary := fixtureBinary(t, root)
	var startedPID int
	_, err := launchWith(binary, config, launchOps{
		capability: pidfdCapability,
		lease:      5 * time.Second,
		start: func(path string, args []string, attr *os.ProcAttr) (*os.Process, error) {
			process, err := fixtureStartProcess(path, args, attr)
			if err == nil {
				startedPID = process.Pid
				if *attr.Sys.PidFD >= 0 {
					_ = unix.Close(*attr.Sys.PidFD)
				}
				*attr.Sys.PidFD = -1
			}
			return process, err
		},
	})
	if err == nil || !strings.Contains(err.Error(), "pidfd") {
		t.Fatalf("missing pidfd accepted: %v", err)
	}
	if startedPID == 0 {
		t.Fatal("did not exercise successful StartProcess")
	}
	var status syscall.WaitStatus
	if _, err = syscall.Wait4(startedPID, &status, syscall.WNOHANG, nil); !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("gate not reaped: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, "phase0.started")); !os.IsNotExist(err) {
		t.Fatalf("service activated: %v", err)
	}
}
func TestActivationCapabilityFailurePreventsLaunch(t *testing.T) {
	starts := 0
	_, err := launchWith("/unused/kaname", "/unused/config", launchOps{
		capability: func() error { return syscall.ENOSYS },
		start: func(string, []string, *os.ProcAttr) (*os.Process, error) {
			starts++
			return nil, errors.New("unexpected start")
		},
		lease: time.Second,
	})
	if !errors.Is(err, syscall.ENOSYS) || starts != 0 {
		t.Fatalf("capability refusal: starts=%d err=%v", starts, err)
	}
}
func TestBoundedForceAndReapFailuresRemainFailures(t *testing.T) {
	// Direct lifecycle exercise with a real signal-ignoring child. A duplicate
	// pidfd is held only by the test so injected SIGKILL failure cannot leak it.
	for _, killFails := range []bool{false, true} {
		t.Run(fmt.Sprintf("kill-fails-%v", killFails), func(t *testing.T) {
			h := newHarness(t, "phase0-ignore", nil)
			h.waitFile("phase0.listening")
			// Stop the owner through its actual control protocol, injecting only the
			// kernel signal operation. Construct a separate owner for this injection.
			h.signals <- syscall.SIGTERM
			if code := h.finish(); code == 0 {
				t.Fatal("forced termination was green")
			}
			h.assertChildren(1)
			root := t.TempDir()
			t.Setenv("OWNER_FIXTURE_ROOT", root)
			t.Setenv("OWNER_FIXTURE_MODE", "phase0-ignore")
			addresses, _ := json.Marshal(fixtureAddresses(t))
			t.Setenv("OWNER_FIXTURE_ADDRESSES", string(addresses))
			config := filepath.Join(root, "registration-writers.json.phase0.json")
			if err := os.WriteFile(config, []byte(emptyPlan), 0600); err != nil {
				t.Fatal(err)
			}
			c, err := fixtureLaunch(h.binary, config)
			if err != nil {
				t.Fatal(err)
			}
			defer finalize(c, syscall.SIGTERM, stopPolicy{send, 300 * time.Millisecond, 300 * time.Millisecond})
			pid := c.process.Pid
			rescue, err := unix.Dup(c.fd)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(rescue)
			defer func() {
				if !c.reaped {
					_ = send(rescue, syscall.SIGKILL)
					limit := time.Now().Add(3 * time.Second)
					var status syscall.WaitStatus
					reaped := false
					for time.Now().Before(limit) {
						got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
						if got == pid || errors.Is(err, syscall.ECHILD) {
							reaped = true
							break
						}
						time.Sleep(10 * time.Millisecond)
					}
					if !reaped {
						t.Error("test rescue could not reap owned child")
					}
				}
				_ = c.close()
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(root, "phase0.listening")); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("child failed to listen")
				}
				time.Sleep(10 * time.Millisecond)
			}
			policy := stopPolicy{send: func(fd int, sig syscall.Signal) error {
				if sig == syscall.SIGTERM {
					return syscall.EPERM
				}
				if killFails {
					return syscall.EACCES
				}
				return send(fd, sig)
			}, grace: 50 * time.Millisecond, reap: 100 * time.Millisecond}
			started := time.Now()
			err = finalize(c, syscall.SIGTERM, policy)
			if time.Since(started) > time.Second {
				t.Fatal("unbounded cleanup")
			}
			if !errors.Is(err, syscall.EPERM) || !strings.Contains(err.Error(), "forced cleanup") {
				t.Fatalf("primary cleanup lost: %v", err)
			}
			if killFails {
				if !errors.Is(err, syscall.EACCES) || !strings.Contains(err.Error(), "owned reap deadline") || c.reaped {
					t.Fatalf("force/reap failure hidden: %v", err)
				}
			} else if !c.reaped {
				t.Fatalf("SIGKILL child not reaped: %v", err)
			}
			if !c.closed {
				t.Fatal("descriptors not closed")
			}
		})
	}
}

func TestFinitePlanHasOnlyActualRegistryAccount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plan.json")
	empty := []byte(`{"registration-account-writers":{"assignments":[],"disabled":[],"retire-cluster-writer":false}}`)
	if err := os.WriteFile(path, empty, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(path, false, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(path, true, ""); err == nil {
		t.Fatal("empty plan accepted for registration phase")
	}
	account := "acc" + strings.Repeat("1", 17)
	doc := map[string]any{"registration-account-writers": map[string]any{"assignments": []map[string]string{{"assignment_id": "stand-registry-" + account, "account_id": account, "module": "registry"}}, "disabled": []any{}, "retire-cluster-writer": false}}
	body, _ := json.Marshal(doc)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(path, true, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(path, false, ""); err == nil {
		t.Fatal("assigned bootstrap admitted")
	}
	if _, err := plan(path, true, strings.Repeat("0", 64)); err == nil {
		t.Fatal("config drift admitted")
	}
	for _, bad := range []string{strings.ReplaceAll(string(body), account, "*"), strings.ReplaceAll(string(body), `"module":"registry"`, `"module":"foreign"`), strings.ReplaceAll(string(body), `"retire-cluster-writer":false`, `"retire-cluster-writer":true`)} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := plan(path, true, ""); err == nil {
			t.Fatal("broad or foreign plan accepted")
		}
	}
}

func TestConfigSnapshotNeverReplacesAndRefusesSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")
	if err := exclusive(path, []byte("original")); err != nil {
		t.Fatal(err)
	}
	if exclusive(path, []byte("replacement")) == nil {
		t.Fatal("snapshot overwritten")
	}
	body, _ := os.ReadFile(path)
	if string(body) != "original" {
		t.Fatal("snapshot changed")
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := plan(link, false, ""); err == nil {
		t.Fatal("config symlink admitted")
	}
}

func TestOwnerForwardsTERMAndINTToLiveOwnedChild(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			h := newHarness(t, "", nil)
			h.waitFile("phase0.listening")
			h.signals <- sig
			if code := h.finish(); code != 0 {
				t.Fatalf("shutdown code=%d", code)
			}
			if got := string(h.waitFile("phase0.signal")); got != sig.String() {
				t.Fatalf("forwarded %q want %q", got, sig.String())
			}
			h.assertChildren(1)
		})
	}
	t.Run("listener-close-failure", func(t *testing.T) {
		closes := 0
		h := newHarness(t, "", func(ops *ownerOps) {
			ops.closeListener = func(listener *net.UnixListener) error {
				closes++
				return errors.Join(listener.Close(), errors.New("injected listener close failure"))
			}
		})
		h.signals <- syscall.SIGTERM
		if code := h.finish(); code != 1 {
			t.Fatalf("listener cleanup failure became code=%d, want 1", code)
		}
		if closes != 1 {
			t.Fatalf("listener close count=%d want 1", closes)
		}
		h.assertChildren(1)
	})
}
func TestReadinessPrimaryAndCleanupExitSevenBothReported(t *testing.T) {
	h := newHarness(t, "missing-eight phase1-term-seven", nil)
	err := restart(h.socket, h.assignment())
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "exit status=7") {
		t.Fatalf("primary or cleanup status lost: %v", err)
	}
	if code := h.finish(); code != 7 {
		t.Fatalf("cleanup exit7 became %d", code)
	}
	h.assertChildren(2)
	t.Run("listener-close-failure", func(t *testing.T) {
		closes := 0
		h := newHarness(t, "missing-eight phase1-term-seven", func(ops *ownerOps) {
			ops.closeListener = func(listener *net.UnixListener) error {
				closes++
				return errors.Join(listener.Close(), errors.New("injected listener close failure"))
			}
		})
		err := restart(h.socket, h.assignment())
		if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "exit status=7") || !strings.Contains(err.Error(), "control listener close: injected listener close failure") {
			t.Fatalf("primary, child cleanup or listener cleanup lost: %v", err)
		}
		if code := h.finish(); code != 7 {
			t.Fatalf("child cleanup exit7 overwritten by listener failure: %d", code)
		}
		if closes != 1 {
			t.Fatalf("listener close count=%d want 1", closes)
		}
		h.assertChildren(2)
	})
}
func TestSignalsDuringReadinessDoNotAcknowledge(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			h := newHarness(t, "missing-eight", nil)
			sha := h.assignment()
			result := make(chan error, 1)
			go func() { result <- restart(h.socket, sha) }()
			h.waitFile("phase1.listening")
			h.signals <- sig
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("ACK after cancellation")
				}
			case <-time.After(5 * time.Second):
				t.Fatal("control reply lost")
			}
			if code := h.finish(); code != 0 {
				t.Fatalf("shutdown code=%d", code)
			}
			h.assertChildren(2)
		})
	}
}

func TestPreLaunchEvidenceFailuresNeverStartChild(t *testing.T) {
	for _, kind := range []string{"phase0-snapshot", "state", "socket"} {
		t.Run(kind, func(t *testing.T) {
			root, err := os.MkdirTemp("", "rwo-pre-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			config := filepath.Join(root, "registration-writers.json")
			socket := filepath.Join(root, "registration-owner.sock")
			if err = os.WriteFile(config, []byte(emptyPlan), 0600); err != nil {
				t.Fatal(err)
			}
			evidence := config + ".phase0.json"
			if kind == "state" {
				evidence = socket + ".state"
			}
			if kind == "socket" {
				evidence = socket
			}
			if err = exclusive(evidence, []byte("foreign evidence")); err != nil {
				t.Fatal(err)
			}
			starts := 0
			closes := 0
			ops := defaults()
			ops.closeListener = func(listener *net.UnixListener) error {
				closes++
				return listener.Close()
			}
			ops.launch = func(string, string) (*child, error) { starts++; return nil, errors.New("unexpected launch") }
			code := serveWith(filepath.Join(root, "kaname"), config, socket, 1, make(chan os.Signal), ops)
			if code == 0 || starts != 0 {
				t.Fatalf("prelaunch refusal code=%d starts=%d", code, starts)
			}
			wantCloses := 0
			if kind == "state" {
				wantCloses = 1
			}
			if closes != wantCloses {
				t.Fatalf("prelaunch listener close count=%d want=%d", closes, wantCloses)
			}
			body, err := os.ReadFile(evidence)
			if err != nil || string(body) != "foreign evidence" {
				t.Fatalf("foreign evidence changed: %q %v", body, err)
			}
		})
	}
}

func TestProtocolReapFailurePreservesPrimaryAndNeverAcknowledges(t *testing.T) {
	rescue, pid, targetFD := -1, 0, -1
	var assigned *child
	h := newHarness(t, "missing-eight phase1-ignore", func(ops *ownerOps) {
		ops.launch = func(binary, config string) (*child, error) {
			c, err := fixtureLaunch(binary, config)
			if err == nil && strings.HasSuffix(config, ".phase1.json") {
				assigned = c
				pid = c.process.Pid
				rescue, err = unix.Dup(c.fd)
				if err != nil {
					return c, err
				}
				targetFD = c.fd
			}
			return c, err
		}
		ops.stop.send = func(fd int, sig syscall.Signal) error {
			if fd == targetFD && sig == syscall.SIGKILL {
				return syscall.EPERM
			}
			return send(fd, sig)
		}
	})
	// Only after the owner has returned may this test become the sole waiter.
	// This rescue is outside production code and retains no numeric signal path.
	t.Cleanup(func() {
		if !h.finished {
			h.signals <- syscall.SIGTERM
			h.finish()
		}
		if rescue < 0 {
			return
		}
		defer unix.Close(rescue)
		if assigned.reaped {
			return
		}
		if err := send(rescue, syscall.SIGKILL); err != nil {
			t.Error(err)
			return
		}
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			var status syscall.WaitStatus
			got, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil)
			if got == pid {
				assigned.reaped = true
				return
			}
			if err != nil && !errors.Is(err, syscall.EINTR) {
				t.Error(err)
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("test rescue reap deadline")
	})
	err := restart(h.socket, h.assignment())
	if err == nil || !strings.Contains(err.Error(), "deadline exceeded") || !strings.Contains(err.Error(), "forced cleanup") || !strings.Contains(err.Error(), "owned reap deadline") || !strings.Contains(err.Error(), syscall.EPERM.Error()) {
		t.Fatalf("primary/force/reap failure hidden: %v", err)
	}
	if code := h.finish(); code == 0 {
		t.Fatal("reap failure was green")
	}
	if len(h.children) != 2 || assigned == nil || assigned.reaped || !assigned.closed {
		t.Fatal("wrong bounded failure state")
	}
}

func TestFixtureRaceEnvironmentPreservesParentAndReporting(t *testing.T) {
	for _, test := range []struct {
		name   string
		parent []string
		child  []string
	}{
		{"unset", []string{"OWNER_FIXTURE_MODE=phase0-ignore"}, []string{"OWNER_FIXTURE_MODE=phase0-ignore", "GORACE=atexit_sleep_ms=0"}},
		{"reporting", []string{"GORACE=halt_on_error=1 exitcode=66 log_path=stderr", "KANAME_CONFIG_PATH=/fixture/phase0"}, []string{"KANAME_CONFIG_PATH=/fixture/phase0", "GORACE=halt_on_error=1 exitcode=66 log_path=stderr atexit_sleep_ms=0"}},
		{"inherited-delay", []string{"GORACE=atexit_sleep_ms=1000 history_size=2"}, []string{"GORACE=atexit_sleep_ms=1000 history_size=2 atexit_sleep_ms=0"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			before := slices.Clone(test.parent)
			child := fixtureRaceEnvironment(test.parent)
			if !slices.Equal(child, test.child) {
				t.Fatalf("child environment=%q want=%q", child, test.child)
			}
			if !slices.Equal(test.parent, before) {
				t.Fatal("parent environment mutated")
			}
			child[0] = "child-only-mutation"
			if !slices.Equal(test.parent, before) {
				t.Fatal("child environment aliases parent")
			}
		})
	}
}

// Захваченный executable сохраняется даже при замене его имени до lease.
func TestActivationUsesOpenedExecutableAfterPathReplacement(t *testing.T) {
	root := t.TempDir()
	t.Setenv("OWNER_FIXTURE_ROOT", root)
	t.Setenv("OWNER_FIXTURE_MODE", "")
	raw, _ := json.Marshal(fixtureAddresses(t))
	t.Setenv("OWNER_FIXTURE_ADDRESSES", string(raw))
	config := filepath.Join(root, "registration-writers.json.phase0.json")
	if err := os.WriteFile(config, []byte(emptyPlan), 0600); err != nil {
		t.Fatal(err)
	}
	binary := fixtureBinary(t, root)
	c, err := launchWith(binary, config, launchOps{
		capability: pidfdCapability,
		lease:      5 * time.Second,
		start: func(path string, args []string, attr *os.ProcAttr) (*os.Process, error) {
			if err := os.Rename(binary, binary+".original"); err != nil {
				return nil, err
			}
			if err := os.WriteFile(binary, []byte("invalid replacement executable"), 0700); err != nil {
				return nil, err
			}
			return fixtureStartProcess(path, args, attr)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := finalize(c, syscall.SIGTERM, defaultStop()); err != nil {
			t.Errorf("original executable cleanup: %v", err)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(root, "phase0.listening")); err == nil {
			break
		}
		if done, err := c.poll(); done {
			t.Fatalf("opened executable was replaced: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("opened executable did not reach readiness")
		}
		time.Sleep(10 * time.Millisecond)
	}
	body, err := os.ReadFile(binary)
	if err != nil || string(body) != "invalid replacement executable" {
		t.Fatalf("foreign replacement changed: %q %v", body, err)
	}
}

func TestActivationRefusesExecutableSymlinkBeforeStart(t *testing.T) {
	root := t.TempDir()
	binary := fixtureBinary(t, root)
	link := filepath.Join(root, "linked-kaname")
	if err := os.Symlink(binary, link); err != nil {
		t.Fatal(err)
	}
	starts := 0
	_, err := launchWith(link, filepath.Join(root, "config"), launchOps{
		capability: pidfdCapability,
		lease:      5 * time.Second,
		start: func(string, []string, *os.ProcAttr) (*os.Process, error) {
			starts++
			return nil, errors.New("unexpected start")
		},
	})
	if err == nil || starts != 0 {
		t.Fatalf("executable symlink admitted: starts=%d err=%v", starts, err)
	}
}

// Реальная локальная Unix fixture: короткий pathname не зависит от длины имени теста.
func ownerUnixFixture(t *testing.T) (*os.File, *net.UnixListener) {
	t.Helper()
	root, err := os.MkdirTemp("", "rwo-connect-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	dir, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dir.Close() })
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(root, "registration-owner.sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return dir, listener
}

func ownerOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestOwnerUnixConnectLawfulPeerDeadlineAndNoFDLeak(t *testing.T) {
	dir, listener := ownerUnixFixture(t)
	// ListenUnix уже инициализировал netpoll до исходного FD census.
	before := ownerOpenFDs(t)
	for range 4 {
		conn, err := dialOwnerUnix(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		peer, err := listener.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = peer.Close() })
		if err = ownedPeer(conn); err != nil {
			t.Fatal(err)
		}
		raw, err := conn.SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var socketErr error
		if err = raw.Control(func(fd uintptr) {
			flags, flagErr := unix.FcntlInt(fd, unix.F_GETFD, 0)
			timeout, timeoutErr := unix.GetsockoptTimeval(int(fd), unix.SOL_SOCKET, unix.SO_SNDTIMEO)
			socketErr = errors.Join(flagErr, timeoutErr)
			if socketErr == nil && (flags&unix.FD_CLOEXEC == 0 || timeout.Sec != 0 || timeout.Usec != 0) {
				socketErr = errors.New("connection lost CLOEXEC or retained kernel send timeout")
			}
		}); err != nil || socketErr != nil {
			t.Fatal(errors.Join(err, socketErr))
		}
		if err = conn.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		var body [1]byte
		_, err = conn.Read(body[:]) // Настоящий peer открыт, но ничего не посылает.
		var timeout net.Error
		if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Fatalf("Go I/O deadline lost: %v", err)
		}
		if err = errors.Join(conn.Close(), peer.Close()); err != nil {
			t.Fatal(err)
		}
	}
	if after := ownerOpenFDs(t); after != before {
		t.Fatalf("lawful connect FD leak: before=%d after=%d", before, after)
	}
}

func TestOwnerUnixConnectBacklogTimeoutAndFailureNoFDLeak(t *testing.T) {
	dir, listener := ownerUnixFixture(t)
	raw, err := listener.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var listenErr error
	if err = raw.Control(func(fd uintptr) { listenErr = unix.Listen(int(fd), 0) }); err != nil || listenErr != nil {
		t.Fatal(errors.Join(err, listenErr))
	}
	// Linux backlog0 допускает один ожидающий peer; accept пока не вызывается.
	filler, err := dialOwnerUnix(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = filler.Close() })
	probe, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	err = unix.Connect(probe, &unix.SockaddrUnix{Name: filepath.Join(dir.Name(), "registration-owner.sock")})
	closeErr := unix.Close(probe)
	if !errors.Is(err, unix.EAGAIN) || closeErr != nil {
		t.Fatalf("fixture backlog is not full: connect=%v close=%v", err, closeErr)
	}
	before := ownerOpenFDs(t)
	// Даже mutant без SO_SNDTIMEO разблокируется закрытием настоящего listener.
	rescue := time.AfterFunc(8*time.Second, func() { _ = listener.Close() })
	defer rescue.Stop()
	started := time.Now()
	conn, err := dialOwnerUnix(dir)
	elapsed := time.Since(started)
	if !rescue.Stop() {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatal("connect required listener rescue instead of kernel deadline")
	}
	if conn != nil {
		_ = conn.Close()
		t.Fatal("full backlog unexpectedly connected")
	}
	var timeout net.Error
	if !errors.Is(err, os.ErrDeadlineExceeded) || !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("backlog did not produce timeout: %v", err)
	}
	// Допуск только на Linux timer tick и планирование теста; production budget=5s.
	if elapsed < 4500*time.Millisecond || elapsed > 8*time.Second {
		t.Fatalf("connect deadline not preserved: %s", elapsed)
	}
	if after := ownerOpenFDs(t); after != before {
		t.Fatalf("timeout FD leak: before=%d after=%d", before, after)
	}
	if err = errors.Join(filler.Close(), listener.Close()); err != nil {
		t.Fatal(err)
	}
	before = ownerOpenFDs(t)
	for range 4 {
		conn, err = dialOwnerUnix(dir)
		if conn != nil {
			_ = conn.Close()
			t.Fatal("missing pathname connected")
		}
		if !errors.Is(err, unix.ENOENT) {
			t.Fatalf("missing pathname errno lost: %v", err)
		}
	}
	if after := ownerOpenFDs(t); after != before {
		t.Fatalf("failed connect FD leak: before=%d after=%d", before, after)
	}
}

//go:build linux

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
// Одноразовый переход собственного test svc; не API или runtime продукта.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type request struct {
	Instance     string
	Generation   int
	ConfigSHA256 string
}
type response struct {
	Instance   string
	Generation int
	Error      string
}
type state struct {
	Instance     string
	Generation   int
	ReadySeconds int
}
type envelope struct {
	conn    net.Conn
	request request
}
type owner struct {
	instance string
	used     bool
}

func (o *owner) authorize(r request) error {
	if o.used || r.Instance != o.instance || r.Generation != 1 {
		return errors.New("чужая instance/generation или повтор restart")
	}
	if ok, _ := regexp.MatchString("^[0-9a-f]{64}$", r.ConfigSHA256); !ok {
		return errors.New("нет exact config SHA")
	}
	return nil
}

// JSON — также законный YAML. Принимается только конечный план этой фикстуры.
func plan(path string, assigned bool, expected string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return nil, errors.New("не owned regular config")
	}
	body, err := io.ReadAll(io.LimitReader(f, 16385))
	if err != nil {
		return nil, err
	}
	if len(body) > 16384 {
		return nil, errors.New("config слишком велик")
	}
	digest := sha256.Sum256(body)
	if expected != "" && hex.EncodeToString(digest[:]) != expected {
		return nil, errors.New("config SHA drift")
	}
	var doc struct {
		Writers struct {
			Assignments []struct {
				ID      string `json:"assignment_id"`
				Account string `json:"account_id"`
				Module  string `json:"module"`
			} `json:"assignments"`
			Disabled []json.RawMessage `json:"disabled"`
			Retire   bool              `json:"retire-cluster-writer"`
		} `json:"registration-account-writers"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return nil, err
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("лишний JSON")
	}
	w := doc.Writers
	if w.Assignments == nil || w.Disabled == nil || len(w.Disabled) != 0 || w.Retire {
		return nil, errors.New("чужой план фикстуры")
	}
	if !assigned && len(w.Assignments) != 0 {
		return nil, errors.New("первая фаза должна быть пустой")
	}
	if assigned {
		if len(w.Assignments) != 1 {
			return nil, errors.New("нужна одна finite assignment")
		}
		a := w.Assignments[0]
		valid, _ := regexp.MatchString("^acc[0-9a-hjkmnp-tv-z]{17}$", a.Account)
		if !valid || a.Module != "registry" || a.ID != "stand-registry-"+a.Account {
			return nil, errors.New("не actual account registry fixture plan")
		}
	}
	return body, nil
}

// Номер используется только собственным неблокирующим waitpid. Сигналы всегда
// идут через pidfd. Других waiters и скрытых exec.Cmd pipes здесь нет.
type child struct {
	process *os.Process
	fd      int
	reaped  bool
	result  error
	closed  bool
}
type childExit struct{ status syscall.WaitStatus }

func (e *childExit) Error() string {
	return fmt.Sprintf("svc exit status=%d signal=%d", e.status.ExitStatus(), e.status.Signal())
}
func (c *child) poll() (bool, error) {
	if c.reaped {
		return true, c.result
	}
	var status syscall.WaitStatus
	pid, err := syscall.Wait4(c.process.Pid, &status, syscall.WNOHANG, nil)
	if errors.Is(err, syscall.EINTR) {
		return false, nil
	}
	if err != nil {
		c.reaped = true
		c.result = errors.Join(fmt.Errorf("owned reap: %w", err), c.process.Release())
		return true, c.result
	}
	if pid == 0 {
		return false, nil
	}
	c.reaped = true
	if !status.Exited() || status.ExitStatus() != 0 {
		c.result = &childExit{status}
	}
	c.result = errors.Join(c.result, c.process.Release())
	return true, c.result
}
func (c *child) close() error {
	if c.closed {
		return nil
	}
	c.closed = true
	var err error
	if !c.reaped {
		err = c.process.Release()
	}
	if c.fd >= 0 {
		err = errors.Join(err, unix.Close(c.fd))
	}
	return err
}
func unexpected(err error) error {
	if err != nil {
		return err
	}
	return errors.New("unexpected zero svc exit")
}
func send(fd int, sig syscall.Signal) error { return unix.PidfdSendSignal(fd, sig, nil, 0) }
func pidfdCapability() error {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		return fmt.Errorf("pidfd capability: %w", err)
	}
	return errors.Join(send(fd, 0), unix.Close(fd))
}
func requirePidfd(fd int) error {
	if fd < 0 {
		return errors.New("pidfd обязателен; service activation запрещена")
	}
	return nil
}

type launchOps struct {
	capability func() error
	start      func(string, []string, *os.ProcAttr) (*os.Process, error)
	lease      time.Duration
}

func launch(binary, config string) (*child, error) {
	return launchWith(binary, config, launchOps{pidfdCapability, os.StartProcess, 5 * time.Second})
}
func await(c *child, budget time.Duration) (bool, error) {
	deadline := time.NewTimer(budget)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if done, err := c.poll(); done {
			return true, err
		}
		select {
		case <-deadline.C:
			return false, errors.New("owned reap deadline")
		case <-tick.C:
		}
	}
}
func launchWith(binary, config string, ops launchOps) (*child, error) {
	if err := ops.capability(); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	gate, activation, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	defer gate.Close()
	defer activation.Close()
	fd := -1
	env := make([]string, 0, len(os.Environ())+1)
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "KANAME_CONFIG_PATH=") {
			env = append(env, e)
		}
	}
	env = append(env, "KANAME_CONFIG_PATH="+config)
	process, err := ops.start(self, []string{self, "__activate", binary}, &os.ProcAttr{
		Env: env, Files: []*os.File{os.Stdin, os.Stdout, os.Stderr, gate},
		Sys: &syscall.SysProcAttr{PidFD: &fd},
	})
	if err != nil {
		return nil, err
	}
	c := &child{process: process, fd: fd}
	// Даже успешный StartProcess может вернуть fd=-1. До записи G работает
	// только наш gate: EOF либо его собственный deadline завершает его без exec.
	if err = requirePidfd(fd); err == nil {
		err = send(fd, 0)
	}
	if err != nil {
		closeErr := activation.Close()
		_, reapErr := await(c, ops.lease)
		return nil, errors.Join(err, closeErr, reapErr, c.close())
	}
	if _, err = activation.Write([]byte{'G'}); err != nil {
		closeErr := activation.Close()
		cleanup := stop(c, syscall.SIGTERM, defaultStop())
		return nil, errors.Join(err, closeErr, cleanup, c.close())
	}
	return c, nil
}

// Единственный pre-exec gate. Дескриптор не переносится в службу; никакой
// числовой signal fallback не нужен даже при невозможности захвата pidfd.
func activate() int {
	if len(os.Args) != 3 || !filepath.IsAbs(os.Args[2]) {
		return 125
	}
	gate := os.NewFile(3, "activation-lease")
	if gate == nil {
		return 125
	}
	deadline := time.AfterFunc(4*time.Second, func() { os.Exit(125) })
	var token [1]byte
	_, err := io.ReadFull(gate, token[:])
	closeErr := gate.Close()
	if err != nil || closeErr != nil || token[0] != 'G' {
		return 125
	}
	if !deadline.Stop() {
		return 125
	}
	if err := syscall.Exec(os.Args[2], []string{os.Args[2], "serve"}, os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "service exec:", err)
		return 126
	}
	return 126
}

type stopPolicy struct {
	send  func(int, syscall.Signal) error
	grace time.Duration
	reap  time.Duration
}

func defaultStop() stopPolicy { return stopPolicy{send, 15 * time.Second, 5 * time.Second} }

// Readiness keeps its original budget. The control reply must additionally
// allow both bounded stop/reap phases, so cleanup errors can reach the caller.
func controlBudget(seconds int) time.Duration {
	policy := defaultStop()
	return time.Duration(seconds)*time.Second + 2*(policy.grace+policy.reap) + 5*time.Second
}
func stop(c *child, sig syscall.Signal, policy stopPolicy) error {
	if done, err := c.poll(); done {
		return unexpected(err)
	}
	first := policy.send(c.fd, sig)
	if done, err := await(c, policy.grace); done {
		return errors.Join(first, err)
	}
	forced := errors.New("forced cleanup after graceful deadline")
	killErr := policy.send(c.fd, syscall.SIGKILL)
	_, reapErr := await(c, policy.reap)
	return errors.Join(first, forced, killErr, reapErr)
}
func finalize(c *child, sig syscall.Signal, policy stopPolicy) error {
	if c == nil || c.closed {
		return nil
	}
	var err error
	if done, prior := c.poll(); done {
		err = prior
	} else {
		err = stop(c, sig, policy)
	}
	return errors.Join(err, c.close())
}
func exitCode(err error) int {
	var e *childExit
	if errors.As(err, &e) {
		if e.status.Signaled() {
			return 128 + int(e.status.Signal())
		}
		if code := e.status.ExitStatus(); code != 0 {
			return code
		}
	}
	return 1
}

type shutdown struct{ signal syscall.Signal }

func (e *shutdown) Error() string { return "owner shutdown: " + e.signal.String() }

// private socket проверяется также kernel peer credentials, не только именем файла.
func ownedPeer(conn net.Conn) error { return ownedPeerUID(conn, uint32(os.Getuid())) }
func ownedPeerUID(conn net.Conn, expectedUID uint32) error {
	u, ok := conn.(*net.UnixConn)
	if !ok {
		return errors.New("не Unix control")
	}
	raw, err := u.SyscallConn()
	if err != nil {
		return err
	}
	var credential *unix.Ucred
	var socketErr error
	if err = raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if socketErr != nil {
		return socketErr
	}
	if credential == nil || credential.Uid != expectedUID {
		return errors.New("foreign control peer")
	}
	return nil
}

type ownerOps struct {
	launch    func(string, string) (*child, error)
	snapshot  func(string, []byte) error
	peer      func(net.Conn) error
	stop      stopPolicy
	addresses []string
}

func defaults() ownerOps {
	addresses := []string{}
	for _, port := range []string{"9090", "9091", "9095", "9096", "9097", "9098", "9099", "9100"} {
		addresses = append(addresses, "127.0.0.1:"+port)
	}
	return ownerOps{launch, exclusive, ownedPeer, defaultStop(), addresses}
}

// Восемь исходных слушателей в исходном бюджете. Ни готовность, ни её отказ
// не забирают ответственность за child у единственного finalizer.
func healthy(c *child, signals <-chan os.Signal, seconds int, addresses []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	for {
		if done, err := c.poll(); done {
			return unexpected(err)
		}
		select {
		case sig := <-signals:
			return &shutdown{sig.(syscall.Signal)}
		default:
		}
		all := true
		for _, address := range addresses {
			conn, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", address)
			if err != nil {
				all = false
				break
			}
			_ = conn.Close()
		}
		if all {
			if done, err := c.poll(); done {
				return unexpected(err)
			}
			select {
			case sig := <-signals:
				return &shutdown{sig.(syscall.Signal)}
			default:
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case sig := <-signals:
			return &shutdown{sig.(syscall.Signal)}
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func serve(binary, config, socket string, readySeconds int) int {
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	return serveWith(binary, config, socket, readySeconds, signals, defaults())
}
func serveWith(binary, config, socket string, readySeconds int, signals <-chan os.Signal, ops ownerOps) (code int) {
	if !filepath.IsAbs(binary) || filepath.Base(binary) != "kaname" || filepath.Base(config) != "registration-writers.json" || filepath.Base(socket) != "registration-owner.sock" || filepath.Dir(binary) != filepath.Dir(config) || filepath.Dir(binary) != filepath.Dir(socket) || readySeconds < 1 || len(ops.addresses) != 8 {
		return 1
	}
	body, err := plan(config, false, "")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	snapshot := config + ".phase0.json"
	if err = ops.snapshot(snapshot, body); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	oldMask := syscall.Umask(0077)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	syscall.Umask(oldMask)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Не удаляем pathname при закрытии: replacement inode нам не принадлежит.
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	if err = os.Chmod(socket, 0600); err != nil {
		return 1
	}
	token := make([]byte, 32)
	if _, err = rand.Read(token); err != nil {
		return 1
	}
	o := owner{instance: hex.EncodeToString(token)}
	raw, _ := json.Marshal(state{Instance: o.instance, Generation: 1, ReadySeconds: readySeconds})
	if err = ops.snapshot(socket+".state", raw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var c *child
	var primary error
	var pending net.Conn
	defer func() {
		sig := syscall.SIGTERM
		var requested *shutdown
		if errors.As(primary, &requested) {
			sig = requested.signal
		}
		cleanup := finalize(c, sig, ops.stop)
		combined := errors.Join(primary, cleanup)
		if pending != nil {
			message := "owner stopped before phase2 ACK"
			if combined != nil {
				message = combined.Error()
			}
			_ = json.NewEncoder(pending).Encode(response{Instance: o.instance, Generation: 1, Error: message})
			_ = pending.Close()
		}
		if combined != nil {
			fmt.Fprintln(os.Stderr, combined)
		}
		if cleanup != nil {
			code = exitCode(combined)
		} else if requested != nil {
			code = 0
		} else if primary != nil {
			code = exitCode(primary)
		}
	}()
	c, primary = ops.launch(binary, snapshot)
	if primary != nil {
		return 1
	}
	incoming := make(chan envelope)
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			if ops.peer(conn) != nil {
				_ = conn.Close()
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
			var r request
			if json.NewDecoder(conn).Decode(&r) != nil {
				_ = conn.Close()
				continue
			}
			_ = conn.SetDeadline(time.Now().Add(controlBudget(readySeconds)))
			select {
			case incoming <- envelope{conn, r}:
			case <-finished:
				_ = conn.Close()
				return
			case <-time.After(5 * time.Second):
				_ = conn.Close()
			}
		}
	}()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-tick.C:
			if done, err := c.poll(); done {
				primary = unexpected(err)
				return 1
			}
		case sig := <-signals:
			primary = &shutdown{sig.(syscall.Signal)}
			return 0
		case e := <-incoming:
			pending = e.conn
			refusal := o.authorize(e.request)
			var next []byte
			if refusal == nil {
				next, refusal = plan(config, true, e.request.ConfigSHA256)
			}
			if refusal == nil {
				refusal = ops.snapshot(config+".phase1.json", next)
			}
			if refusal != nil {
				// Неверный hash или незафиксированный snapshot не достигают TERM.
				encodeErr := json.NewEncoder(pending).Encode(response{Instance: o.instance, Generation: 1, Error: refusal.Error()})
				_ = pending.Close()
				pending = nil
				if encodeErr != nil {
					primary = errors.Join(refusal, encodeErr)
					return 1
				}
				continue
			}
			o.used = true
			primary = stop(c, syscall.SIGTERM, ops.stop)
			if primary != nil {
				return 1
			}
			primary = c.close()
			if primary != nil {
				return 1
			}
			c = nil
			select {
			case sig := <-signals:
				primary = &shutdown{sig.(syscall.Signal)}
				return 0
			default:
			}
			c, primary = ops.launch(binary, config+".phase1.json")
			if primary != nil {
				return 1
			}
			primary = healthy(c, signals, readySeconds, ops.addresses)
			if primary != nil {
				return 1
			}
			if err = json.NewEncoder(pending).Encode(response{Instance: o.instance, Generation: 2}); err != nil {
				primary = fmt.Errorf("phase2 ACK: %w", err)
				return 1
			}
			_ = pending.Close()
			pending = nil
		}
	}
}
func exclusive(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	_, err = f.Write(body)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func restart(socket, sha string) error {
	info, err := os.Lstat(socket)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0600 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("не private owned socket")
	}
	file, err := os.OpenFile(socket+".state", os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0400 || info.Sys().(*syscall.Stat_t).Uid != uint32(os.Getuid()) {
		return errors.New("не private owned instance state")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 4096))
	if err != nil {
		return err
	}
	var current state
	if err = json.Unmarshal(raw, &current); err != nil {
		return err
	}
	if current.Generation != 1 || current.ReadySeconds < 1 {
		return errors.New("foreign phase")
	}
	r := request{Instance: current.Instance, Generation: 1, ConfigSHA256: sha}
	conn, err := net.DialTimeout("unix", socket, 5*time.Second)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	if err = ownedPeer(conn); err != nil {
		return err
	}
	_ = conn.SetDeadline(time.Now().Add(controlBudget(current.ReadySeconds)))
	if err = json.NewEncoder(conn).Encode(r); err != nil {
		return err
	}
	var result response
	if err = json.NewDecoder(conn).Decode(&result); err != nil {
		return err
	}
	if result.Error != "" || result.Instance != r.Instance || result.Generation != 2 {
		return fmt.Errorf("restart refused: %s", result.Error)
	}
	return nil
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "__activate" {
		os.Exit(activate())
	}
	if len(os.Args) == 6 && os.Args[1] == "serve" {
		seconds, err := strconv.Atoi(os.Args[5])
		if err != nil || seconds < 1 {
			os.Exit(64)
		}
		os.Exit(serve(os.Args[2], os.Args[3], os.Args[4], seconds))
	}
	if len(os.Args) == 4 && os.Args[1] == "restart" {
		if err := restart(os.Args[2], os.Args[3]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "fixture owner: serve BINARY CONFIG SOCKET READYSECONDS | restart SOCKET SHA256")
	os.Exit(64)
}

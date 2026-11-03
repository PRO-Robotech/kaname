// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package installruntime runs the ordinary Kaname executable for installation
// acceptance. It supplies no identity, configuration defaults, database, or TLS
// bypass. The fixture must provision those through the existing stand mechanisms.
package installruntime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Input struct {
	Binary               string
	ExpectedBinarySHA256 string
	ConfigFile           string
	Environment          []string
	EvidenceDir          string
}

type Process struct {
	cmd          *exec.Cmd
	done         chan struct{}
	mu           sync.Mutex
	err          error
	BinarySHA256 string
	StdoutPath   string
	StderrPath   string
}

// Start invokes the existing serve command. Environment is explicit so a
// previously running fixture cannot silently supply another credential or DSN.
// ctx is the real process deadline; cancellation kills the process, it is not
// merely metadata in an evidence file.
func Start(ctx context.Context, in Input) (*Process, error) {
	if !filepath.IsAbs(in.Binary) || !filepath.IsAbs(in.ConfigFile) || !filepath.IsAbs(in.EvidenceDir) {
		return nil, errors.New("runtime fixture requires absolute binary, config and evidence paths")
	}
	f, err := os.Open(in.Binary)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	_, err = io.Copy(h, f)
	f.Close()
	if err != nil {
		return nil, err
	}
	digest := hex.EncodeToString(h.Sum(nil))
	if in.ExpectedBinarySHA256 != "" && digest != in.ExpectedBinarySHA256 {
		return nil, errors.New("serve executable differs from frozen artifact before launch")
	}
	if err := os.Mkdir(in.EvidenceDir, 0700); err != nil {
		return nil, err
	}
	p := &Process{done: make(chan struct{}), BinarySHA256: digest,
		StdoutPath: filepath.Join(in.EvidenceDir, "stdout.jsonl"), StderrPath: filepath.Join(in.EvidenceDir, "stderr.jsonl")}
	out, err := os.OpenFile(p.StdoutPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	errout, err := os.OpenFile(p.StderrPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		out.Close()
		return nil, err
	}
	p.cmd = exec.CommandContext(ctx, in.Binary, "serve")
	p.cmd.Env = append(append([]string{}, in.Environment...), "KANAME_CONFIG_PATH="+in.ConfigFile)
	p.cmd.Stdout, p.cmd.Stderr = out, errout
	if err := p.cmd.Start(); err != nil {
		out.Close()
		errout.Close()
		return nil, err
	}
	go func() {
		err := p.cmd.Wait()
		out.Close()
		errout.Close()
		p.mu.Lock()
		p.err = err
		p.mu.Unlock()
		close(p.done)
	}()
	return p, nil
}

// AwaitReady requires an actual listener/application probe supplied by the
// fixture; merely seeing a startup log or a live PID cannot establish readiness.
func (p *Process) AwaitReady(ctx context.Context, probe func(context.Context) error) error {
	if probe == nil {
		return errors.New("readiness probe is required")
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.done:
			return fmt.Errorf("serve exited before readiness: %w", p.ExitError())
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		attempt, cancel := context.WithTimeout(ctx, time.Second)
		err := probe(attempt)
		cancel()
		if err == nil {
			select {
			case <-p.done:
				return errors.New("serve exited during readiness probe")
			default:
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-p.done:
			return errors.New("serve exited before readiness")
		case <-ticker.C:
		}
	}
}

func (p *Process) ExitError() error { p.mu.Lock(); defer p.mu.Unlock(); return p.err }

func (p *Process) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.done:
		return p.ExitError()
	}
}

// Stop preserves the production graceful-shutdown result; forced cleanup is a
// failure, never a successful installation exit.
func (p *Process) Stop(ctx context.Context) error {
	select {
	case <-p.done:
		return p.ExitError()
	default:
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	if err := p.Wait(ctx); err != nil {
		_ = p.cmd.Process.Kill()
		return err
	}
	return nil
}

// Results reads only the structured installation object, while raw logs remain
// private evidence. Driver messages and credential values are never printed by
// this helper. Callers still assert absence of their exact secret bytes in BOTH
// raw streams before publishing evidence.
func (p *Process) Results() ([]json.RawMessage, error) {
	var results []json.RawMessage
	for _, path := range []string{p.StdoutPath, p.StderrPath} {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		s := bufio.NewScanner(f)
		s.Buffer(make([]byte, 4096), 1024*1024)
		for s.Scan() {
			var record map[string]json.RawMessage
			if json.Unmarshal(s.Bytes(), &record) == nil && record["installation"] != nil {
				results = append(results, append(json.RawMessage{}, record["installation"]...))
			}
		}
		err = s.Err()
		f.Close()
		if err != nil {
			return nil, err
		}
	}
	return results, nil
}

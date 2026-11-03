// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Пакет installruntime запускает штатный исполняемый файл Kaname для приёмки
// установки. Он не подставляет идентичность, умолчания конфигурации, базу данных или обход
// TLS. Фикстура должна подготовить их существующими механизмами стенда.
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

// Start вызывает существующую команду serve. Окружение явно, чтобы ранее
// работавшая фикстура не могла незаметно подставить другое удостоверение или DSN.
// ctx — настоящий срок процесса; отмена завершает процесс, а не служит
// лишь метаданными в файле доказательства.
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
	p.cmd.Dir = in.EvidenceDir
	p.cmd.Env = append(append([]string{}, in.Environment...), "KANAME_CONFIG_PATH="+in.ConfigFile)
	p.cmd.Stdout, p.cmd.Stderr = out, errout
	if err := p.cmd.Start(); err != nil {
		out.Close()
		errout.Close()
		return nil, err
	}
	identity, _ := json.Marshal(map[string]any{"pid": p.cmd.Process.Pid, "binarySHA256": digest})
	if err := os.WriteFile(filepath.Join(in.EvidenceDir, "process.json"), identity, 0600); err != nil {
		_ = p.cmd.Process.Kill()
		_ = p.cmd.Wait()
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
		terminal, _ := json.Marshal(map[string]any{"pid": p.cmd.Process.Pid, "exited": true, "exitCode": p.cmd.ProcessState.ExitCode()})
		_ = os.WriteFile(filepath.Join(in.EvidenceDir, "terminal.json"), terminal, 0600)
		close(p.done)
	}()
	return p, nil
}

// AwaitReady требует настоящую пробу слушателя/приложения, переданную
// фикстурой; одного журнала запуска или живого PID недостаточно для установления готовности.
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

// Stop сохраняет результат производственного плавного завершения; принудительная очистка —
// отказ, а не успешный выход установки.
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

// Results читает только структурный объект установки, а необработанные журналы остаются
// закрытым доказательством. Сообщения драйвера и значения удостоверений не печатаются
// этим помощником. Вызывающие всё равно проверяют отсутствие точных байтов секретов в ОБОИХ
// необработанных потоках до публикации доказательства.
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

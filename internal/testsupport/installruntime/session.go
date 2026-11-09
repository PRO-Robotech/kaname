// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Session владеет последовательными НАСТОЯЩИМИ процессами serve на одной существующей базе.
// Вызывающий передаёт штатно подготовленный постоянный удостоверяющий материал, настоящее окружение PKI/DB
// и пробу готовности TLS/приложения. Этот тип не может выдумать
// идентичность, засеять базу или незаметно заменить исполняемый файл после перезапуска.
type Session struct {
	Binary       string
	BinarySHA256 string
	Environment  []string
	Root         string
	Probe        func(context.Context) error
	History      []*Process
	running      *Process
	sequence     int
}

type DeliveryInput struct {
	RegistrationWriters *RegistrationWriterPlan
	Manifests           RIDDeliveryFixture
	Reverse             bool
	CredentialFile      string
	// nil означает S2; ненулевой указатель — ТОЧНОЕ значение S1, включая намеренно пустой вход.
	TenantAccountID *string
	// ExtraConfig — полный профиль фикстуры (PKI/DB обычно остаются в окружении).
	// Зарезервированные ключи поставки/установщика не могут затеняться этой картой или окружением.
	ExtraConfig map[string]any
}

func (s *Session) start(ctx context.Context, config []byte) (*Process, error) {
	if s.running != nil {
		return nil, fmt.Errorf("stop the owned serve process before restart")
	}
	if s.Probe == nil || s.BinarySHA256 == "" {
		return nil, fmt.Errorf("real readiness probe and frozen binary fingerprint are required")
	}
	s.sequence++
	dir := filepath.Join(s.Root, fmt.Sprintf("serve-%03d", s.sequence))
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, config, 0600); err != nil {
		return nil, err
	}
	p, err := Start(ctx, Input{Binary: s.Binary, ExpectedBinarySHA256: s.BinarySHA256, ConfigFile: path, Environment: s.Environment, EvidenceDir: filepath.Join(dir, "process")})
	if err != nil {
		return nil, err
	}
	s.running = p
	s.History = append(s.History, p)
	if p.BinarySHA256 != s.BinarySHA256 {
		stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = s.Stop(stop)
		return nil, fmt.Errorf("serve executable differs from the frozen source artifact")
	}
	return p, nil
}

// StartBase явно исключает поставленные модули и вход установщика. Та же
// база впоследствии получает полную поставку через StartDelivery.
func (s *Session) StartBase(ctx context.Context, plan *RegistrationWriterPlan) (*Process, error) {
	if err := s.checkEnvironment(); err != nil {
		return nil, err
	}
	body, err := FullStartupConfig(map[string]any{"manifests": map[string]any{"dir": "", "required": false}}, plan)
	if err != nil {
		return nil, err
	}
	p, err := s.start(ctx, body)
	if err != nil {
		return p, err
	}
	ready, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return p, p.AwaitReady(ready, s.Probe)
}

// StartDelivery вызывает штатный полный serve, сохраняя неверный вход для
// случаев отказа. Вызывающий решает, ждать готовности или выхода процесса;
// переживший запуск процесс сам по себе не доказывает приём.
func (s *Session) StartDelivery(ctx context.Context, in DeliveryInput) (*Process, error) {
	if err := s.checkEnvironment(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(in.CredentialFile) {
		return nil, fmt.Errorf("standing credential path must be absolute")
	}
	doc := make(map[string]any, len(in.ExtraConfig)+2)
	for k, v := range in.ExtraConfig {
		if k == "manifests" || k == "moduleSeedInstaller" || k == "registration-account-writers" {
			return nil, fmt.Errorf("reserved installation profile key %s", k)
		}
		doc[k] = v
	}
	dir := filepath.Join(s.Root, fmt.Sprintf("delivery-%03d", s.sequence+1))
	if _, err := in.Manifests.Write(dir, in.Reverse); err != nil {
		return nil, err
	}
	doc["manifests"] = map[string]any{"dir": dir, "required": true}
	installer := map[string]any{"credentialFile": in.CredentialFile}
	if in.TenantAccountID != nil {
		installer["tenantAccountId"] = *in.TenantAccountID
	}
	doc["moduleSeedInstaller"] = installer
	body, err := FullStartupConfig(doc, in.RegistrationWriters)
	if err != nil {
		return nil, err
	}
	return s.start(ctx, body)
}

func (s *Session) checkEnvironment() error {
	for _, entry := range s.Environment {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		compact := strings.NewReplacer("_", "", "-", "").Replace(upper)
		if strings.HasPrefix(compact, "KANAMEREGISTRATIONACCOUNTWRITERS") || upper == "KANAME_CONFIG_PATH" || strings.HasPrefix(upper, "KANAME_MANIFESTS") || strings.HasPrefix(upper, "KANAME_MODULESEEDINSTALLER") {
			return fmt.Errorf("environment would shadow installation input: %s", name)
		}
	}
	return nil
}
func (s *Session) Stop(ctx context.Context) error {
	if s.running == nil {
		return nil
	}
	p := s.running
	err := p.Stop(ctx)
	s.running = nil
	return err
}

// CheckSecretAbsence проверяет ОБА полных необработанных потока. Экранированные JSON формы
// тоже проверяются, поскольку многострочный PEM обычно экранируется журналированием JSON.
// Сообщения ошибок не воспроизводят секрет или нарушающую строку журнала.
func (p *Process) CheckSecretAbsence(secrets ...string) error {
	for _, path := range []string{p.StdoutPath, p.StderrPath} {
		raw, err := os.ReadFile(path) // #nosec G304 -- читаются только два захваченных пути потоков собственного процесса фикстуры.
		if err != nil {
			return err
		}
		for i, secret := range secrets {
			if secret == "" {
				continue
			}
			encoded, _ := json.Marshal(secret)
			if bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, encoded[1:len(encoded)-1]) {
				return fmt.Errorf("credential material %d appeared in serve stream %s", i, filepath.Base(path))
			}
		}
	}
	return nil
}

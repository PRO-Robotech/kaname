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

	"gopkg.in/yaml.v3"
)

// Session owns successive REAL serve processes against one existing database.
// The caller supplies ordinary provisioned standing credentials, real PKI/DB
// environment and a TLS/application readiness probe. This type cannot fabricate
// an identity, seed a database or silently replace the executable after restart.
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
	Manifests      RIDDeliveryFixture
	Reverse        bool
	CredentialFile string
	// nil is S2; non-nil is the EXACT S1 value, including deliberate empty input.
	TenantAccountID *string
	// ExtraConfig is the complete fixture profile (PKI/DB normally stay in env).
	// Reserved delivery/installer keys cannot be shadowed by this map or env.
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

// StartBase explicitly excludes delivered modules and installer input. The same
// database subsequently receives the full delivery through StartDelivery.
func (s *Session) StartBase(ctx context.Context) (*Process, error) {
	if err := s.checkEnvironment(); err != nil {
		return nil, err
	}
	p, err := s.start(ctx, []byte("manifests:\n  dir: ''\n  required: false\n"))
	if err != nil {
		return p, err
	}
	ready, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	return p, p.AwaitReady(ready, s.Probe)
}

// StartDelivery invokes ordinary full serve, preserving invalid input for
// failure cases. The caller decides whether to await readiness or process exit;
// a process surviving startup is not itself proof of acceptance.
func (s *Session) StartDelivery(ctx context.Context, in DeliveryInput) (*Process, error) {
	if err := s.checkEnvironment(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(in.CredentialFile) {
		return nil, fmt.Errorf("standing credential path must be absolute")
	}
	doc := make(map[string]any, len(in.ExtraConfig)+2)
	for k, v := range in.ExtraConfig {
		if k == "manifests" || k == "moduleSeedInstaller" {
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
	body, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return s.start(ctx, body)
}

func (s *Session) checkEnvironment() error {
	for _, entry := range s.Environment {
		name, _, _ := strings.Cut(entry, "=")
		upper := strings.ToUpper(name)
		if upper == "KANAME_CONFIG_PATH" || strings.HasPrefix(upper, "KANAME_MANIFESTS") || strings.HasPrefix(upper, "KANAME_MODULESEEDINSTALLER") {
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

// CheckSecretAbsence inspects BOTH complete raw streams. JSON-escaped forms are
// checked as well, since a multiline PEM is commonly escaped by JSON logging.
// Error messages never reproduce the secret or the offending log line.
func (p *Process) CheckSecretAbsence(secrets ...string) error {
	for _, path := range []string{p.StdoutPath, p.StderrPath} {
		raw, err := os.ReadFile(path)
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

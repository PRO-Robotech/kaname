// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const rid11ChildEnv = "KANAME_RID11_INPUT_AUTHN_CHILD"

type rid11ChildInput struct {
	ConfigPath, EvidenceDir, Creator, Variant string
	Twin                                      bool
}
type rid11Return struct {
	Code                                                                 int32
	ErrorPresent, MessageMatches, CaptureOK                              bool
	MaterialObservations, ProofObservations, AuthorityCalls              int
	ActualCreator, ActualQuestion, ContextLive, ForwardAllowed, Injected bool
}

// Единственный сбой полномочий заменяет неудачный транспортный результат Check. Настоящий
// арбитр сначала вызывается с точными настоящими проверенными субъектом и вопросом.
// Ни преобразователь исходов, ни субъект/контекст не заменяются.
type rid11Authority struct {
	authzguard.RelationChecker
	input   rid11ChildInput
	receipt *rid11Return
}

func (r *rid11Authority) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	p, ok := operations.PrincipalFromContextOK(ctx)
	r.receipt.AuthorityCalls++
	actual := ok && p.Type == "service_account" && p.ID == r.input.Creator && subject == "service_account:"+p.ID
	question := relation == "system_admin" && object == authzguard.ClusterObject()
	r.receipt.ActualCreator = actual
	r.receipt.ActualQuestion = question
	r.receipt.ContextLive = ctx.Err() == nil
	allowed, err := r.RelationChecker.Check(ctx, subject, relation, object)
	r.receipt.ForwardAllowed = allowed && err == nil
	if r.input.Variant == "backend" && !r.input.Twin && r.receipt.AuthorityCalls == 1 {
		if !actual || !question || ctx.Err() != nil || err != nil || !allowed {
			return false, errors.New("owned RID11 authority premise not met")
		}
		r.receipt.Injected = true
		return false, errors.New("owned RID11 fresh prewrite authority transport failure")
	}
	return allowed, err
}

func TestRID11OwnedInputAuthnStartupChild(t *testing.T) {
	path := os.Getenv(rid11ChildEnv)
	if path == "" {
		t.Skip("owned input/authentication startup entrypoint")
	}
	own := func(fd uintptr, name string) *os.File {
		f := os.NewFile(fd, name)
		require.NotNil(t, f)
		t.Cleanup(func() { _ = f.Close() })
		return f
	}
	require.NoError(t, syscall.SetNonblock(3, true))
	events := own(3, "rid11-events")
	require.NoError(t, syscall.SetNonblock(4, true))
	control := own(4, "rid11-control")
	inventory := own(5, "rid11-anonymous-secret-inventory")
	info, err := inventory.Stat()
	require.NoError(t, err)
	require.True(t, info.Mode().IsRegular() && info.Mode().Perm() == 0600)
	require.NoError(t, events.SetWriteDeadline(time.Now().Add(15*time.Second)))
	require.NoError(t, control.SetReadDeadline(time.Now().Add(15*time.Second)))
	// Повторно используем протокол только владения, который не утверждает аутентификацию.
	require.NoError(t, json.NewEncoder(events).Encode(rid02ChildEvent{Stage: "whole-preauth-armed", PID: os.Getpid()}))
	var action string
	require.NoError(t, json.NewDecoder(control).Decode(&action))
	require.Equal(t, "start-full-startup", action)
	require.NoError(t, events.SetWriteDeadline(time.Time{}))
	require.NoError(t, control.SetReadDeadline(time.Time{}))
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var input rid11ChildInput
	require.NoError(t, json.Unmarshal(raw, &input))
	cfg, err := config.Load(input.ConfigPath)
	require.NoError(t, err)
	require.NoError(t, cfg.Validate())
	require.NoError(t, refusaldomain.Declare(refusaldomain.ProductSuffix))
	var receipt rid11Return
	var mu sync.Mutex
	var captureErr error
	observer := func(pem, proof string) {
		mu.Lock()
		defer mu.Unlock()
		receipt.MaterialObservations++
		if proof != "" {
			receipt.ProofObservations++
		}
		if captureErr == nil {
			captureErr = json.NewEncoder(inventory).Encode([]string{pem, proof})
		}
	}
	deps := installationServeDependencies{observeCredential: observer, installationPageSize: 2,
		decorateInstallationRelations: func(real authzguard.RelationChecker) authzguard.RelationChecker {
			return &rid11Authority{RelationChecker: real, input: input, receipt: &receipt}
		},
	}
	if input.Variant == "census" {
		pages := &rid08ObservedPages{dir: input.EvidenceDir, fault: !input.Twin, emit: func(context.Context, string) error { return nil }}
		deps.decorateInstallationReader = func(real *kanamepg.InstallationReader) installationReadSource { return real.WithPageFactory(pages) }
	}
	err = runServe(cfg, deps)
	code := status.Code(err)
	receipt.Code = int32(code)
	receipt.ErrorPresent = err != nil
	wantMessage := ""
	if !input.Twin {
		switch input.Variant {
		case "backend":
			wantMessage = "authz backend unavailable"
		case "authority":
			wantMessage = "permission denied"
		case "census":
			wantMessage = "internal error"
		case "deleted-creator", "revoked-key", "bad-signature":
			wantMessage = "unauthenticated"
		}
	}
	receipt.MessageMatches = (err == nil && input.Twin) || (err != nil && (wantMessage == "" || status.Convert(err).Message() == wantMessage))
	mu.Lock()
	receipt.CaptureOK = captureErr == nil
	mu.Unlock()
	raw, marshalErr := json.Marshal(receipt)
	require.NoError(t, marshalErr)
	require.NoError(t, os.WriteFile(filepath.Join(input.EvidenceDir, "actual-return.json"), raw, 0600))
	require.True(t, receipt.CaptureOK, "anonymous actual secret inventory incomplete")
	if err != nil {
		t.Error("actual complete RID11 startup refused; safe structured status retained")
	}
	if input.Twin {
		require.Equal(t, codes.OK, code)
	}
}

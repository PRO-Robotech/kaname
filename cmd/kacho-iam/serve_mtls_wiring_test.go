// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestSECH_ServeWiresServerMTLSCreds — SEC-H wiring guard.
//
// serve.go строит per-listener server-side mTLS creds через config.LoadMTLS()
// → PublicServerCreds()/InternalServerCreds() и передает полученный
// grpc.ServerOption ПЕРВЫМ аргументом в оба grpcsrv.NewServer(...) (public →
// public cfg, internal → internal cfg). Это и есть весь смысл SEC-H: без creds
// internalSrv остается plaintext, а UnaryCertIdentityExtract — no-op.
//
// RED-демонстрация: убрать publicServerCreds/internalServerCreds из
// grpcsrv.NewServer(...) → этот тест падает ДО мержа.
func TestSECH_ServeWiresServerMTLSCreds(t *testing.T) {
	src := readFileT(t, "serve.go")

	// config.LoadMTLS() must be called in the composition root.
	if !strings.Contains(src, "config.LoadMTLS()") {
		t.Errorf("serve.go: нет config.LoadMTLS() — server-side mTLS не загружается (SEC-H)")
	}
	// Both per-edge creds builders must be invoked.
	for _, m := range []string{"PublicServerCreds()", "InternalServerCreds()"} {
		if !strings.Contains(src, m) {
			t.Errorf("serve.go: нет вызова %s (SEC-H per-edge server creds)", m)
		}
	}

	// Both grpcsrv.NewServer(...) calls must receive a *ServerCreds option as
	// the first argument: grpcsrv.NewServer(\n\t\t<creds>, ...).
	newServerRe := regexp.MustCompile(`grpcsrv\.NewServer\(\s*\n\s*(\w+)`)
	matches := newServerRe.FindAllStringSubmatch(src, -1)
	if len(matches) < 2 {
		t.Fatalf("serve.go: ожидалось >=2 grpcsrv.NewServer(...) (public+internal), найдено %d", len(matches))
	}
	firstArgs := map[string]bool{}
	for _, m := range matches {
		firstArgs[m[1]] = true
	}
	for _, creds := range []string{"publicServerCreds", "internalServerCreds"} {
		if !firstArgs[creds] {
			t.Errorf("serve.go: grpcsrv.NewServer(...) не принимает %s первым аргументом "+
				"(SEC-H: server creds должны быть подключены к listener'у)", creds)
		}
	}

	// Startup log mirroring vpc, reflecting per-edge state.
	if !strings.Contains(src, `"kacho-iam listener mTLS"`) {
		t.Errorf("serve.go: нет INFO-лога \"kacho-iam listener mTLS\" с public_mtls/internal_mtls (SEC-H-08)")
	}
}

func readFileT(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(b)
}

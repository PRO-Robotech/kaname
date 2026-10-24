// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// anonymous_pace_wiring_test.go — сборка докерной полосы с анонимным потоком
// требует темп на источник и правило источника (kaname#928).
package registrytokenwire_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
	"github.com/PRO-Robotech/kaname/internal/testsupport/lanesigner"
)

func peerOf(r *http.Request) string { return strings.Split(r.RemoteAddr, ":")[0] }

func anonymousLane(t *testing.T, pace int, source func(*http.Request) string) registrytokenwire.BuildConfig {
	t.Helper()
	cfg := laneWithoutSigner()
	cfg.Signer = lanesigner.New(t)
	cfg.AnonymousClientID = "registry-anonymous"
	cfg.AnonymousPerSourcePerSec = pace
	cfg.Source = source
	return cfg
}

func TestBuild_AnonymousLaneRefusesWithoutItsPaceOrSource(t *testing.T) {
	for name, cfg := range map[string]registrytokenwire.BuildConfig{
		"темп ноль":             anonymousLane(t, 0, peerOf),
		"темп отрицательный":    anonymousLane(t, -1, peerOf),
		"правила источника нет": anonymousLane(t, 5, nil),
	} {
		t.Run(name, func(t *testing.T) {
			if mux, err := registrytokenwire.Build(nil, cfg); err == nil {
				t.Fatalf("анонимный поток собран без предела чеканок на источник (mux=%v)", mux != nil)
			}
		})
	}
}

func TestBuild_AnonymousLaneCarriesItsPace(t *testing.T) {
	mux, err := registrytokenwire.Build(nil, anonymousLane(t, 1, peerOf))
	if err != nil {
		t.Fatalf("исправный анонимный поток не собран: %v", err)
	}
	pull := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath+"?service=registry.probe.local", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := pull("192.0.2.10:1"); code != http.StatusOK {
		t.Fatalf("первый анонимный вход источника: статус %d", code)
	}
	if code := pull("192.0.2.10:2"); code != http.StatusTooManyRequests {
		t.Fatalf("второй вход источника при темпе 1 в секунду: статус %d, ждали 429", code)
	}
	if code := pull("192.0.2.20:1"); code != http.StatusOK {
		t.Fatalf("другой источник в пределах темпа: статус %d", code)
	}
}

func TestBuild_WithoutTheAnonymousLaneNeedsNoPace(t *testing.T) {
	cfg := laneWithoutSigner()
	cfg.Signer = lanesigner.New(t)
	if _, err := registrytokenwire.Build(nil, cfg); err != nil {
		t.Fatalf("полоса без анонимного потока требует его темп: %v", err)
	}
}

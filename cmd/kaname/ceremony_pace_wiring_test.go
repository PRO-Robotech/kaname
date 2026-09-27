// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_pace_wiring_test.go — величины темпа поверхности выдачи доезжают из
// настройки до сборки, и страж старта требует режим слушателя выдачи
// (приёмка ceremony-pace-is-named-by-number.md, kaname#315: KN-PACE-02, 05).
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
)

// ceremonyPaceConfig — посадка KN-PACE-02 с числами, отличными от §3: число,
// совпавшее с константой где-то в сборке, не отличило бы переданное от
// подставленного.
func ceremonyPaceConfig() config.Config {
	var cfg config.Config
	cfg.AuthN.IdentityProvider = config.IdentityProviderOwn
	cfg.AuthN.ClientToken = config.ClientTokenConfig{
		Enabled:                  true,
		AllowedAudiences:         "registry.kacho.local",
		DefaultAudience:          "registry.kacho.local",
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		ExchangesPerClientPerSec: 7,
		InFlightCeiling:          33,
		FailedProofsPerSource:    51,
		FailedProofWindow:        16 * time.Minute,
		AuthorizePerSourcePerSec: 11,
		AuthorizeInFlightCeiling: 34,
	}
	return cfg
}

// KN-PACE-02, токен-эндпоинт: П1, П2 и П3 берутся из настройки.
func TestKNPACE02_TokenEndpointTakesItsPaceFromTheSettings(t *testing.T) {
	got := clientTokenBuildConfig(ceremonyPaceConfig(), "https://kaname.kacho.local", nil, nil, nil)
	if got.InFlightCeiling != 33 || got.ExchangesPerClientPerSec != 7 {
		t.Errorf("П1/П2 не дошли до сборки: %d/%d, ожидалось 33/7", got.InFlightCeiling, got.ExchangesPerClientPerSec)
	}
	if got.FailedProofsPerSource != 51 || got.FailedProofWindow != 16*time.Minute {
		t.Errorf("П3 не дошёл до сборки: %d за %s, ожидалось 51 за 16m", got.FailedProofsPerSource, got.FailedProofWindow)
	}
}

// KN-PACE-02, точка авторизации: П4 и П5 берутся из настройки.
func TestKNPACE02_AuthorizeEndpointTakesItsPaceFromTheSettings(t *testing.T) {
	rule := issuingsource.New(grpcsrv.NewTrustDomain("kacho.cloud"))
	got, err := ceremonyAuthorizePace(ceremonyPaceConfig(), rule, time.Now)
	if err != nil {
		t.Fatalf("сборка осей точки авторизации: %v", err)
	}
	if got.Pace == nil || got.Pace.PerSecond() != 11 {
		t.Errorf("П4 не дошёл до сборки: %v, ожидалось 11 в секунду", got.Pace)
	}
	if got.InFlightCeiling != 34 {
		t.Errorf("П5 не дошёл до сборки: %d, ожидалось 34", got.InFlightCeiling)
	}
	if got.Source == nil {
		t.Error("правило адреса источника не дошло до точки авторизации")
	}
}

// KN-PACE-05 — церемония при слушателе выдачи без запроса сертификата: отказ
// старта с ключом и требуемым значением. Строки — server-tls-only, mutual,
// незаданный режим; близнец — optional-mutual и посадка без церемонии.
func TestKNPACE05_CeremonyRefusesAListenerThatDoesNotAskForACertificate(t *testing.T) {
	const knob = "KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE"
	listener := func(mode string) config.MTLSConfig {
		var m config.MTLSConfig
		m.RegistryTokenServerMTLS = grpcsrv.TLSServer{Enable: true, CertFile: "/tls/tls.crt", KeyFile: "/tls/tls.key",
			ClientCAFiles: []string{"/tls/ca.crt"}}
		m.RegistryTokenClientAuthMode = mode
		return m
	}
	for _, mode := range []string{"server-tls-only", "mutual", ""} {
		t.Run("режим "+mode, func(t *testing.T) {
			err := requireIssuingListenerAsksForACertificate(ceremonyPaceConfig(), listener(mode))
			if err == nil {
				t.Fatal("церемония на слушателе без запроса сертификата стартовала")
			}
			for _, want := range []string{knob, "optional-mutual"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q: %v", want, err)
				}
			}
		})
	}
	t.Run("близнец: optional-mutual", func(t *testing.T) {
		if err := requireIssuingListenerAsksForACertificate(ceremonyPaceConfig(), listener("optional-mutual")); err != nil {
			t.Errorf("законный режим отвергнут: %v", err)
		}
	})
	t.Run("близнец: церемонии нет", func(t *testing.T) {
		cfg := ceremonyPaceConfig()
		cfg.AuthN.IdentityProvider = config.IdentityProviderExternal
		if err := requireIssuingListenerAsksForACertificate(cfg, listener("server-tls-only")); err != nil {
			t.Errorf("без церемонии режим слушателя не судится: %v", err)
		}
	})
}

// Страж режима и правило источника провязаны корнем: сборка поверхности выдачи
// получает ОДНО правило на обе точки, и его перепись выходит на витрину.
func TestServeWiresTheIssuingSourceRuleAndItsGuard(t *testing.T) {
	src := readFileT(t, "serve.go")
	for _, want := range []string{
		"requireIssuingListenerAsksForACertificate(cfg, mtlsCfg)",
		"issuingsource.New(cfg.AuthN.TrustDomain())",
		"metricsReg.NewIssuingSourceFallbackCollector(",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: нет %q", want)
		}
	}
}

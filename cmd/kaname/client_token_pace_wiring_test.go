// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_token_pace_wiring_test.go — величины темпа токен-эндпоинта доезжают
// из настройки до сборки (kaname#315).
//
// Страж настройки требует величину, сборка её исполняет; между ними стоит
// композиционный корень, и если он величину не передаёт, обе стороны зелены
// по своим пробам, а эндпоинт работает на том, что подставит сборка, — то есть
// не собирается вовсе либо ограничивает не тем числом.
package main

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestClientTokenPaceValuesReachTheEndpointBuild(t *testing.T) {
	var cfg config.Config
	cfg.AuthN.ClientToken = config.ClientTokenConfig{
		Enabled:                  true,
		AllowedAudiences:         "registry.kacho.local",
		DefaultAudience:          "registry.kacho.local",
		TokenTTL:                 15 * time.Minute,
		BodyCeiling:              64 << 10,
		ExchangesPerClientPerSec: 7,
		InFlightCeiling:          33,
	}

	got := clientTokenBuildConfig(cfg, "https://kaname.kacho.local", nil)
	if got.ExchangesPerClientPerSec != 7 {
		t.Fatalf("темп на клиента из настройки не дошёл до сборки: %d, ожидалось 7", got.ExchangesPerClientPerSec)
	}
	if got.InFlightCeiling != 33 {
		t.Fatalf("потолок одновременных из настройки не дошёл до сборки: %d, ожидалось 33", got.InFlightCeiling)
	}
	// Контроль соседей: переход не подменяет прочие величины эндпоинта.
	if got.BodyCeiling != 64<<10 || got.TokenTTL != 15*time.Minute || got.ExpectedAudience != "https://kaname.kacho.local" {
		t.Fatalf("прочие величины эндпоинта искажены переходом: %+v", got)
	}
}

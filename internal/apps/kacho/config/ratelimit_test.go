// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// ratelimit_test.go — ключи потолка допуска в файле настроек ДОЕЗЖАЮТ до полей.
//
// # Почему без этой пробы опечатка в ключе молчит
//
// Незаданная секция означает ПОЛ ПЛАТФОРМЫ, и это правильно. Цена правильного
// умолчания — что опечатка в ключе (`rate-limits` вместо `rate-limit`,
// `in-flight-limit` вместо `in-flight`) выглядит В ТОЧНОСТИ как «посадка не
// переопределяла»: viper незнакомый ключ просто игнорирует, поле остаётся нулём,
// подставляется пол, процесс поднимается и пишет в журнал взведённый потолок.
// Ручка объявлена, задокументирована — и задать её нельзя ни при каком вводе.
//
// У iam цена ошибки выше, чем у соседей: он стоит на пути запроса ВСЕХ доменов
// (решение о доступе спрашивают у него на каждом RPC), поэтому потолок, который
// нельзя подвинуть посадкой, — это потолок всей платформы.

import (
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// rateLimitShapedConfig — форма YAML, которой посадка объявляет свои величины.
const rateLimitShapedConfig = `
api-server:
  rate-limit:
    public:
      read-per-sec: 7
      mutation-per-sec: 3
      burst-factor: 2
      in-flight: 5
    internal:
      read-per-sec: 70
      mutation-per-sec: 30
      burst-factor: 4
      in-flight: 50
`

// TestRateLimitFileKeysArmTheFields — восемь ключей доезжают, и слушатели
// читают РАЗНЫЕ ключи.
func TestRateLimitFileKeysArmTheFields(t *testing.T) {
	cfg, err := config.Load(writeConfig(t, rateLimitShapedConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.APIServer.RateLimit.Public; got.ReadPerSec != 7 || got.MutationPerSec != 3 ||
		got.BurstFactor != 2 || got.InFlight != 5 {
		t.Fatalf("группа публичного слушателя не доехала из файла: %+v\n\n"+
			"Опечатка в ключе неотличима от «посадка молчит»: поле остаётся нулём, "+
			"подставляется пол платформы, и ручка не работает ни при каком вводе", got)
	}
	if got := cfg.APIServer.RateLimit.Internal; got.ReadPerSec != 70 || got.MutationPerSec != 30 ||
		got.BurstFactor != 4 || got.InFlight != 50 {
		t.Fatalf("группа внутреннего слушателя не доехала из файла: %+v", got)
	}
	if cfg.APIServer.RateLimit.Public == cfg.APIServer.RateLimit.Internal {
		t.Fatalf("обе группы прочитали одно и то же (%+v) — значит ключи совпали, и посадка не "+
			"может задать слушателям разные величины", cfg.APIServer.RateLimit.Public)
	}
}

// TestRateLimitDefaultsToSilent — законный близнец: без секции ручки МОЛЧАТ,
// то есть композиционный корень подставит пол платформы.
func TestRateLimitDefaultsToSilent(t *testing.T) {
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.APIServer.RateLimit.Public.IsSilent() || !cfg.APIServer.RateLimit.Internal.IsSilent() {
		t.Fatalf("незаданные ручки не молчат (public=%+v internal=%+v)",
			cfg.APIServer.RateLimit.Public, cfg.APIServer.RateLimit.Internal)
	}
}

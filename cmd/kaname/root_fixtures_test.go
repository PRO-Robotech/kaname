// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// root_fixtures_test.go — общие подпорки проб корня: боевая настройка корня и
// немой журнал. Прежде они жили в пробе дороги к внешнему поставщику, которая
// снята вместе с посадкой этого поставщика (kaname#363); пробы, которым нужна
// настройка корня, берут её отсюда.
package main

import (
	"io"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// productionRootCfg — боевая настройка корня с доменом установки и адресом
// зеркала проверочных ключей. Ключа посадки в ней нет: посадка у службы одна.
func productionRootCfg(jwksEndpoint string) config.Config {
	cfg := config.Config{}
	cfg.AuthN.Mode = config.ModeProduction
	cfg.AuthN.Domain = "kaname.test"
	cfg.APIServer.JWKSProxy.Endpoint = jwksEndpoint
	return cfg
}

// quietLogger — журнал, который ничего не пишет: пробам корня нужен приёмник,
// а не вывод.
func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

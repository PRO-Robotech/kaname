// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// restfrontlimits.go — величины потолков публичного REST-фронта из настройки
// (kaname#990). Механизм — `internal/restfront/limits.go`, величины и страж —
// `internal/apps/kaname/config/rest_limits.go`; здесь — их стык, одной
// функцией, чтобы проба судила ТО, что уходит во фронт.

import (
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/restfront"
)

// restFrontLimits — действующие потолки публичного фронта.
func restFrontLimits(cfg config.Config) restfront.Limits {
	eff := cfg.APIServer.RESTLimits.Effective()
	return restfront.Limits{MaxBodyBytes: eff.MaxBodyBytes, MaxInFlight: eff.MaxInFlight}
}

// logRESTFrontLimits печатает действующие потолки ВСЕГДА: посадка обязана быть
// видна в журнале, а снятый потолок — назван словом, а не нулём, который
// читается как «не напечатали».
func logRESTFrontLimits(logger *slog.Logger, l restfront.Limits) {
	logger.Info("rest front limits armed",
		"max_body_bytes", l.MaxBodyBytes,
		"max_in_flight", l.MaxInFlight,
		"body_ceiling_off", l.MaxBodyBytes == 0,
		"in_flight_ceiling_off", l.MaxInFlight == 0)
}

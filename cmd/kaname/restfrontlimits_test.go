// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/restfront"
)

// Объявленные величины уезжают во фронт своим значением, молчание — умолчанием
// (kaname#990).
func TestRESTFrontLimits_ComeFromTheProfile(t *testing.T) {
	body, inflight := int64(4096), 9
	var cfg config.Config
	cfg.APIServer.RESTLimits = config.RESTLimitsConfig{MaxBodyBytes: &body, MaxInFlight: &inflight}
	if got := restFrontLimits(cfg); got != (restfront.Limits{MaxBodyBytes: 4096, MaxInFlight: 9}) {
		t.Fatalf("объявленные потолки не доехали до фронта: %+v", got)
	}
	want := restfront.Limits{MaxBodyBytes: config.DefaultRESTMaxBodyBytes, MaxInFlight: config.DefaultRESTMaxInFlight}
	if got := restFrontLimits(config.Config{}); got != want {
		t.Fatalf("молчание посадки дало %+v, ожидались умолчания %+v", got, want)
	}
}

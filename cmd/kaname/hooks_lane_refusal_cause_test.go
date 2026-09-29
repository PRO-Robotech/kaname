// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_lane_refusal_cause_test.go — ОТКАЗ СБОРКИ ПОЛОС ВЫДАЧИ ДОХОДИТ ДО
// СТАРТА ЗНАЧЕНИЕМ (задача PRO-Robotech/kaname#440).
//
// Сборка полосы вебхуков (`buildHooksMux`) возвращает отказ сборки полос выдачи
// ошибкой, а построитель поверхности корня (`hooksLaneSurface`) отказывает
// старту С ЭТОЙ ПРИЧИНОЙ. Прежде причина становилась строкой журнала и пустым
// обработчиком, а отказ старта выводился из отсутствия обработчика — вызывающий
// получал «обслуживать нечем», а не то, что сломалось.
//
// Отказ подаётся на ШОВ КОРНЯ — замыкание сборки, которое корень передаёт
// построителю (`serve.go`). Изнутри `buildHooksMux` он сегодня не достижим:
// единственная причина отказа сборки полос — непоказательный предел вызова, а
// предел — константа (`credentialLanePeerTimeout`). Близнец идёт через
// НАСТОЯЩУЮ сборку `buildHooksMux`: без отказа поверхность поднимается.

import (
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// errLanesRefusedForProbe — отказ сборки полос выдачи, поданный пробой.
var errLanesRefusedForProbe = errors.New("полосы хука выдачи: предел вызова не положителен (поданный пробой отказ)")

func TestIssuanceLanesAssemblyRefusalReachesTheStartWithItsCause(t *testing.T) {
	cfg := roadCfg(config.IdentityProviderExternal, "9097")
	cfg.AuthN.HooksHTTPEndpoint = "tcp://0.0.0.0:9092"
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS13}

	built := 0
	_, err := hooksLaneSurface(cfg, servicecontract.ModeProduction, quietLogger(), tlsCfg,
		func() (http.Handler, error) {
			built++
			return nil, errLanesRefusedForProbe
		})
	if built != 1 {
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: под внешним поставщиком сборка полосы позвана %d раз(а), ожидался один", built)
	}
	if err == nil {
		t.Fatal("отказ сборки полос выдачи не остановил старт: поверхность вебхуков построилась")
	}
	if !errors.Is(err, errLanesRefusedForProbe) {
		t.Errorf("отказ старта не несёт отказа сборки полос значением (errors.Is ложно): %v", err)
	}
	if !strings.Contains(err.Error(), errLanesRefusedForProbe.Error()) {
		t.Errorf("текст отказа старта не называет причину сборки полос: %q", err.Error())
	}

	// Близнец: НАСТОЯЩАЯ сборка корня, отказа нет — поверхность строится и
	// поднимается.
	desc, err := hooksLaneSurface(cfg, servicecontract.ModeProduction, quietLogger(), tlsCfg,
		func() (http.Handler, error) {
			return buildHooksMux(nil, nil, nil, nil, metrics.NewRegistry(), cfg, quietLogger())
		})
	if err != nil || !desc.Enabled() {
		t.Fatalf("законный близнец: настоящая сборка без отказа обязана подниматься, err=%v", err)
	}
}

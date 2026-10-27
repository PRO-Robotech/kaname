// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"strings"
	"testing"
)

// buildFlavorCase — один вход стража сборки.
type buildFlavorCase struct {
	name      string
	mode      Mode
	trustAny  bool
	testBuild bool
	refused   []string // подстроки отказа; пусто — отказа нет
}

// TestBuildFlavorGuard_ReleaseBuildRefusesEveryCallerCheckRelaxation —
// kaname#985: выпускная сборка отвергает режим разработки и опт-ин «круг
// отправителей не сужаем», в каком бы режиме ни стоял второй; тестовая сборка
// пропускает оба; боевой режим без послаблений проходит любую сборку.
//
// Каждая строка меняет против законного близнеца («выпуск, боевой режим, без
// опт-ина») РОВНО ОДИН факт.
func TestBuildFlavorGuard_ReleaseBuildRefusesEveryCallerCheckRelaxation(t *testing.T) {
	for _, tc := range []buildFlavorCase{
		{name: "близнец: выпуск, боевой режим", mode: ModeProduction},
		{name: "близнец: выпуск, строгий боевой режим", mode: ModeProductionStrict},
		{name: "выпуск, режим разработки", mode: ModeDev,
			refused: []string{"authn.mode", "dev", "release build", "kaname_testbuild"}},
		{name: "выпуск, боевой режим, опт-ин круга", mode: ModeProduction, trustAny: true,
			refused: []string{"authn.trust-any-forwarder", "release build", "kaname_testbuild"}},
		{name: "близнец: тестовая сборка, режим разработки", mode: ModeDev, testBuild: true},
		{name: "близнец: тестовая сборка, опт-ин круга", mode: ModeDev, trustAny: true, testBuild: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Config
			c.AuthN.Mode = tc.mode
			c.AuthN.TrustAnyForwarder = tc.trustAny
			err := c.validateBuildFlavor(tc.testBuild)
			if len(tc.refused) == 0 {
				if err != nil {
					t.Fatalf("законный вход отвергнут: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("выпускная сборка приняла послабление проверки вызывающих (режим %s, опт-ин круга %v)",
					tc.mode, tc.trustAny)
			}
			for _, want := range tc.refused {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q: %v", want, err)
				}
			}
		})
	}
}

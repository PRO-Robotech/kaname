// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// withdrawn_posture_rows_test.go — документ оператора не требует величин
// посадки, которую нельзя объявить (#424).
//
// Посадка `external` снята фундаментом (PRO-Robotech/corelib#30): разбор её не
// производит, а число мимо разбора отвергает проверка старта. Строка таблицы,
// обязательная только на ней, оператору не нужна ни на одной объявимой
// посадке, и печатать её в перечне обязательных значило бы требовать величину,
// без которой служба поднимается.
//
// Законный близнец — та же строка на посадке `own`: она печатается.
package operatordocs

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func withdrawnProbeRow(lanes []config.IdentityProvider) config.RequiredSetting {
	return config.RequiredSetting{
		Key:     "authn.probe-withdrawn-lane-knob",
		Env:     "KANAME_AUTHN__PROBE_WITHDRAWN_LANE_KNOB",
		Supply:  config.SupplyEnv,
		Lanes:   lanes,
		Sample:  "value",
		Why:     "проба строки полосы",
		Refusal: "authn.probe-withdrawn-lane-knob",
	}
}

func TestSettingsBlockLeavesOutARowRequiredOnlyOnAWithdrawnPosture(t *testing.T) {
	row := withdrawnProbeRow([]config.IdentityProvider{config.IdentityProviderExternal})
	if !row.OnlyOnWithdrawnPostures() {
		t.Fatal("предпосылка: строка случая обязательна только на снятой посадке")
	}
	block, findings, census := BuildSettingsBlock([]config.RequiredSetting{row, withdrawnProbeRow(nil)})
	if len(findings) != 0 {
		t.Fatalf("находки на законной таблице: %v", findings)
	}
	if n := strings.Count(block, "`"+row.Key+"`"); n != 1 {
		t.Fatalf("строк с ключом %q в блоке %d, ожидалась 1 — только строка «на любой посадке»; "+
			"строка снятой посадки печататься не должна:\n%s", row.Key, n, block)
	}
	if strings.Contains(block, "identity-provider(") {
		t.Fatalf("блок называет посадку числом вне словаря:\n%s", block)
	}
	t.Logf("перепись: %s", census)
}

// Законный близнец: та же строка на посадке из словаря печатается.
func TestSettingsBlockKeepsTheSameRowOnALegalPosture(t *testing.T) {
	row := withdrawnProbeRow([]config.IdentityProvider{config.IdentityProviderOwn})
	if row.OnlyOnWithdrawnPostures() {
		t.Fatal("предпосылка: строка случая обязательна на законной посадке")
	}
	block, _, _ := BuildSettingsBlock([]config.RequiredSetting{row})
	if !strings.Contains(block, "`"+row.Key+"`") {
		t.Fatalf("строка законной посадки из блока пропала:\n%s", block)
	}
}

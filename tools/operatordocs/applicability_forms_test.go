// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// applicability_forms_test.go — столбец «Когда обязателен» порождённого блока
// несёт ТОЛЬКО формы закрытого словаря (kaname#363).
//
// Столбец разбирает не только человек: проба платформы читает его у пиненной
// службы и на незнакомой форме отказывает. Поэтому форма — контракт между
// репозиториями, и расширение словаря должно быть видно здесь, а не на
// подъёме пина. Прежде форм было три и две называли посадку личности; посадка
// у службы одна, и форм две.
//
// Утверждения три, и у каждого своя половина:
//
//	С1  каждая строка блока несёт одну из двух форм — перепись строк блока;
//	С2  безусловная строка печатается формой «всегда», условная — «при
//	    выполненном условии»; законный близнец — действующая таблица;
//	С3  перепись генератора сходится: «всегда» + «при условии» = строк.
package operatordocs

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// applicabilityColumn — третий столбец каждой строки таблицы блока.
func applicabilityColumn(t *testing.T, block string) []string {
	t.Helper()
	var out []string
	for _, line := range strings.Split(block, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		cells := strings.Split(line, " | ")
		if len(cells) < 4 {
			t.Fatalf("строка блока без четырёх столбцов: %q", line)
		}
		out = append(out, cells[2])
	}
	return out
}

func probeRow(conditional bool) config.RequiredSetting {
	return config.RequiredSetting{
		Key:         "authn.probe-applicability-knob",
		Env:         "KANAME_AUTHN__PROBE_APPLICABILITY_KNOB",
		Supply:      config.SupplyEnv,
		Conditional: conditional,
		Sample:      "value",
		Why:         "проба столбца применимости",
		Refusal:     "authn.probe-applicability-knob",
	}
}

// С1 + С3 на действующей таблице.
func TestSettingsBlockApplicabilityColumnIsAClosedVocabulary(t *testing.T) {
	block, findings, census := BuildSettingsBlock(config.RequiredSettings)
	if len(findings) != 0 {
		t.Fatalf("находки на действующей таблице: %v", findings)
	}
	forms := map[string]int{}
	for _, when := range applicabilityColumn(t, block) {
		forms[when]++
	}
	rows := 0
	for form, n := range forms {
		switch form {
		case config.ApplicabilityAlways, config.ApplicabilityConditional:
			rows += n
		default:
			t.Errorf("форма столбца вне закрытого словаря: %q (%d строк)", form, n)
		}
	}
	t.Logf("перепись: строк блока %d · «%s» %d · «%s» %d · форм вне словаря %d",
		rows, config.ApplicabilityAlways, forms[config.ApplicabilityAlways],
		config.ApplicabilityConditional, forms[config.ApplicabilityConditional], len(forms)-2)
	if rows == 0 {
		t.Fatal("обход пуст: в блоке нет ни одной строки таблицы")
	}
	if rows != len(config.RequiredSettings) {
		t.Errorf("строк блока %d, строк таблицы %d — строка потерялась либо удвоилась", rows, len(config.RequiredSettings))
	}
	if census.Always+census.Condition != census.Rows {
		t.Errorf("перепись генератора не сходится: «всегда» %d + «при условии» %d ≠ строк %d",
			census.Always, census.Condition, census.Rows)
	}
}

// С2: форма выводится из условности строки, и только из неё.
func TestSettingsBlockPrintsTheFormOfTheRowsConditionality(t *testing.T) {
	for _, tc := range []struct {
		conditional bool
		want        string
	}{
		{false, config.ApplicabilityAlways},
		{true, config.ApplicabilityConditional},
	} {
		block, findings, _ := BuildSettingsBlock([]config.RequiredSetting{probeRow(tc.conditional)})
		if len(findings) != 0 {
			t.Fatalf("находки на законной строке: %v", findings)
		}
		got := applicabilityColumn(t, block)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("условная=%v: столбец %v, ожидалась форма %q", tc.conditional, got, tc.want)
		}
	}
}

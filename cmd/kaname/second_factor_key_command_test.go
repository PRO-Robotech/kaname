// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// second_factor_key_command_test.go — что оператор ЧИТАЕТ у команды
// second-factor-key (kaname#259 п.3): разбор вызова и стражи до первого
// соединения, строка исхода и код возврата по каждому исходу прохода. Путь до
// хранилища и сам проход судят пробы сквозь поверхность
// (second_factor_key_command_integration_test.go).

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/secondfactorwrap"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// sfKeyHex — ключ обёртки пробы: 32 байта одного значения в hex.
func sfKeyHex(b byte) string {
	const digits = "0123456789abcdef"
	return strings.Repeat(string([]byte{digits[b>>4], digits[b&0x0f]}), 32)
}

// sfCommandCfgAt — посадка own с перечнем ключей обёртки над базой по адресу.
func sfCommandCfgAt(dsn string, ring ...byte) config.Config {
	cfg := postureCfg(config.ModeDev, "disable")
	cfg.Repository.Postgres.URL = dsn
	cfg.AuthN.IdentityProvider = config.IdentityProviderOwn
	keys := make([]string, 0, len(ring))
	for _, k := range ring {
		keys = append(keys, sfKeyHex(k))
	}
	cfg.AuthN.SecondFactorEncryptionKeyHex = strings.Join(keys, ",")
	return cfg
}

func runSFKey(t *testing.T, cfg config.Config, args ...string) (int, string) {
	t.Helper()
	var out bytes.Buffer
	code := runSecondFactorKeyCommand(context.Background(), cfg, args, &out, quietLogger())
	return code, out.String()
}

// TestSecondFactorKeyCommand_ACallThatDoesNotParseNeverReachesTheStore — вызов
// без действия, с чужим действием и с лишним аргументом — «не исполнялось» с
// перечнем действий, и до базы он не доходит. Близнец — тот же вызов с
// названным действием: он доходит до базы, которой по адресу нет.
func TestSecondFactorKeyCommand_ACallThatDoesNotParseNeverReachesTheStore(t *testing.T) {
	cfg := sfCommandCfgAt("postgres://u:p@"+closedStoreAddress(t)+"/kaname", 2, 1)
	for name, args := range map[string][]string{
		"без действия":    nil,
		"чужое действие":  {"rotate"},
		"лишний аргумент": {"rewrap", "now"},
		"чужой флаг":      {"rewrap", "-batch=5"},
	} {
		t.Run(name, func(t *testing.T) {
			code, out := runSFKey(t, cfg, args...)
			require.Equal(t, secondFactorKeyExitNotRun, code, "вывод: %s", out)
			require.Contains(t, out, "kaname second-factor-key rewrap", "вывод называет вызов")
			require.NotContains(t, out, "база:", "неразобранный вызов не доходит до базы")
		})
	}
	t.Run("близнец: действие названо", func(t *testing.T) {
		code, out := runSFKey(t, cfg, "rewrap")
		require.Equal(t, secondFactorKeyExitNotRun, code, "вывод: %s", out)
		require.Contains(t, out, "база:", "разобранный вызов доходит до базы")
	})
}

// TestSecondFactorKeyCommand_AnUndeclaredRingIsRefusedByItsKnobBeforeTheStore —
// перечень ключей обёртки не задан — «не исполнялось» с именем ручки и
// переменной; до базы команда не доходит: проход без ключей не открыл бы
// ничего. Посадка без полосы входа — тоже «не исполнялось»: второго фактора
// там нет, и секретов под этим перечнем служба не держит.
func TestSecondFactorKeyCommand_AnUndeclaredRingIsRefusedByItsKnobBeforeTheStore(t *testing.T) {
	dsn := "postgres://u:p@" + closedStoreAddress(t) + "/kaname"

	t.Run("перечень не задан", func(t *testing.T) {
		cfg := sfCommandCfgAt(dsn)
		cfg.AuthN.SecondFactorEncryptionKeyHexEnv = "KANAME_PROBE_SF_KEY_UNSET"
		code, out := runSFKey(t, cfg, "rewrap")
		require.Equal(t, secondFactorKeyExitNotRun, code, "вывод: %s", out)
		require.Contains(t, out, "authn.second-factor-encryption-key-hex")
		require.Contains(t, out, "KANAME_PROBE_SF_KEY_UNSET")
		require.NotContains(t, out, "база:")
	})
	t.Run("посадка без полосы входа", func(t *testing.T) {
		cfg := sfCommandCfgAt(dsn, 2, 1)
		cfg.AuthN.IdentityProvider = config.IdentityProviderUnset
		code, out := runSFKey(t, cfg, "rewrap")
		require.Equal(t, secondFactorKeyExitNotRun, code, "вывод: %s", out)
		require.Contains(t, out, config.IdentityProviderSetting)
		require.NotContains(t, out, "база:")
	})
	t.Run("близнец: перечень задан на own", func(t *testing.T) {
		code, out := runSFKey(t, sfCommandCfgAt(dsn, 2, 1), "rewrap")
		require.Equal(t, secondFactorKeyExitNotRun, code, "вывод: %s", out)
		require.Contains(t, out, "база:")
	})
}

// TestReportSecondFactorRewrap_EachOutcomeHasItsCodeAndItsCounts — строка
// исхода называет все счёты всегда, включая нули; код различает три мира:
// «каждый секрет под первым ключом» · «проход прошёл, но не всё переехало» ·
// «проход не доведён». Совет снимать прежние ключи печатается ТОЛЬКО в первом.
func TestReportSecondFactorRewrap_EachOutcomeHasItsCodeAndItsCounts(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rep     secondfactorwrap.Report
		err     error
		code    int
		outcome string
		has     []string
		hasNot  []string
	}{
		{
			name: "всё под первым ключом", rep: secondfactorwrap.Report{Rows: 4, Rewrapped: 3, Current: 1},
			code: secondFactorKeyExitDone, outcome: "outcome=done",
			has: []string{"keys=2", "rows=4", "rewrapped=3", "current=1", "unreadable=0", "vanished=0", "unsettled=0", "снимаются из перечня"},
		},
		{
			name: "нечитаемые остались", rep: secondfactorwrap.Report{Rows: 4, Rewrapped: 2, Unreadable: 2},
			code: secondFactorKeyExitPartial, outcome: "outcome=partial",
			has: []string{"unreadable=2", "ни один ключ перечня"}, hasNot: []string{"снимаются из перечня"},
		},
		{
			name: "не устоялось", rep: secondfactorwrap.Report{Rows: 1, Unsettled: 1},
			code: secondFactorKeyExitPartial, outcome: "outcome=partial",
			has: []string{"unsettled=1", "повторите"}, hasNot: []string{"снимаются из перечня"},
		},
		{
			name: "хранилище отказало посреди", rep: secondfactorwrap.Report{Rows: 3, Rewrapped: 2},
			err:  iamerr.Wrapf(iamerr.ErrUnavailable, "LoginMethod.SwapTOTPSecret: connection reset"),
			code: secondFactorKeyExitNotRun, outcome: "outcome=not-run",
			has: []string{"rewrapped=2", "connection reset", "повторите"}, hasNot: []string{"снимаются из перечня"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportSecondFactorRewrap(&out, 2, tc.rep, tc.err)
			require.Equal(t, tc.code, code, "вывод: %s", out.String())
			require.Contains(t, out.String(), tc.outcome)
			for _, s := range tc.has {
				require.Contains(t, out.String(), s)
			}
			for _, s := range tc.hasNot {
				require.NotContains(t, out.String(), s)
			}
		})
	}
}

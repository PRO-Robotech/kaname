// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// authn_mode_log_test.go — строка о штатной боевой посадке пишется INFO, а не
// WARN, в обоих боевых режимах (задача #610, попутный предмет).
//
// Боевая посадка — штатное состояние, а не отклонение: WARN на каждом старте
// приучает оператора не читать WARN вовсе, и настоящее предупреждение тонет в
// строке, которая предупреждает о норме.

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

func TestAuthnModeLineIsInfoInEveryProductionMode(t *testing.T) {
	for _, tc := range []struct {
		mode config.Mode
		says string
	}{
		{config.ModeProduction, "authn.mode=production:"},
		{config.ModeProductionStrict, "authn.mode=production-strict:"},
	} {
		t.Run(tc.says, func(t *testing.T) {
			var buf bytes.Buffer
			logAuthnMode(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), tc.mode)

			var found int
			for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				var rec map[string]any
				require.NoError(t, json.Unmarshal([]byte(ln), &rec), "запись не разобрана: %s", ln)
				require.NotEqual(t, "WARN", rec["level"], "строка о штатной посадке пишется WARN: %s", ln)
				if strings.HasPrefix(rec["msg"].(string), tc.says) {
					require.Equal(t, "INFO", rec["level"])
					found++
				}
			}
			// Положительный контроль: строка о режиме ЕСТЬ — иначе «ни одного WARN»
			// выполнялось бы на пустом журнале.
			require.Equal(t, 1, found, "строка о режиме не написана: %q", buf.String())
		})
	}
}

// TestAuthnModeLineIsSilentInDev — в режиме разработки строки о боевой посадке
// нет: её предупреждения пишет InsecureDevWarnings, и второй строки о том же нет.
func TestAuthnModeLineIsSilentInDev(t *testing.T) {
	var buf bytes.Buffer
	logAuthnMode(slog.New(slog.NewJSONHandler(&buf, nil)), config.ModeDev)
	require.Empty(t, buf.String())
}

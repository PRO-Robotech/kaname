// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// bootstrap_admin_task_test.go — kaname#631: строка о старте посева первого
// администратора называет администратора признаком «адрес задан», без адреса,
// на любом уровне журнала. Ветка «не задан» по-прежнему говорит, что посев
// выключен, и согласователя не зовёт.

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBootstrapAdminTaskLogsNoAddress(t *testing.T) {
	const (
		local      = "piilocalcmdtask"
		domainPart = "piidomaincmdtask.test"
		addr       = local + "@" + domainPart
	)
	for _, tc := range []struct {
		name    string
		email   string
		wantMsg string
		wantRun bool
	}{
		{name: "address_set", email: addr, wantMsg: "bootstrap admin reconciler starting", wantRun: true},
		{name: "address_unset", email: "", wantMsg: "bootstrap admin disabled", wantRun: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			ran := false
			err := bootstrapAdminTask(logger, tc.email, func() error { ran = true; return nil })()
			require.NoError(t, err)
			require.Equal(t, tc.wantRun, ran, "согласователь зовётся ровно тогда, когда адрес задан")
			logged := buf.String()
			require.Containsf(t, logged, tc.wantMsg,
				"НЕ-ВЫПОЛНИЛОСЬ: сообщение ветки не записано — «адреса нет» было бы «журнала нет»")
			low := strings.ToLower(logged)
			for _, part := range []string{addr, local, domainPart} {
				require.NotContainsf(t, low, strings.ToLower(part),
					"ветка %q: журнал старта посева несёт адрес администратора\n--- журнал ---\n%s", tc.name, logged)
			}
			if tc.wantRun {
				require.Contains(t, logged, "bootstrap_address=set",
					"администратор назван признаком «адрес задан»")
			}
		})
	}
}

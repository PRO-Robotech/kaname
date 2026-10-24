// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// main_test.go — разбор доводов: всякий вход, по которому судить нечем, —
// «условие не создано» (код 2), а не проход.

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/clagate"
)

func TestRun_InputWithoutASubjectIsUnmet(t *testing.T) {
	for name, args := range map[string][]string{
		"режим не назван":  nil,
		"режим неизвестен": {"history"},
		"remote не назван": {"push-range"},
		"лишний довод":     {"push-range", "--remote", "origin", "refs/heads/main"},
		"неизвестный флаг": {"push-range", "--remote", "origin", "--skip"},
	} {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			code := run(args, strings.NewReader(""), &out)
			require.Equal(t, clagate.ExitUnmet, code, out.String())
		})
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate_failure_names_pairs_test.go — отказ стража КАЖДУЮ несошедшуюся пару
// называет поимённо, а не числом (задача #1865).
//
// # Предмет
//
// Страж печатал `failures: 2` и ни одной пары. Отношение, объект и субъект
// лежали в `Reason` и не выводились НИКОГДА — назвать по журналу, что именно не
// сошлось, было невозможно. Находка есть, читателя у неё нет.
//
// Страж некритичен by construction (`Warn` + продолжение), и это верно — он
// наблюдает, а не гейтит. Но наблюдение, не называющее предмета, наблюдением не
// является: на него тратят заход и НИЧЕГО не устанавливают.

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// captureLogger — журнал в память, разбираемый построчно как JSON.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})), &buf
}

// logLines разбирает захваченный журнал в записи.
func logLines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if strings.TrimSpace(ln) == "" {
			continue
		}
		var rec map[string]any
		require.NoError(t, json.Unmarshal([]byte(ln), &rec), "запись журнала не разобрана: %s", ln)
		out = append(out, rec)
	}
	return out
}

// TestVerifyGateFailureNamesEveryPair — при отказе журнал называет отношение,
// объект и субъект КАЖДОЙ несошедшейся пары.
func TestVerifyGateFailureNamesEveryPair(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_ok", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_bad1", Subject: "user:usr_b", Relation: "v_get", Object: "iam_role:rol_y"},
		{BindingID: "acb_bad2", Subject: "service_account:sac_c", Relation: "v_list", Object: "vpc_network:vpcn_z"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{"iam_user:usr_x": true}}

	logger, buf := captureLogger()
	gate := NewVerifyGate(panicEngine{}, store, logger).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	require.False(t, report.NoAccessLoss)
	require.Len(t, report.Failures, 2)

	text := buf.String()
	// Каждая пара названа ТРЕМЯ величинами. Число отказов остаётся — оно про
	// объём, а не про предмет, и одно другого не заменяет.
	for _, want := range []string{
		"acb_bad1", "user:usr_b", "v_get", "iam_role:rol_y",
		"acb_bad2", "service_account:sac_c", "v_list", "vpc_network:vpcn_z",
	} {
		assert.Contains(t, text, want,
			"журнал не называет %q — назвать несошедшуюся пару по журналу невозможно, "+
				"и наблюдение не наблюдает", want)
	}
	// Положительный контроль: сошедшаяся пара в журнале отказа НЕ значится —
	// иначе «называет каждую пару» вырождалось бы в «печатает всё подряд».
	assert.NotContains(t, text, "acb_ok",
		"журнал называет сошедшуюся пару — отказ обязан называть НЕсошедшиеся, а не всё подряд")

	// Величины стоят ПОЛЯМИ, а не только внутри прозы: разбирающий журнал
	// отбирает по полю, а не поиском подстроки в сообщении.
	named := 0
	for _, rec := range logLines(t, buf) {
		if rec["relation"] != nil && rec["object"] != nil && rec["subject"] != nil && rec["binding_id"] != nil {
			named++
		}
	}
	assert.Equal(t, 2, named,
		"записей, называющих пару полями (binding_id · relation · object · subject), %d — ждали 2 "+
			"по числу несошедшихся пар", named)
}

// TestVerifyGateSuccessStaysQuiet — положительный контроль второй оси: на
// сошедшемся прогоне записей об отказе нет вовсе.
func TestVerifyGateSuccessStaysQuiet(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_ok", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
	}}
	chk := &fakeRelChecker{allow: map[string]bool{"iam_user:usr_x": true}}

	logger, buf := captureLogger()
	gate := NewVerifyGate(panicEngine{}, store, logger).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)
	require.True(t, report.NoAccessLoss)
	assert.NotContains(t, buf.String(), "BLOCKED",
		"страж кричит на сошедшемся прогоне — проверка, кричащая всегда, перестаёт читаться")
}

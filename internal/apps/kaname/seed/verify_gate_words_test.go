// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate_words_test.go — слова отчёта равны действию, которое код совершает
// (#119).
//
// Здесь же стояли пробы остатка загрузочной дымовой пробы и владения её типом.
// Они СНЯТЫ ВМЕСТЕ С ПРЕДМЕТОМ: загрузочная дымовая проба снята, синтетического
// объекта не заводится, и утверждать об уборке за ним больше нечего. Оставить их
// ослабленными («проверим, что механизма нет») значило бы держать пробу, которая
// не может упасть.

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestRelationReportSaysWhatTheCodeDoes — слова отчёта равны действию (#119).
//
// Отчёт печатался как «catalog flip BLOCKED», тогда как действия «flip» в дереве
// нет ни одного: вызывающий журналирует вердикт и ничего не переключает. Оператор
// читает такой отчёт как сорванную выкатку и ищет поломку там, где её нет.
func TestRelationReportSaysWhatTheCodeDoes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		allow  bool
		absent []string
		says   string
	}{
		{
			name:   "находка",
			allow:  false,
			absent: []string{"flip", "cutover", "BLOCKED"},
			says:   "do NOT resolve",
		},
		{
			name:   "чисто",
			allow:  true,
			absent: []string{"flip", "cutover", "permitted"},
			says:   "resolves",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
			store := relCheckStore{checks: []BindingRelationCheck{{
				BindingID: domain.AccessBindingID("acb00000000000000wrd"),
				Subject:   "user:usr00000000000000wrd",
				Relation:  "v_get",
				Object:    "iam_group:grp00000000000000wrd",
			}}}
			gate := NewVerifyGate(nil, store, logger).
				WithRelationChecker(&fakeRelChecker{allow: map[string]bool{
					"iam_group:grp00000000000000wrd": tc.allow,
				}})

			_, err := gate.VerifyRelationSatisfiesAction(context.Background())
			require.NoError(t, err)

			out := buf.String()
			require.Contains(t, out, tc.says,
				"отчёт обязан называть то, что код СДЕЛАЛ: %s", out)
			for _, forbidden := range tc.absent {
				require.NotContains(t, out, forbidden,
					"отчёт обязан не обещать действия, которого код не совершает (%q): %s",
					forbidden, out)
			}
		})
	}
}

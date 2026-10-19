// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_remove_integration_test.go — СНЯТИЕ второго фактора на настоящей
// базе через обработчик полосы: тело ответа `remove` — ровно `session` и
// `assurance`, в обеих ветках (запасной код и код по времени); набора после
// снятия нет, и это отсутствие ключа `backupCodeSet`, а не нуль; `GET` того же
// человека — «не заведён», сводки нет.
//
// Приёмка `docs/engineering/acceptance/backup-code-set-has-one-form.md`
// (kaname#297), BCS-10, BCS-11, BCS-31; решение В-2: форма, выбранная по
// kaname#275 (`backupCodesRemaining: 0`), снята, его инвариант «остаток СНЯТОГО
// набора наружу не выходит» сохранён — ключей тела ровно два.
//
// # Почему настоящая база, а не дублёр
//
// Остаток набора считает `settle` над строкой набора ПОД ЗАМКОМ, а
// согласованность с `GET` — над той же строкой ПОСЛЕ снятия, одной транзакцией.
// Дублёр отдал бы объявленное и не показал бы, что набор снят: предмет пробы —
// исход над базой, а не проброс значения.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run TestBCS_RemoveCarriesNoSet -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"net/http"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// TestBCS_RemoveCarriesNoSet — BCS-10, BCS-11, BCS-31 (снятие): ключи тела ровно
// `session`, `assurance`; остатка снятого набора нет ни под каким ключом
// (инвариант kaname#275).
func TestBCS_RemoveCarriesNoSet(t *testing.T) {
	h := newSUAStand(t)
	for _, tc := range []struct{ id, method string }{{"BCS-10", "totp"}, {"BCS-11", "lookup_secret"}} {
		t.Run(tc.id, func(t *testing.T) {
			id := tc.id
			g := h.bcsSeed(t, "bcs-remove-"+tc.method)
			code := g.p.codes[0]
			if tc.method == "totp" {
				code = h.totpNow(t, g.p)
			}
			r := h.bcsConfirmed(t, g.s, loginlanehttp.PathSecondFactorRemove, tc.method, code)
			require.Equalf(t, http.StatusOK, r.status, "%s: %s", id, r.body)
			body := bodyOf(t, id, r)
			keys := make([]string, 0, len(body))
			for k := range body {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			require.Equalf(t, []string{"assurance", "session"}, keys, "%s: ключи тела ровно session, assurance", id)
			st := h.status(t, rotated(t, id, r, g.s))
			require.Equalf(t, false, requireDeclared(t, id, st, "totp.enrolled"), "%s: фактор снят", id)
			require.NotContainsf(t, st, bcsKeySet, "%s: ключа `backupCodeSet` нет", id)
		})
	}
}

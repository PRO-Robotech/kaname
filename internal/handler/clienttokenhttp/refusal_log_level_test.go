// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// refusal_log_level_test.go — отказ токен-эндпоинта клиента — ОДНА запись
// журнала ОБЪЯВЛЕННОГО уровня (задача kaname#390).
//
// Таблица уровней службы (`docs/engineering/components/32-observability.md`,
// «Уровни»): отклонённое предъявление — WARN; отказ критичного пути НАШЕЙ
// стороны — ERROR. Эндпоинт журналил оба уровнем WARN: недоступность реестра
// или хранилища однократности, срыв вопроса об отсечке и несостоявшийся выпуск
// стояли в одном ряду с неверной подписью предъявителя.
package clienttokenhttp_test

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

func TestRefusal_OneRecordOfTheDeclaredLevelPerOutcome(t *testing.T) {
	// Исходы, которые решает НЕ предъявитель: чинит их оператор. Записано
	// литералом — ожидание пробы не берётся у кода под пробой.
	ourSide := map[clientassertion.Outcome]bool{
		clientassertion.OutcomeRegistryUnavailable:    true,
		clientassertion.OutcomeReplayStoreUnavailable: true,
		clientassertion.OutcomeRevocationCheckFailed:  true,
		clientassertion.OutcomeIssuanceFailed:         true,
	}
	issuerSide := map[clientassertion.Outcome]bool{
		clientassertion.OutcomeAudienceNotAllowed:    true,
		clientassertion.OutcomeClientExpired:         true,
		clientassertion.OutcomeOwnerNotActive:        true,
		clientassertion.OutcomeOwnerRevoked:          true,
		clientassertion.OutcomeOwnerUnverified:       true,
		clientassertion.OutcomeRevocationCheckFailed: true,
		clientassertion.OutcomeIssuanceFailed:        true,
	}
	// Исходы, которые эндпоинт решает сам до проверки и до выдачи: своей
	// записи отказа у них нет — они считаются и отвечают своим кодом.
	notRefusals := map[clientassertion.Outcome]bool{
		clientassertion.OutcomeAccepted:               true,
		clientassertion.OutcomeMethodNotAllowed:       true,
		clientassertion.OutcomeBodyAboveCeiling:       true,
		clientassertion.OutcomeMalformedRequest:       true,
		clientassertion.OutcomeMultipleAssertions:     true,
		clientassertion.OutcomeUnsupportedGrantType:   true,
		clientassertion.OutcomeInFlightCeilingReached: true,
		clientassertion.OutcomeClientPaceExceeded:     true,
		clientassertion.OutcomeSourceFailuresExceeded: true,
	}
	var ran, errorLevel int
	for _, o := range clientassertion.Outcomes() {
		if notRefusals[o] {
			continue
		}
		t.Run(string(o), func(t *testing.T) {
			v, i := &stubVerifier{}, &stubIssuer{}
			if issuerSide[o] {
				i.outcome = o
			} else {
				v.outcome = o
			}
			var buf bytes.Buffer
			h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
				BodyCeiling:     testBodyCeiling,
				InFlightCeiling: testInFlightCeiling,
				FailedProofs:    testFailedProofs(t),
				Source:          peerHost,
				Logger:          slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
			}, v, i)
			require.NoError(t, err)
			s := stand{h: h, verifier: v, issuer: i}
			rec := s.post(t, goodForm())
			require.Equal(t, 401, rec.Code, "исход %s обязан быть отказом аутентификации", o)

			var lines []string
			for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				if l != "" {
					lines = append(lines, l)
				}
			}
			require.Lenf(t, lines, 1, "записей на один отказ %d, а не одна: %s", len(lines), buf.String())
			var r map[string]any
			require.NoError(t, json.Unmarshal([]byte(lines[0]), &r))
			want := slog.LevelWarn
			if ourSide[o] {
				want = slog.LevelError
			}
			require.Equalf(t, want.String(), r[slog.LevelKey], "исход %s: уровень записи не объявленный: %s", o, lines[0])
			require.Equal(t, string(o), r["outcome"], "запись не называет исход")
			require.NotContains(t, buf.String(), "header.payload.signature", "предъявленное утверждение в журнале")
		})
		ran++
		if ourSide[o] {
			errorLevel++
		}
	}
	t.Logf("перепись: исходов-отказов %d · из них нашей стороны %d", ran, errorLevel)
	require.Equal(t, len(ourSide), errorLevel, "исход нашей стороны вне словаря — перепись разошлась")
}

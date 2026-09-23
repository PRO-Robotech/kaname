// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// signing_key_command_test.go — что оператор ЧИТАЕТ в исходе команды
// signing-key (#314): строка исхода и код возврата по каждому исходу ключницы.
// Путь до ключницы судят пробы сквозь поверхность
// (signing_key_command_integration_test.go); здесь — только то, что команда
// говорит о полученном исходе.

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestReportSigningKeyOutcome_UnknownSignerIsNoVerdictAndDoesNotClaimAStoppedService —
// ключ снят, а подписывает ли служба, не установлено: исход говорит ровно это
// и отдаёт «вердикта нет», а не «служба не подписывает» с отказом по существу.
// Близнец — частичный исход: там «подписывающего нет» установлено чтением, и
// именно он называет службу неподписывающей.
func TestReportSigningKeyOutcome_UnknownSignerIsNoVerdictAndDoesNotClaimAStoppedService(t *testing.T) {
	outcome := signingkeys.LifecycleOutcome{KID: domain.KeyID("kaname-leaked")}
	cause := errors.New("connection reset")

	var unknown bytes.Buffer
	code := reportSigningKeyOutcome(&unknown, "compromise", "oncall", outcome,
		fmt.Errorf("%w: reading the signing key: %w", signingkeys.ErrSignerUnknownAfterCompromise, cause))
	require.Equal(t, signingKeyExitNotRun, code, "вывод: %s", unknown.String())
	require.Contains(t, unknown.String(), "outcome=signer-unknown")
	require.Contains(t, unknown.String(), "ключ снят из набора")
	require.Contains(t, unknown.String(), "connection reset", "причина доезжает до оператора")
	require.Contains(t, unknown.String(), "повторите команду")
	require.NotContains(t, unknown.String(), "служба не подписывает",
		"не установленное не утверждается")

	var partial bytes.Buffer
	code = reportSigningKeyOutcome(&partial, "compromise", "oncall", outcome,
		fmt.Errorf("%w: %w", signingkeys.ErrNoSignerAfterCompromise, cause))
	require.Equal(t, signingKeyExitRefused, code, "вывод: %s", partial.String())
	require.Contains(t, partial.String(), "outcome=partial")
	require.Contains(t, partial.String(), "служба не подписывает")
}

// TestReportSigningKeyOutcome_ASignerReadAfterAFailedReplacementIsNamed — замена
// этим вызовом не легла, а перечитанный подписывающий есть: исход — не отказ,
// он называет подписывающего и не называет службу неподписывающей. Близнец —
// частичный исход в пробе выше: там перечитанного подписывающего нет.
func TestReportSigningKeyOutcome_ASignerReadAfterAFailedReplacementIsNamed(t *testing.T) {
	for _, tc := range []struct {
		name        string
		alreadyDone bool
		outcome     string
	}{
		{"первое объявление", false, "outcome=done"},
		{"повтор после частичного исхода", true, "outcome=already-done"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			code := reportSigningKeyOutcome(&out, "compromise", "oncall", signingkeys.LifecycleOutcome{
				KID: domain.KeyID("kaname-leaked"), Signer: domain.KeyID("kaname-neighbour"), AlreadyDone: tc.alreadyDone,
			}, nil)
			require.Equal(t, signingKeyExitDone, code, "вывод: %s", out.String())
			require.Contains(t, out.String(), "signer=kaname-neighbour", "оператор обязан узнать, каким ключом служба подписывает")
			require.Contains(t, out.String(), tc.outcome)
			require.NotContains(t, out.String(), "replacement=", "замена этим вызовом не заводилась")
			require.NotContains(t, out.String(), "служба не подписывает", "служба подписывает")
		})
	}
}

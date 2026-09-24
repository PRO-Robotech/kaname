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
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// closedStoreAddress — адрес, по которому базы заведомо нет: порт взят у
// системы и тут же отпущен. Попытка соединения отказывает сразу, поэтому
// команда, дошедшая до базы, говорит об этом словом «база:» без ожидания.
func closedStoreAddress(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestSigningKeyCommand_UndeclaredKeyLifetimeIsRefusedByTheServiceGuardBeforeTheStore —
// срок ключа подписи не подставляется нигде (#321), поэтому команда, у
// которой его нет, судит его ТЕМ ЖЕ стражем, что служба, и ДО первого
// соединения: отвечает «не исполнялось» словами стража и до базы, а значит и
// до ключницы, не доходит. Близнец — та же настройка с объявленным сроком: она
// проходит страж и доходит до базы, которой по этому адресу нет.
func TestSigningKeyCommand_UndeclaredKeyLifetimeIsRefusedByTheServiceGuardBeforeTheStore(t *testing.T) {
	store := closedStoreAddress(t)
	withLifetime := func(lifetime time.Duration) config.Config {
		cfg := postureCfg(config.ModeDev, "disable")
		cfg.Repository.Postgres.URL = "postgres://u:p@" + store + "/kaname"
		cfg.AuthN.JWKSEncryptionKeyHex = strings.Repeat("ab", 32)
		cfg.AuthN.TokenSigning = config.TokenSigningConfig{
			Enabled:           true,
			Issuer:            "https://kaname.kacho.local",
			Algorithm:         "ES256",
			AllowedAlgorithms: "ES256",
			KeySetPath:        "/.well-known/kaname/jwks.json",
			KeyLifetime:       lifetime,
		}
		return cfg
	}
	run := func(cfg config.Config) (int, string) {
		var out bytes.Buffer
		code := runSigningKeyCommandWithin(context.Background(), 10*time.Second, cfg,
			[]string{"compromise", "-kid=kaname-leaked", "-decided-by=oncall@example.invalid"}, &out, quietLogger())
		return code, out.String()
	}

	for _, tc := range []struct {
		name     string
		lifetime time.Duration
		refusal  string
	}{
		{"срок не задан", 0, "authn.token-signing.key-lifetime is not declared"},
		{"срок отрицательный", -time.Hour, "authn.token-signing.key-lifetime must be positive (got -1h0m0s)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := withLifetime(tc.lifetime)
			guard := cfg.AuthN.TokenSigning.Validate()
			require.Error(t, guard, "предпосылка пробы: страж службы эту настройку отвергает")

			code, out := run(cfg)
			require.Equal(t, signingKeyExitNotRun, code, "вывод команды: %s", out)
			require.Contains(t, out, tc.refusal, "отказ называет ключ настройки")
			require.Contains(t, out, guard.Error(), "команда отвечает словами стража службы, а не своими")
			require.NotContains(t, out, "база:", "незаданный срок не доходит до базы")
			require.NotContains(t, out, "ключница", "незаданный срок не доходит до ключницы")
		})
	}

	t.Run("близнец: срок объявлен", func(t *testing.T) {
		cfg := withLifetime(90 * 24 * time.Hour)
		require.NoError(t, cfg.AuthN.TokenSigning.Validate(), "предпосылка близнеца: страж службы настройку принимает")

		code, out := run(cfg)
		require.Equal(t, signingKeyExitNotRun, code, "вывод команды: %s", out)
		require.Contains(t, out, "база:", "объявленный срок проходит страж и доводит команду до базы")
		require.NotContains(t, out, "key-lifetime")
	})
}

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

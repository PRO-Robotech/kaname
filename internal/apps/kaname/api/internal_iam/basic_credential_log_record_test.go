// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_log_record_test.go — один отказ полосы базового секрета —
// ОДНА запись журнала ОБЪЯВЛЕННОГО уровня (задача kaname#390).
//
// # Предмет
//
// Таблица уровней службы (`docs/engineering/components/32-observability.md`,
// «Уровни») относит отклонённое предъявление к WARN, отказ нашей стороны — к
// ERROR. Отказ предъявителю журналился уровнем INFO, а ветка «в поле
// идентификатора пришла предъявленная строка» давала две записи на один отказ.
//
// # Что утверждается
//
// На КАЖДОЙ ветке отказа обоих глаголов — каждая причина словаря от
// авторитета, отказ без названной причины, отказы, которые глагол выносит сам
// (пустой вход, предъявленная строка в поле идентификатора), — в журнале ровно
// одна запись, её уровень — объявленный ([basicRefusalLevel]), и в журнале нет
// ни предъявленной строки, ни идентификатора удостоверения.
package internal_iam

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// allRecords — ВСЕ записи журнала, а не только записи об отказе: «одна
// запись» судится по всему, что напечатал один вопрос.
func allRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "запись журнала не разбирается: %s", line)
		out = append(out, rec)
	}
	return out
}

func TestBasicCredentialRefusal_OneRecordOfTheDeclaredLevelOnEveryBranch(t *testing.T) {
	credentialID := "uoc_lvl00000000000001"
	presented := mintedPresentedForTest(t, credentialID)
	parsed, err := credsecret.Parse(presented)
	require.NoError(t, err)

	type branch struct {
		name      string
		authority reasonedAuthority
		ask       func(h *Handler) error
		wantLevel slog.Level
	}
	resolve := func(p string) func(h *Handler) error {
		return func(h *Handler) error {
			_, err := h.ResolveBasicCredential(context.Background(), &iamv1.ResolveBasicCredentialRequest{Presented: p})
			return err
		}
	}
	live := func(id string) func(h *Handler) error {
		return func(h *Handler) error {
			_, err := h.CheckBasicCredentialLive(context.Background(), &iamv1.CheckBasicCredentialLiveRequest{CredentialId: id})
			return err
		}
	}
	var branches []branch
	for _, r := range domain.BasicCredentialRefusalReasons() {
		a := reasonedAuthority{err: domain.RefuseBasicCredential(r)}
		branches = append(branches,
			branch{"resolve/" + string(r), a, resolve(presented), slog.LevelWarn},
			branch{"liveness/" + string(r), a, live(parsed.CredentialID), slog.LevelWarn})
	}
	unnamed := reasonedAuthority{err: domain.ErrBasicCredentialRefused}
	branches = append(branches,
		// Авторитет нарушил свой контракт — это наш дефект, а не предъявителя.
		branch{"resolve/причина не названа", unnamed, resolve(presented), slog.LevelError},
		branch{"liveness/причина не названа", unnamed, live(parsed.CredentialID), slog.LevelError},
		// Отказы, которые глагол выносит сам, не спрашивая авторитета.
		branch{"resolve/пустой вход", reasonedAuthority{}, resolve(""), slog.LevelWarn},
		branch{"liveness/пустой идентификатор", reasonedAuthority{}, live(""), slog.LevelWarn},
		branch{"liveness/предъявленная строка в поле идентификатора", reasonedAuthority{}, live(presented), slog.LevelWarn},
	)

	for _, b := range branches {
		t.Run(b.name, func(t *testing.T) {
			var buf bytes.Buffer
			h := (&Handler{}).WithBasicCredentialResolver(b.authority).
				WithLogger(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
			require.Error(t, b.ask(h), "ветка отказа обязана отказать")

			recs := allRecords(t, &buf)
			require.Lenf(t, recs, 1, "записей на один отказ %d, а не одна: %s", len(recs), buf.String())
			require.Equal(t, b.wantLevel.String(), recs[0][slog.LevelKey],
				"уровень записи не объявленный: %s", buf.String())
			require.NotContains(t, buf.String(), presented, "предъявленная строка в журнале")
			require.NotContains(t, buf.String(), parsed.SecretPart, "секретная часть в журнале")
			require.NotContains(t, buf.String(), parsed.CredentialID, "идентификатор удостоверения в журнале")
		})
	}
	t.Logf("перепись: веток отказа %d", len(branches))
	require.Equal(t, 2*len(domain.BasicCredentialRefusalReasons())+5, len(branches))
}

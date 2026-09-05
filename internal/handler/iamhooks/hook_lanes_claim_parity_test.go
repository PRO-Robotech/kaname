// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// hook_lanes_claim_parity_test.go — задача #2052: выдача и продление обязаны
// отдать ОДНОМУ человеку ОДИН набор утверждений.
//
// # Что здесь утверждается и почему целиком, а не по полям
//
// Токен одному и тому же человеку выдают две полосы обратного вызова
// провайдера: выпуск (`/hooks/token`) и продление (`/hooks/refresh`). Пока
// каждая собирала состав утверждений сама, они были ДВУМЯ МЕСТАМИ ОБ ОДНОМ
// предмете — и расходились бы молча: правка производной «согласие устройства»
// в службе не доехала бы до полосы продления, а обе половины остались бы
// зелёными, потому что проба каждой утверждает СВОЁ ожидаемое значение.
// Поэтому сверяются карты целиком: проверка «есть поле X» зелена на составе,
// потерявшем поле Y.
//
// # Почему обе полосы спрашиваются ОДНИМ прогоном и на ОДНИХ часах
//
// В составе есть величина, произведённая часами (`kacho_issued_at`). Две
// службы с двумя источниками времени разошлись бы по ней, и расхождение было
// бы свойством пробы, а не продукта. Один экземпляр службы, одни часы, обе
// полосы: расходиться остаётся ровно тому, что принадлежит полосам.
//
// # Чего эта проба НЕ делает
//
// Она не стережёт ЕДИНСТВЕННОСТЬ производителя в дереве — это свойство дерева
// и предмет гейта, а не пробы. Здесь спрашивается ИСХОД: два обращения по HTTP
// к двум полосам на одном принципале обязаны дать один состав.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// parityUserPort — одна и та же строка обеим полосам.
//
// Дублёр, отдающий разным полосам разные строки, сверял бы двух разных
// принципалов и был бы зелен при любом расхождении составов. Разрешение
// КЛЮЧУЕТСЯ внешним идентификатором, как у настоящего репозитория: всеядный
// дублёр снисходительнее продукта ровно там, где это ломает предмет пробы.
type parityUserPort struct {
	externalID string
	user       domain.User
}

func (p parityUserPort) FindByExternalID(_ context.Context, id domain.ExternalSubject) ([]domain.User, error) {
	if string(id) != p.externalID {
		return nil, nil
	}
	return []domain.User{p.user}, nil
}

func (p parityUserPort) GetByID(_ context.Context, _ domain.UserID) (domain.User, error) {
	return p.user, nil
}

// TestIssuanceAndRefreshLanesMintTheSameClaimSet — выпуск и продление одного
// принципала отдают побайтово один состав утверждений.
func TestIssuanceAndRefreshLanesMintTheSameClaimSet(t *testing.T) {
	t.Parallel()

	const (
		secret     = "parity-hook-secret"
		externalID = "kratos-sub-parity"
		clientID   = "client-parity"
		acr        = "urn:kacho:acr:2fa"
		jkt        = "jkt-thumb-parity"
		x5t        = "x5t-thumb-parity"
	)
	// Момент аутентификации сессии — НЕПУСТОЙ: он попадает в состав
	// (`kacho_mfa_at`), и на нуле расхождение по нему было бы неотличимо от
	// совпадения.
	authTime := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	fixed := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

	user := domain.User{
		ID:           domain.UserID("usr000000000parity"),
		AccountID:    domain.AccountID("acc000000000parity"),
		ExternalID:   domain.ExternalSubject(externalID),
		InviteStatus: domain.InviteStatusActive,
	}
	port := parityUserPort{externalID: externalID, user: user}

	// Одна служба, одни часы, обе полосы.
	svc := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"},
		port,
	).WithClock(func() time.Time { return fixed })

	logger := slog.New(slog.DiscardHandler)

	tokenHook := iamhooks.NewTokenHookHandler(
		iamhooks.TokenHookConfig{HookSharedSecret: secret, Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"},
		svc, nil, nil, logger,
	)
	refreshHook := iamhooks.NewRefreshHookHandler(
		iamhooks.RefreshHookConfig{HookSharedSecret: secret, Domain: "kacho.cloud", HydraIssuer: "https://hydra.kacho.local"},
		port, svc, nil, nil, logger,
	)

	// Тела обеих полос — РАЗНЫЕ по форме и одинаковые по фактам. Это и есть
	// предмет: один человек, одна сессия, один набор областей.
	issuanceBody := `{
	  "session": {
	    "client_id": "` + clientID + `",
	    "id_token": {
	      "subject": "` + externalID + `",
	      "id_token_claims": {"auth_time": "` + authTime.Format(time.RFC3339) + `", "acr": "` + acr + `"}
	    },
	    "cnf": {"jkt": "` + jkt + `", "x5t#S256": "` + x5t + `"}
	  },
	  "request": {
	    "client_id": "` + clientID + `",
	    "granted_scopes": ["openid", "webauthn"],
	    "grant_types": ["authorization_code"]
	  }
	}`
	refreshBody := `{
	  "subject": "` + externalID + `",
	  "session": {
	    "client_id": "` + clientID + `",
	    "id_token": {"id_token_claims": {"auth_time": "` + authTime.Format(time.RFC3339) + `", "acr": "` + acr + `"}},
	    "cnf": {"jkt": "` + jkt + `", "x5t#S256": "` + x5t + `"}
	  },
	  "requester": {"client_id": "` + clientID + `", "granted_scopes": ["openid", "webauthn"]}
	}`

	issued := postHookForClaims(t, tokenHook, secret, issuanceBody)
	renewed := postHookForClaims(t, refreshHook, secret, refreshBody)

	// Положительный контроль: состав НЕПУСТ на ОБЕИХ полосах. Равенство двух
	// пустых карт зелено и не утверждает ничего.
	require.NotEmpty(t, issued, "полоса выпуска отдала пустой состав — сверять нечего")
	require.NotEmpty(t, renewed, "полоса продления отдала пустой состав — сверять нечего")

	// Положительный контроль номер два: производная, ради которой задача
	// заводилась, ДЕЙСТВИТЕЛЬНО сработала на этом входе. Без него равенство
	// двух составов, у обоих одинаково не сработавшей производной, зелено.
	require.Equal(t, "attested", issued["kacho_device_compliance"],
		"область webauthn не дала attested — вход пробы не задевает производную согласия устройства")

	// Множество ИМЁН — отдельным утверждением, чтобы отказ называл потерянное
	// поле, а не печатал две карты целиком.
	require.ElementsMatch(t, claimNamesOf(issued), claimNamesOf(renewed),
		"множества имён утверждений двух полос разошлись")

	// Значения — равенство карт целиком: имена могут совпасть при
	// разошедшихся значениях.
	require.Equal(t, issued, renewed,
		"значения утверждений двух полос разошлись")
}

// postHookForClaims гоняет полосу по HTTP и возвращает её `ext_claims`.
func postHookForClaims(t *testing.T, h http.Handler, secret, body string) map[string]any {
	t.Helper()

	req := httptest.NewRequest(http.MethodPost, "/hook", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Kacho-Hook-Token", secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, "полоса отказала: %s", rec.Body.String())

	var resp struct {
		Session struct {
			AccessToken map[string]any `json:"access_token"`
		} `json:"session"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	claims, ok := resp.Session.AccessToken["ext_claims"].(map[string]any)
	require.True(t, ok, "в ответе полосы нет ext_claims: %s", rec.Body.String())
	return claims
}

// claimNamesOf — имена утверждений состава.
func claimNamesOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

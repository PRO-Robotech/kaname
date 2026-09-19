// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_authorize_red_test.go — Группа A приёмки LINE-A-1: эндпоинт
// авторизации (выдача кода). Свежие утверждения против нашей поверхности
// выдачи; заимствованные векторы (S256, redirect_uri) — в
// `ceremony_fosite_vectors_test.go` (атрибуция Ory там).
//
// Общий честный красный группы: `/iam/v1/authorize` не смонтирован на dd66b5be
// → 404. Утверждения формы ответа (302, code, state, error=…) — целевые: они
// исполнятся, когда реализация смонтирует эндпоинт и провяжет посев сессии
// через порт LoginAuthority.

package main

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// authorizeQuery — валидный запрос авторизации сценария 02 (фронт-канал несёт
// ТОЛЬКО code_challenge; аутентификацию клиента предъявляет бэк-канал обмена, Р3).
func authorizeQuery(clientID, redirectURI, state string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"iam.read"},
		"state":                 {state},
		"code_challenge":        {fositeS256(fositePKCEVerifier)},
		"code_challenge_method": {"S256"},
	}
}

// TestLINEA1_02_AuthorizeEndpointIssuesCodeOnValidRequest — LINE-A-1-02 (E/P):
// happy path выдачи кода.
//
// Given аутентифицированная сессия (посев ответа авторитета входа) + ACTIVE
// интерактивный клиент с зарегистрированным redirect_uri.
// When GET /iam/v1/authorize с валидными параметрами (response_type=code, PKCE S256).
// Then 302 на R?code=…&state=…; state дословно; связку назначает выдача (Р5).
//
// RED на dd66b5be: эндпоинт не смонтирован → 404.
func TestLINEA1_02_AuthorizeEndpointIssuesCodeOnValidRequest(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)
	const state = "opaque-state-xyz"

	rec := ceremonyGET(mux, ceremonyAuthorizePath, authorizeQuery("ic-first-party", fositeRedirectRegistered, state))

	if !mounted(rec) {
		t.Fatalf("LINE-A-1-02 КРАСНЫЙ: эндпоинт авторизации %s не смонтирован (код %d, ожидалось 302) — церемония выдачи кода отсутствует", ceremonyAuthorizePath, rec.Code)
	}

	// Целевая форма (исполнится по реализации): 302 + Location = R?code&state.
	if rec.Code != http.StatusFound {
		t.Fatalf("LINE-A-1-02: ожидался 302, получен %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("LINE-A-1-02: Location неразбираем: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != fositeRedirectRegistered {
		t.Errorf("LINE-A-1-02: перенаправление на %q, ожидался зарегистрированный %q", got, fositeRedirectRegistered)
	}
	if loc.Query().Get("state") != state {
		t.Errorf("LINE-A-1-02: state вернулся %q, ожидался дословно %q", loc.Query().Get("state"), state)
	}
	if loc.Query().Get("code") == "" {
		t.Error("LINE-A-1-02: код не выдан в перенаправлении")
	}
}

// TestLINEA1_04_UnregisteredRedirectURIRefusedWithoutRedirect — LINE-A-1-04 (E):
// redirect_uri не зарегистрирован → отказ БЕЗ перенаправления (защита от
// открытого перенаправления, Р4). Точная сверка — вектор fosite: чужой хост и
// «тот же адрес плюс хвост» НЕ совпадают.
//
// RED на dd66b5be: эндпоинт не смонтирован → 404 на положительном близнеце.
func TestLINEA1_04_UnregisteredRedirectURIRefusedWithoutRedirect(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	// Положительный близнец: зарегистрированный R → 302 с кодом (отличие в
	// одном факте — сам redirect_uri).
	twin := ceremonyGET(mux, ceremonyAuthorizePath, authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1"))
	if !mounted(twin) {
		t.Fatalf("LINE-A-1-04 КРАСНЫЙ: эндпоинт авторизации не смонтирован (код %d) — точная сверка redirect_uri невыразима, предмета нет", twin.Code)
	}
	if twin.Code != http.StatusFound {
		t.Fatalf("LINE-A-1-04: положительный близнец ожидал 302, получил %d", twin.Code)
	}

	// Незарегистрированные адреса: ни 302 на них, ни 302 на зарегистрированный R
	// — иначе код утёк бы на чужой адрес.
	for _, bad := range []string{fositeRedirectForeign, fositeRedirectTrailing} {
		rec := ceremonyGET(mux, ceremonyAuthorizePath, authorizeQuery("ic-first-party", bad, "s1"))
		if rec.Code == http.StatusFound {
			t.Errorf("LINE-A-1-04: открытое перенаправление — 302 на незарегистрированный %q (Location %q)", bad, rec.Header().Get("Location"))
		}
		if strings.Contains(rec.Header().Get("Location"), "code=") {
			t.Errorf("LINE-A-1-04: код доставлен по незарегистрированному адресу %q", bad)
		}
	}
}

// TestLINEA1_06_PKCEMissingOrPlainRejected — LINE-A-1-06 (E): PKCE отсутствует
// либо метод не S256 → 302 на R с error=invalid_request (PKCE обязателен и для
// конфиденциального клиента, Р3). Здесь отказ ИДЁТ через перенаправление —
// клиент и redirect_uri уже валидны (в отличие от 04, где перенаправлять некуда).
//
// RED на dd66b5be: эндпоинт не смонтирован → 404 на положительном близнеце.
func TestLINEA1_06_PKCEMissingOrPlainRejected(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	// Положительный близнец: валидный S256 → код (02).
	twin := ceremonyGET(mux, ceremonyAuthorizePath, authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1"))
	if !mounted(twin) {
		t.Fatalf("LINE-A-1-06 КРАСНЫЙ: эндпоинт авторизации не смонтирован (код %d) — принуждение PKCE S256 невыразимо, предмета нет", twin.Code)
	}

	// Без code_challenge.
	noPKCE := authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1")
	noPKCE.Del("code_challenge")
	noPKCE.Del("code_challenge_method")
	// Метод plain (S256 обязателен).
	plain := authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1")
	plain.Set("code_challenge_method", "plain")

	for _, q := range []url.Values{noPKCE, plain} {
		rec := ceremonyGET(mux, ceremonyAuthorizePath, q)
		if rec.Code != http.StatusFound {
			t.Errorf("LINE-A-1-06: ожидался 302 с ошибкой на R, получен %d", rec.Code)
			continue
		}
		if loc, _ := url.Parse(rec.Header().Get("Location")); loc.Query().Get("error") != oauthErrInvalidRequest {
			t.Errorf("LINE-A-1-06: ожидался error=%s на перенаправлении, получено %q", oauthErrInvalidRequest, loc.Query().Get("error"))
		}
		if strings.Contains(rec.Header().Get("Location"), "code=") {
			t.Error("LINE-A-1-06: код выдан несмотря на отсутствующий/plain PKCE")
		}
	}
}

// TestLINEA1_07_ResponseTypeNotCodeRejected — LINE-A-1-07 (E): response_type не
// code → 302 на R с error=unsupported_response_type; код не выдаётся.
//
// RED на dd66b5be: эндпоинт не смонтирован → 404 на положительном близнеце.
func TestLINEA1_07_ResponseTypeNotCodeRejected(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	twin := ceremonyGET(mux, ceremonyAuthorizePath, authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1"))
	if !mounted(twin) {
		t.Fatalf("LINE-A-1-07 КРАСНЫЙ: эндпоинт авторизации не смонтирован (код %d) — разбор response_type невыразим, предмета нет", twin.Code)
	}

	q := authorizeQuery("ic-first-party", fositeRedirectRegistered, "s1")
	q.Set("response_type", "token")
	rec := ceremonyGET(mux, ceremonyAuthorizePath, q)
	if rec.Code != http.StatusFound {
		t.Fatalf("LINE-A-1-07: ожидался 302 с ошибкой, получен %d", rec.Code)
	}
	if loc, _ := url.Parse(rec.Header().Get("Location")); loc.Query().Get("error") != oauthErrUnsupportedRespType {
		t.Errorf("LINE-A-1-07: ожидался error=%s, получено %q", oauthErrUnsupportedRespType, loc.Query().Get("error"))
	}
}

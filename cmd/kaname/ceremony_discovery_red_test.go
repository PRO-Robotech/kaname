// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_discovery_red_test.go — Группа H приёмки LINE-A-1: метаданные
// обнаружения OAuth AS. Путь и имена полей метаданных — из hydra
// oauth2/handler.go (OauthAuthorizationServerPath, response_types_supported,
// code_challenge_methods_supported); проверка против нашей поверхности — свежая.
//
// ВНИМАНИЕ О СТАДИИ: приёмка §3 относит метаданные обнаружения к S2, а задание
// диспетчера — к S1. Проба написана (предмет отсутствует на dd66b5be при любом
// прочтении — предикат G = ∅), расхождение вынесено в возврат «вопросы к приёмке».
//
// Честный красный: `.well-known/oauth-authorization-server` не смонтирован → 404.
// Эта проба зеленеет по одному лишь монтированию (метаданные — статическое
// публичное чтение, посева не требуют).

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLINEA1_22_DiscoveryMetadataPublished — LINE-A-1-22 (E): эндпоинт
// обнаружения отдаёт наши координаты церемонии публичным неаутентифицированным
// чтением: издатель, эндпоинт авторизации, токен-эндпоинт,
// code_challenge_methods_supported=["S256"], response_types_supported=["code"],
// поддерживаемые виды выдачи (включая authorization_code).
//
// RED на dd66b5be: путь не смонтирован → 404.
func TestLINEA1_22_DiscoveryMetadataPublished(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	rec := ceremonyGET(mux, ceremonyDiscoveryPath, nil)
	if !mounted(rec) {
		t.Fatalf("LINE-A-1-22 КРАСНЫЙ: %s не смонтирован (код %d, ожидалось 200 с метаданными) — эндпоинт обнаружения OAuth AS отсутствует", ceremonyDiscoveryPath, rec.Code)
	}

	// Целевая форма (исполнится по монтированию).
	if rec.Code != http.StatusOK {
		t.Fatalf("LINE-A-1-22: ожидался 200, получен %d", rec.Code)
	}
	var meta struct {
		Issuer                        string   `json:"issuer"`
		AuthorizationEndpoint         string   `json:"authorization_endpoint"`
		TokenEndpoint                 string   `json:"token_endpoint"`
		ResponseTypesSupported        []string `json:"response_types_supported"`
		GrantTypesSupported           []string `json:"grant_types_supported"`
		CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatalf("LINE-A-1-22: метаданные не разобрать: %v", err)
	}
	if !ceremonySingleton(meta.CodeChallengeMethodsSupported, "S256") {
		t.Errorf("LINE-A-1-22: code_challenge_methods_supported=%v, ожидалось [S256]", meta.CodeChallengeMethodsSupported)
	}
	if !ceremonySingleton(meta.ResponseTypesSupported, "code") {
		t.Errorf("LINE-A-1-22: response_types_supported=%v, ожидалось [code]", meta.ResponseTypesSupported)
	}
	if !ceremonyContains(meta.GrantTypesSupported, grantAuthorizationCode) {
		t.Errorf("LINE-A-1-22: grant_types_supported=%v, не содержит %s", meta.GrantTypesSupported, grantAuthorizationCode)
	}
}

// TestLINEA1_22_DiscoveryMethodBound — LINE-A-1-22 (E), продолжение: метод,
// отличный от GET, → 405 с перечнем допустимых.
//
// RED на dd66b5be: путь не смонтирован → 404 (не 405).
func TestLINEA1_22_DiscoveryMethodBound(t *testing.T) {
	mux := buildCeremonyIssuanceSurface(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, ceremonyDiscoveryPath, nil))
	if rec.Code == http.StatusNotFound {
		t.Fatalf("LINE-A-1-22 КРАСНЫЙ: %s не смонтирован (код 404) — ограничение метода невыразимо, эндпоинта нет", ceremonyDiscoveryPath)
	}
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("LINE-A-1-22: POST ожидал 405, получил %d", rec.Code)
	}
}

func ceremonyContains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}

func ceremonySingleton(xs []string, want string) bool {
	return len(xs) == 1 && xs[0] == want
}

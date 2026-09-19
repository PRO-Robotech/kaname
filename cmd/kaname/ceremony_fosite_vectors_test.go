// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0
//
// Adapted from github.com/ory/hydra/v2/fosite@v26.2.0, modified by PRO-Robotech.
//
// Векторы и формулы, ПЕРЕНЕСЁННЫЕ из тестов fosite дословно (директива владельца
// 2026-09-19 «тесты адаптировать из ory/fosite»). Здесь — только заимствованный
// материал; свежие утверждения против НАШЕЙ поверхности выдачи kaname лежат в
// соседних `ceremony_*_red_test.go` (лицензия дерева, без атрибуции).
//
// Источники в карте порта:
//   - S256 verifier↔challenge:   fosite/handler/pkce/handler.go + handler_test.go
//     (S256: sha256 → base64url; verifier 43..128; charset [A-Za-z0-9.\-_~])
//   - точная сверка redirect_uri: fosite/authorize_helper.go
//     (MatchRedirectURIWithClientRedirectURIs, точное равенство) + _test.go
//   - коды ошибок RFC 6749:       fosite/errors.go (ErrInvalidGrant единый,
//     ErrInvalidClient, ErrUnsupportedGrantType, ErrUnsupportedResponseType)

package main

import (
	"crypto/sha256"
	"encoding/base64"
)

// fositeS256 — BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), точь-в-точь
// формула fosite/handler/pkce/handler.go (RFC 7636 §4.6):
//
//	base64.RawURLEncoding.EncodeToString(sha256(verifier)) == code_challenge
//
// Реализация — стандартной библиотекой, но формула и режим кодирования
// (RawURLEncoding, без набивки) взяты у fosite дословно.
func fositeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// fositePKCEVerifier — законный code_verifier из fosite/handler/pkce/handler_test.go
// (`s256verifier`): 60 знаков, charset [A-Za-z0-9], в пределах 43..128.
const fositePKCEVerifier = "KGCt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"

// fositePKCEVerifierWrong — другой законный по форме verifier, чей SHA256 НЕ даёт
// того же challenge (близнец для сценария 11 «неверный code_verifier»). Форма
// валидна (charset и длина по RFC 7636), отличается ровно содержимым.
const fositePKCEVerifierWrong = "ZZZt4m8AmjUvIR5ArTByrmehjtbxn1A49YpTZhsH8N7fhDr7LQayn9xx6mck"

// Точная сверка redirect_uri — векторы из fosite/authorize_helper_test.go
// (MatchRedirectURIWithClientRedirectURIs). Зарегистрирован ровно один адрес;
// чужой хост и «тот же адрес плюс хвост» НЕ совпадают (точное равенство, не
// префикс) — это и есть защита от открытого перенаправления.
const (
	fositeRedirectRegistered = "https://bar.com/cb"    // зарегистрированный
	fositeRedirectForeign    = "https://foo.com/cb"    // чужой хост → нет совпадения
	fositeRedirectTrailing   = "https://bar.com/cb123" // хвост → нет совпадения (не префикс)
)

// Коды ошибок RFC 6749 §5.2 — имена полей `error` из fosite/errors.go.
// ErrInvalidGrant — ЕДИНЫЙ ответ на все причины, наступившие ПОСЛЕ того, как
// назван код (анти-оракул, Р10 приёмки): «код неизвестен/истёк/использован»,
// «неверный code_verifier», «чужой клиент», «не тот redirect_uri». ErrInvalidClient
// решается ДО кода и остаётся различимым.
const (
	oauthErrInvalidGrant        = "invalid_grant"             // fosite ErrInvalidGrant, HTTP 400
	oauthErrInvalidClient       = "invalid_client"            // fosite ErrInvalidClient, HTTP 401
	oauthErrUnsupportedGrant    = "unsupported_grant_type"    // fosite ErrUnsupportedGrantType, HTTP 400
	oauthErrInvalidRequest      = "invalid_request"           // fosite ErrInvalidRequest, HTTP 400
	oauthErrUnsupportedRespType = "unsupported_response_type" // fosite ErrUnsupportedResponseType, HTTP 400
)

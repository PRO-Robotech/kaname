// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_test.go — F1-25 (сторона авторитета отзыва): отзыв читается НА
// ПРЕДЪЯВЛЕНИИ, а не только на выдаче.
package tokenintrospecthttp_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/tokenintrospecthttp"
	"github.com/PRO-Robotech/kacho-iam/internal/signingkeygen"
)

const testIssuer = "https://iam.kacho.local"

// stubKeys — публикуемый набор, которым проверяется подпись.
type stubKeys struct {
	keys []domain.PublishedKey
	err  error
}

func (s stubKeys) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	return s.keys, s.err
}

// stubRevocations — авторитет отзыва.
type stubRevocations struct {
	before map[string]time.Time
	err    error
}

func (s stubRevocations) RevokedBefore(_ context.Context, subject string) (time.Time, bool, error) {
	if s.err != nil {
		return time.Time{}, false, s.err
	}
	t, ok := s.before[subject]
	return t, ok, nil
}

type minted struct {
	raw string
	kid string
}

func mintToken(t *testing.T, sub string, iat time.Time, pub *domain.PublishedKey) minted {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("порождение ключа: %v", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(mat.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("разбор ключа: %v", err)
	}
	kid := "kacho-" + sub
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": testIssuer, "sub": sub, "aud": []string{"registry.kacho.local"},
		"iat": iat.Unix(), "nbf": iat.Unix(), "exp": iat.Add(5 * time.Minute).Unix(),
		"jti": "tok-" + sub,
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = "at+jwt"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("подпись: %v", err)
	}
	*pub = domain.PublishedKey{KID: domain.KeyID(kid), Algorithm: domain.SigningAlgES256, PublicKeyPEM: mat.PublicKeyPEM}
	return minted{raw: raw, kid: kid}
}

func ask(t *testing.T, h http.Handler, token string) (int, map[string]any) {
	t.Helper()
	body := strings.NewReader(url.Values{"token": {token}}.Encode())
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	raw, _ := io.ReadAll(res.Body)
	_ = res.Body.Close()
	var out map[string]any
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("ответ авторитета обязан быть стандартным документом: %v; тело=%s", err, raw)
		}
	}
	return res.StatusCode, out
}

func newHandler(keys stubKeys, rev stubRevocations, now time.Time) http.Handler {
	return tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:      testIssuer,
		Keys:        keys,
		Revocations: rev,
		Clock:       func() time.Time { return now },
	})
}

// TestIntrospect_F1_25_RevocationIsReadAtPresentation — F1-25, сторона
// авторитета.
func TestIntrospect_F1_25_RevocationIsReadAtPresentation(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	iat := now.Add(-time.Minute)

	var livePub domain.PublishedKey
	live := mintToken(t, "sva-live", iat, &livePub)
	var revokedPub domain.PublishedKey
	revoked := mintToken(t, "sva-revoked", iat, &revokedPub)

	keys := stubKeys{keys: []domain.PublishedKey{livePub, revokedPub}}
	rev := stubRevocations{before: map[string]time.Time{
		// Отзыв субъекта: всё, выпущенное ДО этого момента, недействительно.
		"sva-revoked": now,
	}}
	h := newHandler(keys, rev, now)

	// Then — токен субъекта, чей отзыв записан, объявляется недействительным.
	code, out := ask(t, h, revoked.raw)
	if code != http.StatusOK {
		t.Fatalf("авторитет обязан отвечать по существу, получено %d", code)
	}
	if out["active"] != false {
		t.Fatalf("отозванный субъект обязан давать active=false, получено %v", out["active"])
	}

	// And — токен НЕ ОТОЗВАННОГО субъекта при ДОСТУПНОМ авторитете
	// ПРИНИМАЕТСЯ. Без этой половины авторитет, который ВСЕГДА отвечает
	// отказом, проходит пробу целиком — то есть «контроль, не отказавший ни
	// разу», только зеркально.
	code, out = ask(t, h, live.raw)
	if code != http.StatusOK {
		t.Fatalf("живой токен: код %d", code)
	}
	if out["active"] != true {
		t.Fatalf("не отозванный субъект обязан давать active=true, получено %v", out["active"])
	}

	// And — отзыв действует ВПЕРЁД: токен, выпущенный ПОСЛЕ записи отзыва,
	// снова действителен. Иначе отзыв субъекта означал бы вечную блокировку.
	var afterPub domain.PublishedKey
	after := mintToken(t, "sva-revoked", now.Add(time.Minute), &afterPub)
	hAfter := newHandler(stubKeys{keys: []domain.PublishedKey{afterPub}}, rev,
		now.Add(2*time.Minute))
	code, out = ask(t, hAfter, after.raw)
	if code != http.StatusOK || out["active"] != true {
		t.Fatalf("токен, выпущенный после отзыва, обязан быть действительным: %d %v", code, out["active"])
	}
}

// TestIntrospect_RefusesWhatItCannotVouchFor — авторитет не объявляет
// действительным то, за что не может поручиться.
func TestIntrospect_RefusesWhatItCannotVouchFor(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	var pub domain.PublishedKey
	good := mintToken(t, "sva-a", now.Add(-time.Minute), &pub)
	keys := stubKeys{keys: []domain.PublishedKey{pub}}
	h := newHandler(keys, stubRevocations{}, now)

	// Положительный контроль — законный токен действителен; без него все
	// отрицания ниже зелены на авторитете, отвергающем всё.
	if code, out := ask(t, h, good.raw); code != http.StatusOK || out["active"] != true {
		t.Fatalf("законный токен обязан быть действительным: %d %v", code, out["active"])
	}

	for name, raw := range map[string]string{
		"мусор":              "not-a-token",
		"пустая строка":      "",
		"подпись подменена":  good.raw[:len(good.raw)-4] + "AAAA",
		"чужой издатель":     mintForeignIssuer(t),
		"без подписи (none)": unsignedToken(t),
	} {
		code, out := ask(t, h, raw)
		if code != http.StatusOK {
			// Пустая строка — отсутствующий обязательный параметр запроса, и
			// это отказ формы, а не суждение о токене.
			if name == "пустая строка" && code == http.StatusBadRequest {
				continue
			}
			t.Fatalf("%s: код %d", name, code)
		}
		if out["active"] != false {
			t.Fatalf("%s: авторитет объявил действительным то, за что поручиться не может", name)
		}
	}

	// Истёкший токен недействителен, а тот же токен ДО истечения —
	// действителен: пара доказывает, что отвергается именно истечение.
	expired := newHandler(keys, stubRevocations{}, now.Add(time.Hour))
	if _, out := ask(t, expired, good.raw); out["active"] != false {
		t.Fatalf("истёкший токен объявлен действительным")
	}
}

func mintForeignIssuer(t *testing.T) string {
	t.Helper()
	mat, err := signingkeygen.Generate(domain.SigningAlgES256)
	if err != nil {
		t.Fatalf("%v", err)
	}
	key, err := jwt.ParseECPrivateKeyFromPEM(mat.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("%v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://outsider.example", "sub": "x",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kacho-sva-a"
	raw, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

func unsignedToken(t *testing.T) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"iss": testIssuer, "sub": "sva-a", "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = "kacho-sva-a"
	raw, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return raw
}

// TestIntrospect_AuthorityUnavailableIsARefusalNotAnApproval — недоступный
// авторитет не есть «да»: он отвечает ОТКАЗОМ, по которому спрашивающий
// закрывается сам.
func TestIntrospect_AuthorityUnavailableIsARefusalNotAnApproval(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	var pub domain.PublishedKey
	good := mintToken(t, "sva-a", now.Add(-time.Minute), &pub)

	// Источник ключей недоступен.
	h := newHandler(stubKeys{err: errors.New("database is unavailable")}, stubRevocations{}, now)
	code, _ := ask(t, h, good.raw)
	if code == http.StatusOK {
		t.Fatalf("недоступный источник ключей обязан давать ОТКАЗ, а не суждение о токене")
	}

	// Хранилище отзывов недоступно — то же самое: молчаливое active=true
	// означало бы «отзыв не читается», то есть контроль, не отказавший ни разу.
	h = newHandler(stubKeys{keys: []domain.PublishedKey{pub}},
		stubRevocations{err: errors.New("database is unavailable")}, now)
	code, _ = ask(t, h, good.raw)
	if code == http.StatusOK {
		t.Fatalf("недоступное хранилище отзывов обязано давать ОТКАЗ")
	}

	// Положительный контроль — при доступных обоих тот же токен действителен.
	h = newHandler(stubKeys{keys: []domain.PublishedKey{pub}}, stubRevocations{}, now)
	if code, out := ask(t, h, good.raw); code != http.StatusOK || out["active"] != true {
		t.Fatalf("при доступных источниках токен обязан быть действительным: %d %v", code, out["active"])
	}
}

// TestIntrospect_MethodAndShape — маршрут сужен по методу, и ответ не несёт
// наружу ничего сверх суждения.
func TestIntrospect_MethodAndShape(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	var pub domain.PublishedKey
	good := mintToken(t, "sva-a", now.Add(-time.Minute), &pub)
	h := newHandler(stubKeys{keys: []domain.PublishedKey{pub}}, stubRevocations{}, now)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tokenintrospecthttp.IntrospectPath, nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("маршрут обязан быть сужен по методу, GET дал %d", rec.Code)
	}
	if !strings.Contains(rec.Header().Get("Allow"), http.MethodPost) {
		t.Fatalf("отказ по методу обязан нести перечень допустимых: %q", rec.Header().Get("Allow"))
	}

	// Ответ не выносит наружу ни ключей, ни самого токена, ни подробности.
	_, out := ask(t, h, good.raw)
	body, _ := json.Marshal(out)
	for _, forbidden := range []string{"kacho-sva-a", good.raw, "PRIVATE", "keys"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("ответ авторитета вынес наружу %q: %s", forbidden, body)
		}
	}
}

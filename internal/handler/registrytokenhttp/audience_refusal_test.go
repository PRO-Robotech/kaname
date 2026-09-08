// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audience_refusal_test.go — что ПОЛУЧАЕТ предъявитель, когда адресат отвергнут
// (задача #1184).
//
// Проба утверждает исход на наблюдаемом уровне: код ответа, тело и вызов на
// аутентификацию. Утверждать «выдача была позвана с таким-то входом» здесь
// нельзя — это факт вызова, а не то, что видит клиент.
package registrytokenhttp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
)

// TestAudienceRefusedLooksExactlyLikeAnyOtherAuthFailure — отказ адресата
// неотличим снаружи от прочих отказов аутентификации.
//
// Различимый ответ сказал бы предъявителю, ЧТО именно объявлено посадкой и подо
// что выдан ключ, — то есть был бы оракулом. Утверждается ПАРА: код ответа и
// тело; плюс вызов на аутентификацию, по которому докер-клиент решает, куда
// идти дальше.
func TestAudienceRefusedLooksExactlyLikeAnyOtherAuthFailure(t *testing.T) {
	body := func(err error) (int, string, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/iam/token?service=sts.example.com", nil)
		req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
		newTokenHandler(&fakeIssuer{err: err}).ServeHTTP(rec, req)
		return rec.Code, strings.TrimSpace(rec.Body.String()), rec.Header().Get("WWW-Authenticate")
	}

	gotCode, gotBody, gotChallenge := body(registrytokenuc.ErrAudienceNotAllowed)
	wantCode, wantBody, wantChallenge := body(registrytokenuc.ErrUnauthenticated)

	if gotCode != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401 (body=%s)", gotCode, gotBody)
	}
	if gotCode != wantCode || gotBody != wantBody || gotChallenge != wantChallenge {
		t.Fatalf("отказ адресата отличим снаружи: %d/%q/%q против %d/%q/%q",
			gotCode, gotBody, gotChallenge, wantCode, wantBody, wantChallenge)
	}
	// Ни адресата, ни перечня в теле: тело фиксировано.
	if strings.Contains(gotBody, "sts.example.com") || strings.Contains(gotBody, "audience") {
		t.Fatalf("тело назвало предмет отказа: %s", gotBody)
	}
	// И токена в нём нет — отказ есть отказ.
	var parsed map[string]any
	_ = json.Unmarshal([]byte(gotBody), &parsed)
	if _, ok := parsed["token"]; ok {
		t.Fatalf("тело отказа несёт токен: %s", gotBody)
	}
}

// TestAudienceRefusalReachesTheLog — причина отказа доезжает до журнала.
//
// Наружу тело фиксировано, и это правильно; но без этой строки «посадка такого
// адресата не объявляла» и «учётные данные негодны» выглядят для оператора
// одинаково — при том что чинятся в разных местах и разными людьми.
func TestAudienceRefusalReachesTheLog(t *testing.T) {
	var buf bytes.Buffer
	h := NewTokenHandler(Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, &fakeIssuer{err: registrytokenuc.ErrAudienceNotAllowed}).
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=sts.example.com", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d; want 401", rec.Code)
	}
	if !strings.Contains(buf.String(), "audience") {
		t.Fatalf("причина не доехала до журнала: %s", buf.String())
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: обычный отказ учётных данных журнал отказом
	// адресата НЕ называет — иначе строка выше зеленела бы на любом отказе.
	buf.Reset()
	h = NewTokenHandler(Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, &fakeIssuer{err: registrytokenuc.ErrUnauthenticated}).
		WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	h.ServeHTTP(rec, req)
	if strings.Contains(buf.String(), "audience refused") {
		t.Fatalf("отказ учётных данных назван отказом адресата: %s", buf.String())
	}
}

// TestOmittedServiceReachesIssuanceUnsubstituted — транспорт НЕ решает за
// выдачу, какой адресат подставить запросу, его не назвавшему.
//
// Подставив умолчание посадки здесь, транспорт отдал бы ключу, объявившему своё
// назначение, ЧУЖОЙ адресат — и такой ключ отвергался бы собственной проверкой
// платформы. Решение принадлежит выдаче, которая одна знает объявленное ключом.
func TestOmittedServiceReachesIssuanceUnsubstituted(t *testing.T) {
	iss := &fakeIssuer{out: registrytokenuc.IssueOutput{Token: "t", ExpiresIn: 60}}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	newTokenHandler(iss).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200", rec.Code)
	}
	if iss.gotSvc != "" {
		t.Fatalf("выдача получила %q; запрос адресата не называл", iss.gotSvc)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: названный запросом адресат доезжает дословно.
	iss = &fakeIssuer{out: registrytokenuc.IssueOutput{Token: "t", ExpiresIn: 60}}
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.Header.Set("Authorization", basic("cid-ci", "sa-key-private-pem"))
	newTokenHandler(iss).ServeHTTP(rec, req)
	if iss.gotSvc != "registry.kacho.local" {
		t.Fatalf("выдача получила %q; want registry.kacho.local", iss.gotSvc)
	}

	// И вызов на аутентификацию всё равно называет службу: клиенту без неё
	// некуда идти.
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/iam/token", nil)
	newTokenHandler(&fakeIssuer{}).ServeHTTP(rec, req)
	if !strings.Contains(rec.Header().Get("WWW-Authenticate"), `service="registry.kacho.local"`) {
		t.Fatalf("вызов на аутентификацию не назвал службу: %q", rec.Header().Get("WWW-Authenticate"))
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_cert_test.go — авторитет отзыва принимает вопрос только от пира,
// предъявившего ПРОВЕРЕННЫЙ сертификат.
//
// Соседняя поверхность того же слушателя — набор проверочных ключей — authN
// намеренно не требует: на проводе только публичный материал. Обоснование,
// выданное ей, на эту поверхность не распространяется: сюда присылают
// предъявленный токен. Молчаливое пользование чужим обоснованием и есть
// запрещённое допущение «внутреннее — значит доверенное».
package tokenintrospecthttp_test

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/tokenintrospecthttp"
)

func askWithTLS(t *testing.T, h http.Handler, token string, state *tls.ConnectionState) int {
	t.Helper()
	body := strings.NewReader(url.Values{"token": {token}}.Encode())
	req := httptest.NewRequest(http.MethodPost, tokenintrospecthttp.IntrospectPath, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.TLS = state
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestIntrospect_RefusesACallerItCannotIdentify(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	var pub domain.PublishedKey
	good := mintToken(t, "sva-a", now.Add(-time.Minute), &pub)

	h := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:            testIssuer,
		Keys:              stubKeys{keys: []domain.PublishedKey{pub}},
		Revocations:       stubRevocations{},
		Clock:             func() time.Time { return now },
		RequireClientCert: true,
	})

	// Пир без сертификата — отказ. Он не узнаёт даже того, существует ли
	// токен, о котором собирался спросить.
	if code := askWithTLS(t, h, good.raw, nil); code != http.StatusUnauthorized {
		t.Fatalf("вопрос без сертификата принят: код %d", code)
	}

	// Пир, ПРЕДЪЯВИВШИЙ сертификат, которого транспорт не проверил, — тоже
	// отказ: непроверенный сертификат есть заявление пира о себе, и принимать
	// его за личность значило бы завести контроль, который не отказывает.
	presentedOnly := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if code := askWithTLS(t, h, good.raw, presentedOnly); code != http.StatusUnauthorized {
		t.Fatalf("непроверенный сертификат принят за личность: код %d", code)
	}

	// Положительный контроль — пир с ПРОВЕРЕННОЙ цепочкой отвечает по
	// существу. Без него отрицания выше зелены на обработчике, отвергающем
	// всё, и авторитет, не отвечающий никогда, прошёл бы пробу целиком.
	verified := &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{{}},
		VerifiedChains:   [][]*x509.Certificate{{{}}},
	}
	if code := askWithTLS(t, h, good.raw, verified); code != http.StatusOK {
		t.Fatalf("проверенный пир получил отказ: код %d", code)
	}

	// И вторая половина того же контроля: там, где требование не включено,
	// поведение прежнее — иначе включение стало бы неотличимо от невключения.
	open := tokenintrospecthttp.NewHandler(tokenintrospecthttp.Config{
		Issuer:      testIssuer,
		Keys:        stubKeys{keys: []domain.PublishedKey{pub}},
		Revocations: stubRevocations{},
		Clock:       func() time.Time { return now },
	})
	if code := askWithTLS(t, open, good.raw, nil); code != http.StatusOK {
		t.Fatalf("без включённого требования вопрос обязан проходить: код %d", code)
	}
}

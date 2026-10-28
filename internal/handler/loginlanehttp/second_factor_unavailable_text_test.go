// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// second_factor_unavailable_text_test.go — недоступность материала второго
// фактора называет шаг человека, а не «позже» (PRO-Robotech/kaname#258 п. 2;
// Ф12 Р2, редакции 16–17). Текст — литералом из приёмки.
package loginlanehttp_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
)

// stepSecondFactorUnavailable — Ф12 Р2: материал не открывается; дословно.
const stepSecondFactorUnavailable = "second factor cannot be verified; ask the administrator of this installation"

// TestLane_F12_35_UnavailableNamesTheOperatorStep — Ф12-35 (в), (г) на
// транспорте: `503` / `14` текстом Р2, без `Retry-After`; ни «позже», ни класса
// причины. Текст один на все глаголы сверки кода — вход, step-up, подтверждение.
func TestLane_F12_35_UnavailableNamesTheOperatorStep(t *testing.T) {
	stub := &stubLane{
		loginErr:   humansession.ErrSecondFactorUnavailable,
		stepUpErr:  humansession.ErrSecondFactorUnavailable,
		confirmErr: humansession.ErrSecondFactorUnavailable,
	}
	l := newLane(t, stub, "")
	c := l.client(t, gatewaySAN)
	sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}

	loginTok, loginCk := l.csrf(t, c, "login", nil)
	login := l.do(t, c, http.MethodPost, loginlanehttp.PathLogin, map[string]any{
		"email": "a@example.invalid", "password": "pw", "csrfToken": loginTok,
		"secondFactor": map[string]string{"method": "totp", "code": "123456"},
	}, fwd(), loginCk)
	require.Equal(t, http.StatusServiceUnavailable, login.status, login.body)
	require.Equal(t, refusalWire(14, stepSecondFactorUnavailable), login.body, "Ф12-35: текст Р2 дословно")
	require.Empty(t, login.header.Get("Retry-After"), "повтор ничего не восстановит — срока нет")

	suTok, suCk := l.csrf(t, c, "step-up", loginCk)
	stepUp := l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up", map[string]string{"method": "lookup_secret", "code": "ABCDEFGH12", "csrfToken": suTok}, fwd(), suCk, sess)
	require.Equal(t, http.StatusServiceUnavailable, stepUp.status)
	require.Equal(t, login.body, stepUp.body, "текст один на глаголы и способы")
	require.Empty(t, stepUp.header.Get("Retry-After"))

	requireNamesNoCause(t, stepSecondFactorUnavailable,
		"temporarily", "try again", "later", "key", "wrap", "secret", "material", "decrypt", "encrypt")
}

// TestLane_F12_35_UnavailableLeavesTheRecordToTheVerb — Ф12-35 (в), (г): запись
// журнала уровня ошибки о неоткрывающемся материале одна на предъявление и живёт
// в общей сверке глагола (`sf_present.go`, kaname#700), где известны личность и
// способ. Край на этой ветви отвечает 503 и НЕ пишет второй записи; близнец той
// же формы — неклассифицированный отказ — край пишет сам (иначе проба молчала
// бы на любом журнале).
func TestLane_F12_35_UnavailableLeavesTheRecordToTheVerb(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		records int
	}{
		{"second factor unavailable", humansession.ErrSecondFactorUnavailable, 0},
		{"twin: unclassified refusal", errUnclassifiedForLog, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
			l := newLaneLogged(t, &stubLane{stepUpErr: tc.err}, logger)
			c := l.client(t, gatewaySAN)
			sess := &http.Cookie{Name: "kaname_session", Value: "bearer-1"}
			_, loginCk := l.csrf(t, c, "login", nil)
			suTok, suCk := l.csrf(t, c, "step-up", loginCk)
			r := l.do(t, c, http.MethodPost, "/iam/v1/auth/step-up",
				map[string]string{"method": "totp", "code": "123456", "csrfToken": suTok}, fwd(), suCk, sess)
			require.Equal(t, http.StatusServiceUnavailable, r.status, r.body)
			require.Equal(t, tc.records, bytes.Count(buf.Bytes(), []byte("\n")),
				"записей уровня ERROR у края: %s", buf.String())
		})
	}
}

// errUnclassifiedForLog — отказ вне словаря края: близнец, на котором край
// обязан писать сам.
var errUnclassifiedForLog = errors.New("probe: unclassified refusal")

// newLaneLogged — слушатель над дублёром глаголов с журналом, который читает
// проба (у `newLaneOver` журнал выброшен).
func newLaneLogged(t *testing.T, stub *stubLane, logger *slog.Logger) *lane {
	t.Helper()
	ca := newCA(t)
	h, err := loginlanehttp.New(loginlanehttp.Config{
		SessionTTL:    24 * time.Hour,
		TrustDomain:   grpcsrv.NewTrustDomain(trustDomain),
		Modules:       laneRoster(t),
		RefusalDomain: "iam.kaname.cloud",
		Logger:        logger,
	}, stub)
	require.NoError(t, err)
	srv := httptest.NewUnstartedServer(h)
	pool := x509.NewCertPool()
	pool.AddCert(ca.cert)
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.leaf(t, "", x509.ExtKeyUsageServerAuth)},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &lane{srv: srv, ca: ca, stub: stub}
}

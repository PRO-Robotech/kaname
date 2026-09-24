// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pace_test.go — отказы по темпу у токен-эндпоинта (kaname#315, п. 3 и 4
// предиката снятия).
//
// Две оси, решаемые ДО того, как запрос назвал клиента по реестру:
//
//   - потолок одновременных обменов — держит эндпоинт;
//   - обменов в секунду на идентификатор клиента — судит проверяющий по
//     заявленному идентификатору, эндпоинт отдаёт его исход.
//
// У обеих свой исход в закрытом словаре, свой счётчик и свой код ответа, НЕ
// сливающийся с отказом аутентификации: отказ по темпу говорит «повторите
// позже», а не «учётные данные неверны», и чужая библиотека, прочитав второе,
// стала бы чинить не то.
package clienttokenhttp_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/client_token"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// pacedVerifier — проверяющий, чей исход задаёт проба, и который считает вызовы.
type pacedVerifier struct {
	calls  atomic.Int64
	result clientassertion.Result
	err    error
}

func (p *pacedVerifier) Verify(context.Context, string, string) (clientassertion.Result, error) {
	p.calls.Add(1)
	return p.result, p.err
}

func (p *pacedVerifier) VerifyFederated(context.Context, string) (clientassertion.Result, error) {
	p.calls.Add(1)
	return p.result, p.err
}

// blockingIssuer — выдача, удерживающая обмен до сигнала пробы.
//
// Сигнал входа буферизован: обмен, прошедший мимо потолка, обязан не вешать
// пробу, а стать её находкой.
type blockingIssuer struct {
	entered chan struct{}
	release chan struct{}
}

func newBlockingIssuer() *blockingIssuer {
	return &blockingIssuer{entered: make(chan struct{}, 16), release: make(chan struct{})}
}

func (b *blockingIssuer) Issue(context.Context, client_token.Input) (client_token.Output, clientassertion.Outcome, error) {
	b.entered <- struct{}{}
	<-b.release
	return client_token.Output{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 900}, clientassertion.OutcomeAccepted, nil
}

func newPacedHandler(t *testing.T, ceiling int, v clienttokenhttp.Verifier, i clienttokenhttp.Issuer) *clienttokenhttp.Handler {
	t.Helper()
	h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
		BodyCeiling:     testBodyCeiling,
		InFlightCeiling: ceiling,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, v, i)
	require.NoError(t, err)
	return h
}

func postTo(h http.Handler) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(goodForm().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// requireOnlyCounter — двинулся ровно названный счётчик, и ровно на n.
func requireOnlyCounter(t *testing.T, h *clienttokenhttp.Handler, want clientassertion.Outcome, n uint64) {
	t.Helper()
	for o, c := range h.Outcomes() {
		if o == want {
			require.EqualValuesf(t, n, c, "счётчик исхода %s", o)
			continue
		}
		require.Zerof(t, c, "исход %s двинул чужой счётчик %s", want, o)
	}
}

// TestClientPaceRefusalHasItsOwnCodeAndCounter — превышение темпа клиента даёт
// свой код, срок ожидания и свой счётчик.
func TestClientPaceRefusalHasItsOwnCodeAndCounter(t *testing.T) {
	v := &pacedVerifier{
		result: clientassertion.Result{Outcome: clientassertion.OutcomeClientPaceExceeded, RetryAfter: 1500 * time.Millisecond},
		err:    context.DeadlineExceeded, // любой отказ; исход решает Outcome
	}
	h := newPacedHandler(t, 4, v, &stubIssuer{})

	rec := postTo(h)
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "2", rec.Header().Get("Retry-After"),
		"срок ожидания округляется ВВЕРХ до целых секунд: округление вниз звало бы повтор раньше, чем он пройдёт")
	require.Equal(t, "temporarily_unavailable", errorCode(t, rec.Body.Bytes()))
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	requireOnlyCounter(t, h, clientassertion.OutcomeClientPaceExceeded, 1)

	// Отказ по темпу обязан отличаться от отказа аутентификации: тот —
	// «неверный клиент», этот — «повторите позже».
	auth := newStand(t)
	auth.verifier.outcome = clientassertion.OutcomeSignatureMismatch
	authRec := auth.post(t, goodForm())
	require.Equal(t, http.StatusUnauthorized, authRec.Code)
	require.NotEqual(t, authRec.Body.String(), rec.Body.String())

	// Законный близнец: под порогом обмен проходит.
	ok := newPacedHandler(t, 4, &pacedVerifier{result: clientassertion.Result{Outcome: clientassertion.OutcomeAccepted}}, &stubIssuer{})
	require.Equal(t, http.StatusOK, postTo(ok).Code)
	requireOnlyCounter(t, ok, clientassertion.OutcomeAccepted, 1)
}

// TestInFlightCeilingRefusesAboveItBeforeAuthentication — обмен сверх потолка
// одновременных отвергается своим исходом и до проверяющего не доходит.
func TestInFlightCeilingRefusesAboveItBeforeAuthentication(t *testing.T) {
	v := &pacedVerifier{result: clientassertion.Result{Outcome: clientassertion.OutcomeAccepted}}
	issuer := newBlockingIssuer()
	h := newPacedHandler(t, 1, v, issuer)
	defer func() {
		select {
		case <-issuer.release:
		default:
			close(issuer.release)
		}
	}()

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- postTo(h) }()
	<-issuer.entered // первый обмен занял единственное место

	second := make(chan *httptest.ResponseRecorder, 1)
	go func() { second <- postTo(h) }()
	var rec *httptest.ResponseRecorder
	select {
	case rec = <-second:
	case <-issuer.entered:
		t.Fatal("второй обмен прошёл сверх потолка одновременных и дошёл до выдачи")
	case <-time.After(10 * time.Second):
		t.Fatal("второй обмен не получил ответа за 10 с: потолок не отказал")
	}
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	require.Equal(t, "1", rec.Header().Get("Retry-After"))
	require.Equal(t, "temporarily_unavailable", errorCode(t, rec.Body.Bytes()))
	require.EqualValues(t, 1, v.calls.Load(),
		"обмен сверх потолка не имеет права дойти до проверяющего: потолок бережёт именно проверку")
	require.EqualValues(t, 1, h.Outcomes()[clientassertion.OutcomeInFlightCeilingReached])

	close(issuer.release)
	require.Equal(t, http.StatusOK, (<-first).Code)

	// Законный близнец: освобождённое место принимает следующий обмен.
	require.Equal(t, http.StatusOK, postTo(h).Code, "место обязано освобождаться по завершении обмена")
	require.EqualValues(t, 1, h.Outcomes()[clientassertion.OutcomeInFlightCeilingReached])
	require.EqualValues(t, 2, h.Outcomes()[clientassertion.OutcomeAccepted])
}

// TestInFlightSlotIsReleasedOnRefusalToo — место освобождается и на отказе:
// иначе каждый отказ навсегда отнимал бы одно место.
func TestInFlightSlotIsReleasedOnRefusalToo(t *testing.T) {
	v := &pacedVerifier{}
	v.result, v.err = clientassertion.Refuse(clientassertion.OutcomeSignatureMismatch, "probe")
	h := newPacedHandler(t, 1, v, &stubIssuer{})
	for i := 0; i < 3; i++ {
		require.Equal(t, http.StatusUnauthorized, postTo(h).Code, "обмен %d", i+1)
	}
	require.Zero(t, h.Outcomes()[clientassertion.OutcomeInFlightCeilingReached])
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// federated_grant_test.go — эндпоинт принимает федеративную выдачу (задача
// #1124, RFC 7523 §2.1).
//
// # Чем эта полоса отличается на уровне ФОРМЫ ЗАПРОСА
//
// Полоса аутентификации клиента приходит парой `client_assertion` +
// `client_assertion_type` при виде выдачи «учётные данные клиента»: утверждение
// там доказывает ЛИЧНОСТЬ КЛИЕНТА. Федеративная приходит одним параметром
// `assertion` при виде выдачи jwt-bearer: утверждение там и есть ОСНОВАНИЕ
// ВЫДАЧИ, а клиента, который себя аутентифицирует, нет вовсе.
//
// Смешение форм — не педантизм: приняв `client_assertion` на федеративном виде
// выдачи, мы позволили бы предъявителю выбирать, какой проверкой его проверят.
package clienttokenhttp_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
)

// federatedForm — законная форма федеративной выдачи.
func federatedForm() url.Values {
	return url.Values{
		"grant_type": {tokenpolicy.GrantTypeJWTBearer},
		"assertion":  {"header.payload.signature"},
	}
}

// TestFederatedGrantIsServedByTheFederatedLane — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ:
// федеративный вид выдачи обслуживается, и обслуживает его ФЕДЕРАТИВНАЯ полоса
// проверяющего, а не полоса аутентификации клиента.
func TestFederatedGrantIsServedByTheFederatedLane(t *testing.T) {
	s := newStand(t)
	rec := s.post(t, federatedForm())

	require.Equal(t, http.StatusOK, rec.Code, "тело: %s", rec.Body.String())
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "tok", body["access_token"])

	require.Equal(t, "header.payload.signature", s.verifier.seenFederatedRaw,
		"утверждение обязано уйти в федеративную полосу")
	require.Empty(t, s.verifier.seenRaw,
		"полоса аутентификации клиента на этом виде выдачи не участвует вовсе")
}

// TestClientAssertionParamsAreNotAcceptedOnTheFederatedGrant — форму нельзя
// смешивать.
//
// Приняв пару полосы клиента на федеративном виде выдачи, эндпоинт позволил бы
// предъявителю ВЫБИРАТЬ, какой проверкой его проверят, — а проверки эти берут
// ключ из разных источников.
func TestClientAssertionParamsAreNotAcceptedOnTheFederatedGrant(t *testing.T) {
	s := newStand(t)
	form := federatedForm()
	form.Set("client_assertion", "header.payload.signature")
	form.Set("client_assertion_type", tokenpolicy.ClientAssertionType)

	rec := s.post(t, form)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, s.verifier.seenFederatedRaw, "проверка не должна была состояться")
	require.Empty(t, s.verifier.seenRaw)
}

// TestFederatedAssertionMustAppearExactlyOnce — ровно одно утверждение.
//
// Требование к НАШЕМУ разбору, а не описание намерения клиента: форма позволяет
// прислать параметр дважды, и разбор, берущий первое значение, проверил бы не
// то, что подписал предъявитель.
func TestFederatedAssertionMustAppearExactlyOnce(t *testing.T) {
	s := newStand(t)

	none := url.Values{"grant_type": {tokenpolicy.GrantTypeJWTBearer}}
	require.Equal(t, http.StatusBadRequest, s.post(t, none).Code, "утверждения нет вовсе")

	twice := url.Values{
		"grant_type": {tokenpolicy.GrantTypeJWTBearer},
		"assertion":  {"a.b.c", "d.e.f"},
	}
	require.Equal(t, http.StatusBadRequest, s.post(t, twice).Code, "утверждение дважды")
	require.Empty(t, s.verifier.seenFederatedRaw, "проверка не должна была состояться")

	// Положительный контроль: ровно одно проходит. Без него проба зелена на
	// эндпоинте, отвергающем федеративную выдачу целиком.
	require.Equal(t, http.StatusOK, s.post(t, federatedForm()).Code)
}

// TestPlainAssertionParamIsNotAcceptedOnTheClientCredentialsGrant — зеркальная
// сторона: параметр федеративной полосы не принимается на виде выдачи «учётные
// данные клиента».
//
// Без этой стороны запрет был бы односторонним, а смешение форм — предмет
// симметричный: выбирать проверку не вправе ни один вид выдачи.
func TestPlainAssertionParamIsNotAcceptedOnTheClientCredentialsGrant(t *testing.T) {
	s := newStand(t)
	form := goodForm()
	form.Set("assertion", "header.payload.signature")

	rec := s.post(t, form)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Empty(t, s.verifier.seenRaw, "проверка не должна была состояться")
}

// TestFederatedRefusalLooksLikeEveryOtherRefusal — отказ федеративной полосы
// неотличим снаружи от прочих.
//
// Различимый отказ есть оракул: по нему устанавливают, доверена ли пара, то
// есть ровно то, что перечень доверенных издателей и скрывает.
func TestFederatedRefusalLooksLikeEveryOtherRefusal(t *testing.T) {
	s := newStand(t)
	s.verifier.outcome = clientassertion.OutcomeIssuerUntrusted
	fed := s.post(t, federatedForm())

	c := newStand(t)
	c.verifier.outcome = clientassertion.OutcomeClientUnknown
	client := c.post(t, goodForm())

	require.Equal(t, http.StatusUnauthorized, fed.Code)
	require.Equal(t, client.Code, fed.Code)
	require.JSONEq(t, client.Body.String(), fed.Body.String(),
		"ответ предъявителю обязан быть один и тот же: иначе он оракул состава перечня")
}

// TestUnknownGrantTypeIsStillRefused — закрытый перечень видов выдачи остался
// закрытым: заведение второго вида не превратило его в корзину «прочее».
func TestUnknownGrantTypeIsStillRefused(t *testing.T) {
	s := newStand(t)
	form := federatedForm()
	form.Set("grant_type", "urn:example:some-other-grant")

	rec := s.post(t, form)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "unsupported_grant_type", body["error"])
}

// verifierSeesFederatedContext — предел времени и контекст запроса доезжают до
// федеративной полосы так же, как до полосы клиента.
func TestFederatedLaneReceivesTheRequestContext(t *testing.T) {
	s := newStand(t)
	s.verifier.captureCtx = true
	require.Equal(t, http.StatusOK, s.post(t, federatedForm()).Code)
	require.NotNil(t, s.verifier.seenCtx)
	require.NoError(t, s.verifier.seenCtx.Err())
	var _ context.Context = s.verifier.seenCtx
}

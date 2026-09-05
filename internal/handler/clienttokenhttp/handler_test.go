// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_test.go — токен-эндпоинт (приёмка F2, сценарии F2-02, F2-11, F2-33,
// F2-43, F2-45).
package clienttokenhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/handler/clienttokenhttp"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// countingBody — тело, считающее ПРОЧИТАННЫЕ байты.
//
// Проба утверждает ПАРУ: исход И число прочитанных байт. Один код ответа
// свойства «отказ ДО чтения тела» не измеряет вовсе — тот же код возвращается и
// после того, как тело прочитано целиком.
type countingBody struct {
	r    io.Reader
	read int
}

func (c *countingBody) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.read += n
	return n, err
}
func (c *countingBody) Close() error { return nil }

// stubVerifier — проверяющий.
type stubVerifier struct {
	outcome clientassertion.Outcome
	seenTyp string
	seenRaw string
	// seenFederatedRaw — что дошло до ФЕДЕРАТИВНОЙ полосы. Отдельное поле, а не
	// то же: проба обязана различать, какая из двух полос проверяла, — иначе
	// «утверждение проверено» осталось бы верным при проверке не той полосой.
	seenFederatedRaw string
	captureCtx       bool
	seenCtx          context.Context
}

func (s *stubVerifier) Verify(ctx context.Context, typ, raw string) (clientassertion.Result, error) {
	s.seenTyp, s.seenRaw = typ, raw
	if s.captureCtx {
		s.seenCtx = ctx
	}
	return s.result()
}

func (s *stubVerifier) VerifyFederated(ctx context.Context, raw string) (clientassertion.Result, error) {
	s.seenFederatedRaw = raw
	if s.captureCtx {
		s.seenCtx = ctx
	}
	return s.result()
}

func (s *stubVerifier) result() (clientassertion.Result, error) {
	if s.outcome == "" || s.outcome == clientassertion.OutcomeAccepted {
		return clientassertion.Result{Outcome: clientassertion.OutcomeAccepted}, nil
	}
	return clientassertion.Refuse(s.outcome, "stub refusal")
}

// stubIssuer — выдача.
type stubIssuer struct {
	outcome clientassertion.Outcome
	seen    client_token.Input
}

func (s *stubIssuer) Issue(_ context.Context, in client_token.Input) (client_token.Output, clientassertion.Outcome, error) {
	s.seen = in
	if s.outcome == "" || s.outcome == clientassertion.OutcomeAccepted {
		return client_token.Output{AccessToken: "tok", TokenType: "Bearer", ExpiresIn: 900}, clientassertion.OutcomeAccepted, nil
	}
	return client_token.Output{}, s.outcome, errors.New("stub issuance refusal")
}

// testBodyCeiling — потолок тела в пробах. Число фикстуры, а не объявление
// величины: величину объявляет профиль развёртывания, и построение требует её
// заданной.
const testBodyCeiling int64 = 64 << 10

type stand struct {
	h        *clienttokenhttp.Handler
	verifier *stubVerifier
	issuer   *stubIssuer
}

func newStand(t *testing.T) stand {
	t.Helper()
	v, i := &stubVerifier{}, &stubIssuer{}
	h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
		// Потолок задаётся ЯВНО: у построения умолчания нет, и это не
		// неудобство пробы, а условие того, чтобы страж старта мог отличить
		// заданную величину от незаданной.
		BodyCeiling: testBodyCeiling,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, v, i)
	require.NoError(t, err)
	return stand{h: h, verifier: v, issuer: i}
}

func goodForm() url.Values {
	return url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {"header.payload.signature"},
	}
}

func (s stand) post(t *testing.T, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, req)
	return rec
}

// TestF2_45_OnlyTheDeclaredMethodIsServed — обращение иным методом отвергается
// ответом, несущим перечень допустимых.
func TestF2_45_OnlyTheDeclaredMethodIsServed(t *testing.T) {
	s := newStand(t)
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodHead} {
		rec := httptest.NewRecorder()
		s.h.ServeHTTP(rec, httptest.NewRequest(m, clienttokenhttp.TokenPath, nil))
		require.Equal(t, http.StatusMethodNotAllowed, rec.Code, "метод %s", m)
		require.Equal(t, http.MethodPost, rec.Header().Get("Allow"), "метод %s", m)
	}

	// Положительный контроль: объявленный метод ОБСЛУЖИВАЕТСЯ. Без него проба
	// зелена на эндпоинте, не отвечающем ни на что.
	require.Equal(t, http.StatusOK, s.post(t, goodForm()).Code)
}

// TestF2_45_EndpointResolvesOnItsDeclaredPathAndNoOther — перечень путей
// ВЫВОДИТСЯ из объявления, а не выписывается.
func TestF2_45_EndpointResolvesOnItsDeclaredPathAndNoOther(t *testing.T) {
	s := newStand(t)
	mux := clienttokenhttp.NewMux(s.h)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(goodForm().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	// Соседние пути этим mux'ом не обслуживаются — в том числе путь ПРЕЖНЕГО
	// токен-эндпоинта: два эндпоинта на одном пути были бы двумя правилами об
	// одном предмете.
	for _, path := range []string{"/", "/iam/token", "/iam/v1/token/extra", "/.well-known/jwks.json"} {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		require.Equal(t, http.StatusNotFound, rec.Code, "путь %s", path)
	}
}

// TestF2_11_BodyCeilingRefusesBeforeReadingAnyByte — утверждается ПАРА: исход и
// число прочитанных байт.
func TestF2_11_BodyCeilingRefusesBeforeReadingAnyByte(t *testing.T) {
	v, i := &stubVerifier{}, &stubIssuer{}
	const ceiling = 512
	h, err := clienttokenhttp.NewHandler(clienttokenhttp.Config{
		BodyCeiling: ceiling,
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}, v, i)
	require.NoError(t, err)

	// Объявленная длина сверх потолка: НИ ОДНОГО байта не прочитано.
	body := &countingBody{r: bytes.NewReader(bytes.Repeat([]byte("x"), ceiling*4))}
	req := httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = ceiling * 4
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusRequestEntityTooLarge, rec.Code)
	require.Zero(t, body.read, "тело обязано остаться непрочитанным: отказ после разбора память не экономит")

	// Тело сверх потолка БЕЗ объявленной длины тоже отвергается: чтение
	// ограничено потолком, а не только объявленной длиной.
	big := url.Values{
		"grant_type":            {tokenpolicy.GrantTypeClientCredentials},
		"client_assertion_type": {tokenpolicy.ClientAssertionType},
		"client_assertion":      {strings.Repeat("a", ceiling*4)},
	}.Encode()
	req = httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(big))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.ContentLength = -1
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.NotEqual(t, http.StatusOK, rec.Code, "тело сверх потолка обязано быть отвергнуто и без объявленной длины")

	// Положительный контроль: запрос в пределах потолка читается и
	// обрабатывается.
	req = httptest.NewRequest(http.MethodPost, clienttokenhttp.TokenPath, strings.NewReader(goodForm().Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

// TestF2_02_ExactlyOneAssertionIsAccepted — «ровно одно утверждение» есть
// требование к нашему разбору, а не описание намерения клиента.
func TestF2_02_ExactlyOneAssertionIsAccepted(t *testing.T) {
	s := newStand(t)

	twice := goodForm()
	twice["client_assertion"] = []string{"first.a.b", "second.c.d"}
	rec := s.post(t, twice)
	require.Equal(t, http.StatusBadRequest, rec.Code)
	// Отказ наступает ДО проверки подписи ЛЮБОГО из двух значений.
	require.Empty(t, s.verifier.seenRaw, "проверяющий не должен был получить ни одного значения")

	// Вид предъявления, названный дважды, — то же самое.
	s2 := newStand(t)
	twiceType := goodForm()
	twiceType["client_assertion_type"] = []string{tokenpolicy.ClientAssertionType, tokenpolicy.ClientAssertionType}
	require.Equal(t, http.StatusBadRequest, s2.post(t, twiceType).Code)
	require.Empty(t, s2.verifier.seenRaw)

	// Отсутствие параметра — тот же исход формы.
	s3 := newStand(t)
	none := goodForm()
	delete(none, "client_assertion")
	require.Equal(t, http.StatusBadRequest, s3.post(t, none).Code)

	// Положительный контроль: ровно одно значение доезжает до проверяющего КАК
	// ЕСТЬ.
	s4 := newStand(t)
	require.Equal(t, http.StatusOK, s4.post(t, goodForm()).Code)
	require.Equal(t, "header.payload.signature", s4.verifier.seenRaw)
	require.Equal(t, tokenpolicy.ClientAssertionType, s4.verifier.seenTyp)
}

// TestF2_43_GrantTypeDictionaryIsClosed — «прочее» не является корзиной приёма.
//
// Видов в словаре ДВА с задачи #1124 (второй — федеративная выдача), и это не
// ослабление: перечень по-прежнему закрыт и перечисляет оба поимённо. Проба
// сверяет перечень отвергаемых с ОБЪЯВЛЕННЫМ словарём, а не со своим списком —
// иначе третий заведённый вид остался бы ею незамеченным.
func TestF2_43_GrantTypeDictionaryIsClosed(t *testing.T) {
	s := newStand(t)
	for _, g := range []string{
		"authorization_code",
		"refresh_token",
		"password",
		"CLIENT_CREDENTIALS",
		"client_credentials ",
		"urn:ietf:params:oauth:grant-type:jwt-bearer ",
		"URN:IETF:PARAMS:OAUTH:GRANT-TYPE:JWT-BEARER",
		"",
	} {
		form := goodForm()
		form.Set("grant_type", g)
		rec := s.post(t, form)
		require.Equal(t, http.StatusBadRequest, rec.Code, "вид выдачи %q", g)
		require.Equal(t, "unsupported_grant_type", errorCode(t, rec.Body.Bytes()), "вид выдачи %q", g)
	}

	// Ни один вид из объявленного словаря не отвергается как неизвестный —
	// иначе объявление и приём разошлись бы молча.
	require.Len(t, tokenpolicy.GrantTypes(), 2)
	require.Equal(t, http.StatusOK, s.post(t, goodForm()).Code)
}

// TestF2_33_EveryAuthenticationRefusalLooksIdenticalAndEachHasItsOwnCounter —
// перепись, а не выборка.
func TestF2_33_EveryAuthenticationRefusalLooksIdenticalAndEachHasItsOwnCounter(t *testing.T) {
	// Исходы, наступающие ПОСЛЕ того, как запрос назвал клиента, обязаны
	// выглядеть наружу побайтово одинаково.
	verifierOutcomes := []clientassertion.Outcome{
		clientassertion.OutcomeAssertionTypeMismatch,
		clientassertion.OutcomeMalformedSerialization,
		clientassertion.OutcomeDuplicateHeaderMember,
		clientassertion.OutcomeUnsupportedCritical,
		// Объявленный тип утверждения — третий независимый признак разделения
		// двух видов подписанного. Перепись поймала его без входа раньше
		// человека: исход завёлся, а подающего его входа не было.
		clientassertion.OutcomeTokenTypeMismatch,
		clientassertion.OutcomeAlgorithmNotAllowed,
		clientassertion.OutcomeAlgorithmMismatch,
		clientassertion.OutcomeIdentityMismatch,
		clientassertion.OutcomeClientUnknown,
		clientassertion.OutcomeClientCannotAssert,
		// Два исхода федеративной полосы (#1124). Перепись потребовала их
		// входов раньше человека — ровно так, как и задумана.
		clientassertion.OutcomeIssuerUntrusted,
		clientassertion.OutcomeTrustExpired,
		clientassertion.OutcomeSignatureMismatch,
		clientassertion.OutcomeAudienceMismatch,
		clientassertion.OutcomeExpiryMissing,
		clientassertion.OutcomeIssuedAtMissing,
		clientassertion.OutcomeIssuedAtInFuture,
		clientassertion.OutcomeLifetimeAboveCeiling,
		clientassertion.OutcomeExpired,
		clientassertion.OutcomeNotYetValid,
		clientassertion.OutcomeAssertionIDMissing,
		clientassertion.OutcomeReplayed,
		clientassertion.OutcomeRegistryUnavailable,
		clientassertion.OutcomeReplayStoreUnavailable,
	}
	issuerOutcomes := []clientassertion.Outcome{
		clientassertion.OutcomeAudienceNotAllowed,
		clientassertion.OutcomeClientExpired,
		clientassertion.OutcomeOwnerNotActive,
		clientassertion.OutcomeIssuanceFailed,
	}

	var reference []byte
	seen := map[clientassertion.Outcome]bool{}

	check := func(s stand, o clientassertion.Outcome) {
		rec := s.post(t, goodForm())
		require.Equal(t, http.StatusUnauthorized, rec.Code, "исход %s", o)
		if reference == nil {
			reference = append([]byte(nil), rec.Body.Bytes()...)
		}
		// ПОБАЙТОВОЕ совпадение: различимый ответ есть оракул.
		require.Equal(t, string(reference), rec.Body.String(), "исход %s различим снаружи", o)

		// Двинулся ИМЕННО ТОТ счётчик — перепись, а не выборка.
		counts := s.h.Outcomes()
		require.EqualValues(t, 1, counts[o], "исход %s: счётчик не двинулся", o)
		for other, n := range counts {
			if other != o {
				require.Zerof(t, n, "исход %s двинул чужой счётчик %s", o, other)
			}
		}
		seen[o] = true
	}

	for _, o := range verifierOutcomes {
		s := newStand(t)
		s.verifier.outcome = o
		check(s, o)
	}
	for _, o := range issuerOutcomes {
		s := newStand(t)
		s.issuer.outcome = o
		check(s, o)
	}

	// У КАЖДОГО исхода закрытого словаря есть счётчик — в том числе у тех, что
	// проба не производила. Счётчик, появляющийся при первом отказе, не
	// отличает «ноль отказов» от «исхода без счётчика», и мёртвый контроль на
	// нём снова становится невидимым.
	counts := newStand(t).h.Outcomes()
	for _, o := range clientassertion.Outcomes() {
		_, ok := counts[o]
		require.Truef(t, ok, "исход %s заведён в словаре, а счётчика у него нет", o)
	}
	require.Len(t, counts, len(clientassertion.Outcomes()))

	// Ни один исход словаря не остался неучтённым пробой сверх тех, что
	// производит сам эндпоинт: перечень выше — ВЫБОРКА из словаря, и она
	// обязана быть полной по своей половине.
	for _, o := range clientassertion.Outcomes() {
		switch o {
		case clientassertion.OutcomeAccepted,
			clientassertion.OutcomeMethodNotAllowed,
			clientassertion.OutcomeBodyAboveCeiling,
			clientassertion.OutcomeMalformedRequest,
			clientassertion.OutcomeMultipleAssertions,
			clientassertion.OutcomeUnsupportedGrantType:
			// Эти пять решаются ДО того, как запрос назвал клиента, и им
			// положены свои стандартные коды — их проверяют пробы выше.
			continue
		}
		require.Truef(t, seen[o], "исход %s не подан ни одним входом пробы", o)
	}
}

// TestTransportRefusalsAreDistinguishableAndSayWhatIsWrong — пять отказов,
// решаемых ДО того, как запрос назвал клиента, обязаны иметь СВОИ коды.
//
// Свести их к «неверный клиент» значило бы сказать чужой библиотеке неправду:
// она стала бы чинить учётные данные там, где велико тело или не тот метод.
func TestTransportRefusalsAreDistinguishableAndSayWhatIsWrong(t *testing.T) {
	s := newStand(t)

	rec := httptest.NewRecorder()
	s.h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, clienttokenhttp.TokenPath, nil))
	require.Equal(t, http.StatusMethodNotAllowed, rec.Code)

	form := goodForm()
	form.Set("grant_type", "password")
	require.Equal(t, "unsupported_grant_type", errorCode(t, s.post(t, form).Body.Bytes()))

	// А отказ аутентификации — «неверный клиент», и ничего сверх.
	s2 := newStand(t)
	s2.verifier.outcome = clientassertion.OutcomeSignatureMismatch
	require.Equal(t, "invalid_client", errorCode(t, s2.post(t, goodForm()).Body.Bytes()))
}

// TestRefusalCarriesNoDiagnosticsOutward — ни исход, ни предъявленное
// утверждение наружу не уходят.
func TestRefusalCarriesNoDiagnosticsOutward(t *testing.T) {
	s := newStand(t)
	s.verifier.outcome = clientassertion.OutcomeReplayed
	form := goodForm()
	const secret = "header.PAYLOAD-SECRET.signature"
	form.Set("client_assertion", secret)
	rec := s.post(t, form)
	body := rec.Body.String()

	require.NotContains(t, body, string(clientassertion.OutcomeReplayed))
	require.NotContains(t, body, secret, "предъявленное утверждение наружу не уходит")
	require.NotContains(t, body, "PAYLOAD-SECRET")

	// Контроль читателя: подсаженное заведомо присутствующее значение проба
	// обязана НАЙТИ. Утверждение об отсутствии зелено на читателе, который не
	// читает ничего.
	require.Contains(t, body, "invalid_client")
}

// TestRequestedAudienceReachesIssuanceAsGiven — адресат берётся ИЗ ЗАПРОСА.
func TestRequestedAudienceReachesIssuanceAsGiven(t *testing.T) {
	s := newStand(t)
	form := goodForm()
	form["audience"] = []string{"https://a.example", "https://b.example"}
	form.Set("scope", "registry:pull")
	require.Equal(t, http.StatusOK, s.post(t, form).Code)
	require.Equal(t, []string{"https://a.example", "https://b.example"}, s.issuer.seen.RequestedAudience)
	require.Equal(t, "registry:pull", s.issuer.seen.Scope)
}

// TestHandlerRefusesToBuildWithoutItsPorts — эндпоинт без проверяющего принимал
// бы кого угодно, без выдачи — не выдавал бы никому, а без потолка тела читал
// бы сколько прислали.
//
// Потолок стоит здесь наравне с портами намеренно. Пока построение
// подставляло его молча, страж старта не мог отличить заданную величину от
// незаданной: она не бывала незаданной. Умолчание, снимающее вопрос, снимает и
// проверку — и снимает её тише, чем отсутствие проверки.
func TestHandlerRefusesToBuildWithoutItsPorts(t *testing.T) {
	full := clienttokenhttp.Config{BodyCeiling: testBodyCeiling}
	_, err := clienttokenhttp.NewHandler(full, nil, &stubIssuer{})
	require.Error(t, err)
	_, err = clienttokenhttp.NewHandler(full, &stubVerifier{}, nil)
	require.Error(t, err)
	_, err = clienttokenhttp.NewHandler(clienttokenhttp.Config{}, &stubVerifier{}, &stubIssuer{})
	require.Error(t, err, "нулевой потолок тела означает «без потолка» и обязан отвергать построение")
	// Положительный контроль.
	_, err = clienttokenhttp.NewHandler(full, &stubVerifier{}, &stubIssuer{})
	require.NoError(t, err)
}

// TestSuccessfulResponseIsNotCached — ответ несёт предъявительский документ.
func TestSuccessfulResponseIsNotCached(t *testing.T) {
	s := newStand(t)
	rec := s.post(t, goodForm())
	require.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "tok", body["access_token"])
	require.Equal(t, "Bearer", body["token_type"])
	require.EqualValues(t, 900, body["expires_in"])
}

func errorCode(t *testing.T, body []byte) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m), "ответ обязан быть разбираем чужой библиотекой: %s", body)
	s, _ := m["error"].(string)
	require.NotEmpty(t, s, fmt.Sprintf("ответ обязан нести опознавательное слово: %s", body))
	return s
}

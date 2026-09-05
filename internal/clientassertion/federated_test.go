// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// federated_test.go — федеративная полоса проверяющего: утверждение подписал
// ВНЕШНИЙ издатель, а перечень доверенных издателей ведём мы (задача #1124).
//
// # Чем цена ошибки здесь отличается от полосы аутентификации клиента
//
// На полосе клиента ключ принадлежит строке, которую завели мы, и «принять
// чужое» требует подмены нашей же записи. Здесь ключ принадлежит ПОСТОРОННЕМУ
// издателю, а решение о доверии — наша запись. Значит промах даёт токен
// платформы предъявителю, которого мы не заводили вовсе, и выглядит это как
// исправная федерация.
//
// Отсюда состав утверждений: у каждого отрицания стоит положительный контроль
// на том же входе с ОДНИМ различием. Проба, все утверждения которой ждут
// отказа, зеленеет на проверяющем, отвергающем всё подряд.
package clientassertion_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

const (
	// testExternalIssuer — внешний издатель, чей ключ подписывает утверждение.
	testExternalIssuer = "https://token.actions.githubusercontent.com"
	// testExternalSubject — внешний субъект, которому выдано доверие.
	testExternalSubject = "repo:acme/infra:ref:refs/heads/main"
	// testFederatedClientID — НАША строка федеративного ключа.
	testFederatedClientID = "soc_0123456789abcdefg"
	testFederatedOwnerID  = "sva_0123456789abcdefg"
)

// stubTrustedIssuers — НАША таблица доверенных издателей.
//
// Дублёр не снисходительнее настоящего: на паре, которой в таблице нет, он
// отвечает тем же признаком, что настоящий, и строк не выдумывает. Пустая
// таблица здесь — законное состояние, и означает она «не доверяем НИКОМУ»;
// дублёр, отвечающий на пустой таблице приёмом, скрыл бы ровно тот дефект,
// ради которого проба написана.
type stubTrustedIssuers struct {
	rows map[string]domain.TrustedIssuer
	// client — наша строка, которую запись доверия уполномочивает.
	client domain.AssertionClient
	err    error
}

func (s stubTrustedIssuers) ResolveTrustedIssuer(_ context.Context, issuer, subject string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	if s.err != nil {
		return domain.TrustedIssuer{}, domain.AssertionClient{}, s.err
	}
	row, ok := s.rows[issuer+"\x00"+subject]
	if !ok {
		return domain.TrustedIssuer{}, domain.AssertionClient{}, domain.ErrTrustedIssuerUnknown
	}
	return row, s.client, nil
}

// fedFixture — стенд федеративной полосы.
type fedFixture struct {
	verifier *clientassertion.Verifier
	issuers  stubTrustedIssuers
	replay   *stubReplay
	// idpKey — ключ ВНЕШНЕГО издателя. Наш реестр его не содержит и содержать
	// не может: федеративная строка ключевого материала не несёт.
	idpKey testKey
}

// newFedFixture собирает стенд. Опции правят ЗАПИСЬ ДОВЕРИЯ — так видно, что
// различие между пробами ровно одно.
func newFedFixture(t *testing.T, opts ...func(*stubTrustedIssuers)) fedFixture {
	t.Helper()
	idp := newKey(t, tokenpolicy.AlgES256)
	trust := domain.TrustedIssuer{
		ClientID:     testFederatedClientID,
		Issuer:       testExternalIssuer,
		Subject:      testExternalSubject,
		PublicKeyPEM: idp.publicPEM,
		Algorithm:    idp.alg,
	}
	issuers := stubTrustedIssuers{
		rows: map[string]domain.TrustedIssuer{
			testExternalIssuer + "\x00" + testExternalSubject: trust,
		},
		client: domain.AssertionClient{
			ID:      testFederatedClientID,
			Kind:    domain.AssertionClientServiceAccount,
			OwnerID: testFederatedOwnerID,
			// Ключевого материала у федеративной строки НЕТ by construction:
			// подпись проверяется ключом издателя, а не клиента.
			OwnerActive: true,
		},
	}
	for _, o := range opts {
		o(&issuers)
	}
	rep := newReplay()
	v, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return testNow },
	}, stubRegistry{rows: map[string]domain.AssertionClient{}}, issuers, rep)
	require.NoError(t, err)
	return fedFixture{verifier: v, issuers: issuers, replay: rep, idpKey: idp}
}

// fedClaims — нагрузка внешнего утверждения, которая обязана приниматься.
//
// Издатель и субъект здесь РАЗНЫЕ, и это не оформление: на полосе клиента они
// обязаны совпадать и оба называть нашу строку, здесь — назвать постороннего
// издателя и его субъект.
func fedClaims(jti string) map[string]any {
	return map[string]any{
		"iss": testExternalIssuer,
		"sub": testExternalSubject,
		"aud": testIssuerID,
		"exp": testNow.Add(10 * time.Minute).Unix(),
		"iat": testNow.Unix(),
		"jti": jti,
	}
}

// fedHeader — заголовок внешнего утверждения.
//
// Объявленного НАМИ типа здесь нет и быть не может: тип ставит производитель, а
// производитель тут посторонний. Признак «это не наш токен доступа» на этой
// полосе даёт другое — подпись проверяется ключом ИЗДАТЕЛЯ, которым наш
// издатель не подписывает ничего.
func fedHeader(alg string) string {
	return header(jsonString("alg"), jsonString(alg), jsonString("kid"), jsonString("k1"))
}

func (f fedFixture) verifyFederated(t *testing.T, raw string) (clientassertion.Result, error) {
	t.Helper()
	return f.verifier.VerifyFederated(context.Background(), raw)
}

// TestVerifyFederated_TrustedPairFromOurTableIsAccepted — ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ всей полосы: пара (издатель, субъект) есть в НАШЕЙ таблице, подпись
// сошлась с зарегистрированным у неё ключом издателя — утверждение принято, и
// принято ЗА НАШУ строку.
func TestVerifyFederated_TrustedPairFromOurTableIsAccepted(t *testing.T) {
	f := newFedFixture(t)
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-fed-ok")),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	require.NoError(t, err, "законное федеративное утверждение обязано приниматься")
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	require.Equal(t, testFederatedClientID, res.Client.ID,
		"принято обязано быть ЗА нашу строку, а не за внешнего субъекта")
	require.Equal(t, testFederatedOwnerID, res.Client.OwnerID)
	require.Equal(t, "jti-fed-ok", res.AssertionID)
}

// TestVerifyFederated_EmptyTrustTableRefusesEveryone — ПУСТОЙ ПЕРЕЧЕНЬ ОЗНАЧАЕТ
// «НЕ ДОВЕРЯЕМ НИКОМУ», а не «не сужаем».
//
// Класс записан в корпусе (`security.md` §«Кто вправе говорить за
// пользователя»): величина, которая может быть пустой и не проверена на
// непустоту, означает «принимаем любого». Здесь предмет тот же, и вход
// подаётся ТОТ ЖЕ, что у положительного контроля выше, — различие ровно одно:
// таблица пуста.
func TestVerifyFederated_EmptyTrustTableRefusesEveryone(t *testing.T) {
	f := newFedFixture(t, func(s *stubTrustedIssuers) {
		s.rows = map[string]domain.TrustedIssuer{}
	})
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-empty-table")),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeIssuerUntrusted, res, err)
	require.Empty(t, res.Client.ID, "отказ не вправе называть строку")
}

// TestVerifyFederated_UntrustedPairIsRefused — таблица непуста, но ЭТОЙ пары в
// ней нет. Отличается от пробы выше тем, что доверие вообще-то выдано — другому
// субъекту того же издателя.
func TestVerifyFederated_UntrustedPairIsRefused(t *testing.T) {
	f := newFedFixture(t)
	cl := fedClaims("jti-other-subject")
	cl["sub"] = "repo:acme/infra:ref:refs/heads/attacker"
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(cl),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeIssuerUntrusted, res, err)
}

// TestVerifyFederated_SignatureOfAnotherKeyIsRefused — пара доверенная, ключ
// чужой. Без этой пробы принятым оказалось бы ЛЮБОЕ утверждение, называющее
// доверенную пару, — то есть доверие издателю выродилось бы в доверие строке.
func TestVerifyFederated_SignatureOfAnotherKeyIsRefused(t *testing.T) {
	f := newFedFixture(t)
	other := newKey(t, tokenpolicy.AlgES256)
	raw := assertion{
		headerJSON:  fedHeader(other.alg),
		payloadJSON: claims(fedClaims("jti-foreign-key")),
		key:         other,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeSignatureMismatch, res, err)
}

// TestVerifyFederated_AlgorithmMustEqualTheRegisteredOne — алгоритм заголовка
// сверяется с ЗАРЕГИСТРИРОВАННЫМ у записи доверия, и сверка стоит ДО проверки
// подписи.
func TestVerifyFederated_AlgorithmMustEqualTheRegisteredOne(t *testing.T) {
	f := newFedFixture(t)
	// Ключ издателя ES256; предъявитель объявляет RS256 и им же подписывает.
	rsa := newKey(t, tokenpolicy.AlgRS256)
	raw := assertion{
		headerJSON:  fedHeader(tokenpolicy.AlgRS256),
		payloadJSON: claims(fedClaims("jti-alg-swap")),
		key:         rsa,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeAlgorithmMismatch, res, err)
}

// TestVerifyFederated_ExpiredTrustIsRefused — запись доверия истекла. Доверие
// издателю не переживает объявленного ему срока: иначе снятие доверия
// сроком не работало бы вовсе.
func TestVerifyFederated_ExpiredTrustIsRefused(t *testing.T) {
	f := newFedFixture(t, func(s *stubTrustedIssuers) {
		row := s.rows[testExternalIssuer+"\x00"+testExternalSubject]
		row.ExpiresAt = testNow.Add(-time.Second).Unix()
		s.rows[testExternalIssuer+"\x00"+testExternalSubject] = row
	})
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-trust-expired")),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeTrustExpired, res, err)
}

// TestVerifyFederated_LiveTrustNearItsExpiryIsAccepted — положительный контроль
// к пробе выше: запись, чей срок ещё не наступил, принимается. Без него
// «истёкшее отвергается» зеленело бы на проверяющем, отвергающем всякое
// доверие со сроком.
func TestVerifyFederated_LiveTrustNearItsExpiryIsAccepted(t *testing.T) {
	f := newFedFixture(t, func(s *stubTrustedIssuers) {
		row := s.rows[testExternalIssuer+"\x00"+testExternalSubject]
		row.ExpiresAt = testNow.Add(time.Second).Unix()
		s.rows[testExternalIssuer+"\x00"+testExternalSubject] = row
	})
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-trust-live")),
		key:         f.idpKey,
	}.sign(t)

	_, err := f.verifyFederated(t, raw)
	require.NoError(t, err, "живая запись доверия обязана приниматься")
}

// TestVerifyFederated_TableUnavailableIsRefusedNeverPassed — недоступность
// НАШЕЙ таблицы есть отказ, никогда «пропустить». Мягкий проход здесь означал
// бы приём утверждения, о доверии к которому мы ничего не установили.
func TestVerifyFederated_TableUnavailableIsRefusedNeverPassed(t *testing.T) {
	f := newFedFixture(t, func(s *stubTrustedIssuers) {
		s.err = errors.New("dial: connection refused")
	})
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-registry-down")),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeRegistryUnavailable, res, err)
}

// TestVerifyFederated_ReplayedAssertionIsRefused — однократность действует и
// здесь: внешнее утверждение — такой же предъявительский документ.
func TestVerifyFederated_ReplayedAssertionIsRefused(t *testing.T) {
	f := newFedFixture(t)
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(fedClaims("jti-replay")),
		key:         f.idpKey,
	}.sign(t)

	_, err := f.verifyFederated(t, raw)
	require.NoError(t, err, "первое предъявление обязано приниматься")

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeReplayed, res, err)
}

// TestVerifyFederated_AudienceMustBeOurIssuer — адресат внешнего утверждения
// обязан называть НАС. Утверждение, выписанное этим же издателем для другого
// потребителя, принято быть не может: иначе токен платформы получал бы всякий,
// кому тот же издатель что-нибудь подписал.
func TestVerifyFederated_AudienceMustBeOurIssuer(t *testing.T) {
	f := newFedFixture(t)
	cl := fedClaims("jti-foreign-aud")
	cl["aud"] = "https://someone.else.example"
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(cl),
		key:         f.idpKey,
	}.sign(t)

	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeAudienceMismatch, res, err)
}

// TestVerifyFederated_LifetimeCeilingIsTheFederatedOne — потолок длительности
// на этой полосе СВОЙ, и он не равен потолку полосы клиента.
//
// Наш клиент подписывает утверждение специально для нас и вправе давать ему
// минуты. Внешний издатель выпускает своей нагрузке токен со СВОИМ сроком, и
// пятиминутный потолок отверг бы его целиком. Проба утверждает обе стороны:
// срок сверх федеративного потолка отвергается, в его пределах — принимается.
func TestVerifyFederated_LifetimeCeilingIsTheFederatedOne(t *testing.T) {
	f := newFedFixture(t)

	// Сверх потолка полосы клиента, но в пределах федеративного — принимается.
	within := fedClaims("jti-within-fed-ceiling")
	within["exp"] = testNow.Add(tokenpolicy.MaxAssertionLifetime + time.Minute).Unix()
	raw := assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(within),
		key:         f.idpKey,
	}.sign(t)
	_, err := f.verifyFederated(t, raw)
	require.NoError(t, err,
		"федеративный потолок обязан быть шире потолка полосы клиента, иначе внешний издатель отвергается целиком")

	// Сверх федеративного потолка — отвергается.
	above := fedClaims("jti-above-fed-ceiling")
	above["exp"] = testNow.Add(tokenpolicy.MaxFederatedAssertionLifetime + time.Minute).Unix()
	raw = assertion{
		headerJSON:  fedHeader(f.idpKey.alg),
		payloadJSON: claims(above),
		key:         f.idpKey,
	}.sign(t)
	res, err := f.verifyFederated(t, raw)
	requireOutcome(t, clientassertion.OutcomeLifetimeAboveCeiling, res, err)
}

// TestNew_RequiresTheTrustedIssuerResolver — СТРАЖ ПОСТРОЕНИЯ.
//
// Проверяющий без резолвера доверенных издателей обязан не построиться, а не
// «работать без федерации». Второе означало бы, что посадка, забывшая провязать
// таблицу, отвергает всякое федеративное утверждение молча — то есть возможность
// объявлена, задокументирована и не работает ни при каком входе.
func TestNew_RequiresTheTrustedIssuerResolver(t *testing.T) {
	_, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return testNow },
	}, stubRegistry{}, nil, newReplay())
	require.Error(t, err, "проверяющий без перечня доверенных издателей построиться не вправе")
	require.Contains(t, err.Error(), "trusted issuer")
}

// TestNew_RequiresTheFederatedLifetimeCeiling — незаявленный федеративный
// потолок означает «любую длительность», а не «по умолчанию».
func TestNew_RequiresTheFederatedLifetimeCeiling(t *testing.T) {
	_, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience: testIssuerID,
		MaxLifetime:      tokenpolicy.MaxAssertionLifetime,
		ClockSkew:        tokenpolicy.ClockSkew,
		Clock:            func() time.Time { return testNow },
	}, stubRegistry{}, stubTrustedIssuers{}, newReplay())
	require.Error(t, err, "федеративный потолок длительности обязан быть объявлен")
}

// TestLanesDoNotResolveThroughEachOthersRegistry — полосы РАЗДЕЛЕНЫ.
//
// Утверждение полосы клиента (издатель и субъект называют нашу строку) на
// федеративной полосе не резолвится, и наоборот. Без этой пробы одна полоса
// молча стала бы запасным путём другой — то есть перечень доверенных издателей
// оказался бы вторым источником клиентов, а реестр клиентов — вторым источником
// доверия.
func TestLanesDoNotResolveThroughEachOthersRegistry(t *testing.T) {
	// (а) утверждение клиента, поданное на федеративную полосу.
	f := newFedFixture(t)
	ours := newKey(t, tokenpolicy.AlgES256)
	rawClientShaped := assertion{
		headerJSON:  fedHeader(ours.alg),
		payloadJSON: claims(goodClaims("jti-client-shaped")),
		key:         ours,
	}.sign(t)
	res, err := f.verifyFederated(t, rawClientShaped)
	requireOutcome(t, clientassertion.OutcomeIssuerUntrusted, res, err)

	// (б) внешнее утверждение, поданное на полосу клиента: издатель и субъект
	// не совпадают, и это отвергается ДО всякого резолва.
	c := newFixture(t)
	rawFedShaped := assertion{
		headerJSON:  goodHeader(c.key.alg),
		payloadJSON: claims(fedClaims("jti-fed-shaped")),
		key:         c.key,
	}.sign(t)
	res, err = c.verify(t, rawFedShaped)
	requireOutcome(t, clientassertion.OutcomeIdentityMismatch, res, err)
}

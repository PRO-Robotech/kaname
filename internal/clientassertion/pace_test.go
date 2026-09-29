// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pace_test.go — ось «обменов в секунду на идентификатор клиента» у
// проверяющего (kaname#315, п. 3 и 4 предиката снятия).
//
// # Что утверждается
//
//   - темп судится по ЗАЯВЛЕННОМУ идентификатору ДО обращения к реестру и к
//     перечню доверенных издателей: отказ по темпу не спрашивает базу вовсе;
//   - темп тратят только ПРИНЯТЫЕ предъявления: отвергнутое возвращает свою
//     бронь, и предъявитель без ключа клиента не расходует его темп;
//   - у отказа по темпу свой исход и срок ожидания;
//   - законный близнец под порогом проходит.
package clientassertion_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/exchangepace"
)

// countingRegistry — реестр, считающий обращения.
type countingRegistry struct {
	inner stubRegistry
	calls *atomic.Int64
}

func (c countingRegistry) ResolveAssertionClient(ctx context.Context, id string) (domain.AssertionClient, error) {
	c.calls.Add(1)
	return c.inner.ResolveAssertionClient(ctx, id)
}

// countingIssuers — перечень доверенных издателей, считающий обращения.
type countingIssuers struct {
	inner stubTrustedIssuers
	calls *atomic.Int64
}

func (c countingIssuers) ResolveTrustedIssuer(ctx context.Context, issuer, subject string) (
	domain.TrustedIssuer, domain.AssertionClient, error,
) {
	c.calls.Add(1)
	return c.inner.ResolveTrustedIssuer(ctx, issuer, subject)
}

// generousPace — темп проб, чей предмет не темп: настоящий компонент с
// величиной, которую ни одна проба не исчерпывает. Дублёр «всегда пропускать»
// сюда не годится: он выполнял бы контракт порта не тем кодом, что производство.
func generousPace(t *testing.T) *exchangepace.Pace {
	t.Helper()
	p, err := exchangepace.New(1<<20, func() time.Time { return testNow })
	require.NoError(t, err)
	return p
}

func testPolicy() clientassertion.Policy {
	return clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return testNow },
	}
}

// pacedStand — проверяющий с объявленным темпом и считающими портами.
type pacedStand struct {
	verifier      *clientassertion.Verifier
	registryCalls *atomic.Int64
	issuerCalls   *atomic.Int64
}

func newPacedStand(t *testing.T, perSec int, reg stubRegistry, iss stubTrustedIssuers) pacedStand {
	t.Helper()
	pace, err := exchangepace.New(perSec, func() time.Time { return testNow })
	require.NoError(t, err)
	s := pacedStand{registryCalls: &atomic.Int64{}, issuerCalls: &atomic.Int64{}}
	s.verifier, err = clientassertion.New(testPolicy(),
		countingRegistry{inner: reg, calls: s.registryCalls},
		countingIssuers{inner: iss, calls: s.issuerCalls},
		newReplay(), pace)
	require.NoError(t, err)
	return s
}

// TestClientPaceIsJudgedBeforeTheRegistry — на полосе клиента превышение темпа
// даёт свой исход и не доходит до реестра.
func TestClientPaceIsJudgedBeforeTheRegistry(t *testing.T) {
	f := newFixture(t)
	s := newPacedStand(t, 1, f.registry, f.issuers)
	good := func(jti string) string {
		return assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims(jti)), key: f.key}.sign(t)
	}

	// Законный близнец: под порогом предъявление принято.
	res, err := s.verifier.Verify(context.Background(), tokenpolicy.ClientAssertionType, good("jti-pace-1"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	require.EqualValues(t, 1, s.registryCalls.Load())

	// Сверх порога — свой исход, свой срок ожидания, и реестр не спрошен.
	res, err = s.verifier.Verify(context.Background(), tokenpolicy.ClientAssertionType, good("jti-pace-2"))
	requireOutcome(t, clientassertion.OutcomeClientPaceExceeded, res, err)
	require.Equal(t, time.Second, res.RetryAfter, "срок ожидания — время до одного обмена при темпе 1 в секунду")
	require.Empty(t, res.Client.ID, "отказ по темпу не вправе называть строку реестра")
	require.EqualValues(t, 1, s.registryCalls.Load(),
		"отказ по темпу обязан решаться ДО реестра: иначе он не сберегает того, ради чего заведён")
}

// TestRefusedPresentationReturnsItsReservation — отвергнутое предъявление не
// тратит темп клиента, которого назвало.
func TestRefusedPresentationReturnsItsReservation(t *testing.T) {
	f := newFixture(t)
	s := newPacedStand(t, 1, f.registry, f.issuers)

	// Предъявление без ключа клиента (подпись испорчена) называет его
	// идентификатор — и отвергается.
	forged := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-forged")),
		key: f.key, tamper: true}.sign(t)
	for i := 0; i < 3; i++ {
		res, err := s.verifier.Verify(context.Background(), tokenpolicy.ClientAssertionType, forged)
		requireOutcome(t, clientassertion.OutcomeSignatureMismatch, res, err)
	}

	// Темп 1 в секунду не израсходован ни одним из трёх: законное предъявление
	// в ту же секунду принимается.
	good := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-after-forged")), key: f.key}.sign(t)
	res, err := s.verifier.Verify(context.Background(), tokenpolicy.ClientAssertionType, good)
	require.NoError(t, err, "отвергнутые предъявления израсходовали темп клиента, которого только назвали")
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestFederatedPaceIsJudgedBeforeTheTrustListAndPerPair — на федеративной
// полосе темп ведётся по паре (издатель, субъект) и судится ДО перечня доверия.
func TestFederatedPaceIsJudgedBeforeTheTrustListAndPerPair(t *testing.T) {
	const otherSubject = "repo:acme/infra:ref:refs/heads/release"
	f := newFedFixture(t, func(s *stubTrustedIssuers) {
		row := s.rows[testExternalIssuer+"\x00"+testExternalSubject]
		row.Subject = otherSubject
		s.rows[testExternalIssuer+"\x00"+otherSubject] = row
	})
	s := newPacedStand(t, 1, stubRegistry{rows: map[string]domain.AssertionClient{}}, f.issuers)
	fed := func(subject, jti string) string {
		cl := fedClaims(jti)
		cl["sub"] = subject
		return assertion{headerJSON: fedHeader(f.idpKey.alg), payloadJSON: claims(cl), key: f.idpKey}.sign(t)
	}

	res, err := s.verifier.VerifyFederated(context.Background(), fed(testExternalSubject, "jti-fed-pace-1"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	require.EqualValues(t, 1, s.issuerCalls.Load())

	res, err = s.verifier.VerifyFederated(context.Background(), fed(testExternalSubject, "jti-fed-pace-2"))
	requireOutcome(t, clientassertion.OutcomeClientPaceExceeded, res, err)
	require.Equal(t, time.Second, res.RetryAfter)
	require.EqualValues(t, 1, s.issuerCalls.Load(), "отказ по темпу обязан решаться ДО перечня доверия")

	// Законный близнец: другой субъект того же издателя в ту же секунду принят.
	res, err = s.verifier.VerifyFederated(context.Background(), fed(otherSubject, "jti-fed-pace-3"))
	require.NoError(t, err, "темп одной пары не имеет права задевать другую")
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestVerifierRefusesToBuildWithoutItsPace — проверяющий без темпа не
// собирается: ось, провязанная не на каждой сборке, молчит там, где забыта.
func TestVerifierRefusesToBuildWithoutItsPace(t *testing.T) {
	f := newFixture(t)
	_, err := clientassertion.New(testPolicy(), f.registry, f.issuers, newReplay(), nil)
	require.Error(t, err)
}

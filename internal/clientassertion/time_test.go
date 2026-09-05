// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// time_test.go — время как ВХОД проверяющего (приёмка F2, §11 C-D).
//
// # Почему обязательность поля проверяется отдельным сценарием
//
// Разбор, ВСТРЕТИВ срок, его проверит; НЕ ВСТРЕТИВ — не возразит. Это верно для
// срока, для момента выпуска и для идентификатора однократности одинаково.
// Поэтому обязательность каждого включается ЯВНО, а проба подаёт утверждение
// БЕЗ соответствующего поля. Проба, подающая полное утверждение, это свойство
// не измеряет вовсе.
package clientassertion_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// atClock строит стенд, часы которого выставлены в названный момент.
func atClock(t *testing.T, at time.Time, opts ...func(*domain.AssertionClient)) fixture {
	t.Helper()
	f := newFixture(t, opts...)
	v, err := clientassertion.New(clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return at },
	}, f.registry, f.issuers, f.replay)
	require.NoError(t, err)
	f.verifier = v
	return f
}

// TestF2_18_ExpiryIsRequiredExplicitly — утверждение без срока отвергается.
func TestF2_18_ExpiryIsRequiredExplicitly(t *testing.T) {
	f := newFixture(t)
	c := goodClaims("jti-18")
	delete(c, "exp")
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeExpiryMissing, res, err)

	// Положительный контроль: утверждение со сроком в будущем принимается.
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-18-ok")), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_19_IssuedAtIsRequiredAndTheFutureIsBoundedByTheDeclaredSkew — без
// момента выпуска потолок длительности не вычисляется (§2.5).
//
// Решение по БУДУЩЕМУ моменту выпуска записано, потому что стандарт правила
// отказа не даёт: сверх объявленного допуска расхождения часов — отказ, в
// пределах допуска — приём. Иначе клиент со спешащими часами не смог бы
// аутентифицироваться вовсе, а допуск, объявленный числом, существовал бы для
// одного поля и не действовал для соседнего.
func TestF2_19_IssuedAtIsRequiredAndTheFutureIsBoundedByTheDeclaredSkew(t *testing.T) {
	f := newFixture(t)
	c := goodClaims("jti-19")
	delete(c, "iat")
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeIssuedAtMissing, res, err)

	// Момент выпуска в будущем СВЕРХ допуска — отказ.
	c = goodClaims("jti-19b")
	iat := testNow.Add(tokenpolicy.ClockSkew + time.Second)
	c["iat"] = iat.Unix()
	c["exp"] = iat.Add(time.Minute).Unix()
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeIssuedAtInFuture, res, err)

	// Момент выпуска в будущем В ПРЕДЕЛАХ допуска — приём. Обе стороны решения
	// утверждаются одной пробой.
	c = goodClaims("jti-19c")
	iat = testNow.Add(tokenpolicy.ClockSkew - time.Second)
	c["iat"] = iat.Unix()
	c["exp"] = iat.Add(time.Minute).Unix()
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_20_LifetimeCeilingIsArithmeticOnDeclaredNumber — разница
// «срок − момент выпуска» ограничена ОБЪЯВЛЕННЫМ ЧИСЛОМ.
//
// Без потолка запись погашения занимает свой ключ на всю длительность
// утверждения — снять её раньше нельзя, иначе повтор станет законным. Значит
// длительность утверждения И ЕСТЬ срок жизни строки, а выбирает её предъявитель.
func TestF2_20_LifetimeCeilingIsArithmeticOnDeclaredNumber(t *testing.T) {
	f := newFixture(t)
	sign := func(life time.Duration, jti string) string {
		c := goodClaims(jti)
		c["iat"] = testNow.Unix()
		c["exp"] = testNow.Add(life).Unix()
		return assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	}
	ceiling := tokenpolicy.MaxAssertionLifetime

	// Сверх потолка — отказ.
	res, err := f.verify(t, sign(ceiling+time.Second, "jti-20-over"))
	requireOutcome(t, clientassertion.OutcomeLifetimeAboveCeiling, res, err)
	res, err = f.verify(t, sign(24*time.Hour, "jti-20-way-over"))
	requireOutcome(t, clientassertion.OutcomeLifetimeAboveCeiling, res, err)

	// РОВНО НА ПОТОЛКЕ — приём. Без этой границы проба зелена на проверяющем,
	// отвергающем любую длительность.
	res, err = f.verify(t, sign(ceiling, "jti-20-at"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	// Меньше потолка — приём.
	res, err = f.verify(t, sign(ceiling/2, "jti-20-under"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestF2_21_ExpiryBoundIsInclusiveAndNotBeforeIsNot — асимметрия задана
// стандартом, и ОБЕ её стороны утверждаются в одной пробе.
func TestF2_21_ExpiryBoundIsInclusiveAndNotBeforeIsNot(t *testing.T) {
	exp := testNow.Add(2 * time.Minute)
	nbf := testNow.Add(time.Minute)

	build := func(f fixture, jti string) string {
		c := goodClaims(jti)
		c["exp"] = exp.Unix()
		c["nbf"] = nbf.Unix()
		c["iat"] = testNow.Unix()
		return assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	}

	// Часы РОВНО в момент истечения (с поправкой на объявленный допуск) —
	// отказ: граница включительно.
	f := atClock(t, exp.Add(tokenpolicy.ClockSkew))
	res, err := f.verify(t, build(f, "jti-21-exp"))
	requireOutcome(t, clientassertion.OutcomeExpired, res, err)

	// Часы РОВНО в момент начала действия — приём.
	f = atClock(t, nbf)
	res, err = f.verify(t, build(f, "jti-21-nbf"))
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	// На шаг раньше момента начала действия (за пределом допуска) — отказ.
	f = atClock(t, nbf.Add(-tokenpolicy.ClockSkew-time.Second))
	res, err = f.verify(t, build(f, "jti-21-early"))
	requireOutcome(t, clientassertion.OutcomeNotYetValid, res, err)
}

// TestF2_23_SingleUseIdentifierIsRequiredByOurPolicy — обязательность объявлена
// НАШЕЙ политикой явно: стандарт её не требует, а без идентификатора
// однократность невыразима.
func TestF2_23_SingleUseIdentifierIsRequiredByOurPolicy(t *testing.T) {
	f := newFixture(t)
	c := goodClaims("")
	delete(c, "jti")
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err := f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeAssertionIDMissing, res, err)

	// Пустая строка — то же самое: пустое обязано означать пусто.
	c = goodClaims("")
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(c), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeAssertionIDMissing, res, err)

	// Положительный контроль.
	raw = assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-23-ok")), key: f.key}.sign(t)
	res, err = f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestVerifierReadsNoClockButTheDeclaredOne — часы приходят ВХОДОМ.
//
// Проверяющий, читающий системные часы, невоспроизводим в пробе: граничные
// сценарии (ровно в момент истечения, ровно в момент начала действия) на нём
// нельзя поставить вовсе, и их отсутствие неотличимо от полноты.
func TestVerifierReadsNoClockButTheDeclaredOne(t *testing.T) {
	// Часы выставлены далеко в будущее: утверждение, законное «сейчас», обязано
	// быть отвергнуто как истёкшее — значит проверяющий читает поданные часы, а
	// не окружение.
	far := atClock(t, testNow.Add(365*24*time.Hour))
	raw := assertion{headerJSON: goodHeader(far.key.alg), payloadJSON: claims(goodClaims("jti-clock")), key: far.key}.sign(t)
	res, err := far.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeExpired, res, err)

	// Положительный контроль на ТОТ ЖЕ вход: при часах, выставленных в момент
	// выпуска, то же утверждение принимается. Без него проба зелена на
	// проверяющем, отвергающем всё как истёкшее.
	near := atClock(t, testNow)
	raw = assertion{headerJSON: goodHeader(near.key.alg), payloadJSON: claims(goodClaims("jti-clock-ok")), key: near.key}.sign(t)
	res, err = near.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
}

// TestVerifierRefusesToBuildWithoutItsDeclaredNumbers — страж ПОСТРОЕНИЯ.
//
// Незаданный ожидаемый адресат означает «принимаем любой»; пустой потолок
// длительности — «любую»; отсутствующие часы — «читаем окружение». Все три —
// класс «пустое значение означает „не сужаем“», и все три обязаны быть отказом
// построения, а не умолчанием.
func TestVerifierRefusesToBuildWithoutItsDeclaredNumbers(t *testing.T) {
	full := clientassertion.Policy{
		ExpectedAudience:     testIssuerID,
		MaxLifetime:          tokenpolicy.MaxAssertionLifetime,
		MaxFederatedLifetime: tokenpolicy.MaxFederatedAssertionLifetime,
		ClockSkew:            tokenpolicy.ClockSkew,
		Clock:                func() time.Time { return testNow },
	}
	reg := stubRegistry{rows: map[string]domain.AssertionClient{}}
	iss := stubTrustedIssuers{rows: map[string]domain.TrustedIssuer{}}

	degenerate := map[string]func(*clientassertion.Policy){
		"адресат не задан":                 func(p *clientassertion.Policy) { p.ExpectedAudience = "" },
		"адресат — одни пробелы":           func(p *clientassertion.Policy) { p.ExpectedAudience = "   " },
		"потолок длительности не задан":    func(p *clientassertion.Policy) { p.MaxLifetime = 0 },
		"потолок длительности отрицателен": func(p *clientassertion.Policy) { p.MaxLifetime = -time.Second },
		"федеративный потолок не задан": func(p *clientassertion.Policy) {
			p.MaxFederatedLifetime = 0
		},
		"федеративный потолок отрицателен": func(p *clientassertion.Policy) {
			p.MaxFederatedLifetime = -time.Second
		},
		"допуск часов отрицателен": func(p *clientassertion.Policy) { p.ClockSkew = -time.Second },
		"часы не поданы":           func(p *clientassertion.Policy) { p.Clock = nil },
	}
	for name, break_ := range degenerate {
		p := full
		break_(&p)
		_, err := clientassertion.New(p, reg, iss, newReplay())
		require.Error(t, err, "вырожденный вход %q обязан отвергнуть построение", name)
	}

	// Порты обязательны так же: проверяющий без реестра принимал бы всех,
	// проверяющий без однократности — повторы, проверяющий без перечня
	// доверенных издателей — отвергал бы каждое федеративное утверждение молча.
	_, err := clientassertion.New(full, nil, iss, newReplay())
	require.Error(t, err)
	_, err = clientassertion.New(full, reg, nil, newReplay())
	require.Error(t, err)
	_, err = clientassertion.New(full, reg, iss, nil)
	require.Error(t, err)

	// Положительный контроль: с полной настройкой проверяющий строится. Без
	// него проба зелена на конструкторе, не пускающем никого.
	_, err = clientassertion.New(full, reg, iss, newReplay())
	require.NoError(t, err)
}

// TestF2_24_ReplayIsRefusedAndStoreFailureIsFailClosed — сторона проверяющего.
//
// Инвариант однократности держит хранилище (интеграционные пробы рядом с ним);
// здесь утверждается, что проверяющий его СПРАШИВАЕТ и что недоступность
// хранилища — ОТКАЗ, а не «погасим потом». Отложенное погашение есть та же пара
// «проверить и записать», разнесённая на неопределённый срок.
func TestF2_24_ReplayIsRefusedAndStoreFailureIsFailClosed(t *testing.T) {
	f := newFixture(t)
	raw := assertion{headerJSON: goodHeader(f.key.alg), payloadJSON: claims(goodClaims("jti-24")), key: f.key}.sign(t)

	res, err := f.verify(t, raw)
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)

	res, err = f.verify(t, raw)
	requireOutcome(t, clientassertion.OutcomeReplayed, res, err)

	// Недоступность хранилища — отказ, и он ОТЛИЧИМ внутрь от повтора.
	f2 := newFixture(t)
	f2.replay.err = context.DeadlineExceeded
	raw2 := assertion{headerJSON: goodHeader(f2.key.alg), payloadJSON: claims(goodClaims("jti-24b")), key: f2.key}.sign(t)
	res, err = f2.verify(t, raw2)
	requireOutcome(t, clientassertion.OutcomeReplayStoreUnavailable, res, err)
}

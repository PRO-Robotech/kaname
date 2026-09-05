// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_audience_narrowing_test.go — сужение адресатов, объявленное САМИМ
// ключом, действует на выпуске (задача #1136).
//
// # Что здесь измеряется
//
// Не «читается ли поле», а КАКОЙ ВХОД ОНО ЗАВОРАЧИВАЕТ. До этой работы
// множество отвергаемых сужением входов было пусто: перечень заказчика уезжал
// в регистрацию у прежнего издателя и на своей полосе выпуска не имел читателя
// вовсе. Поле принималось, сохранялось, возвращалось в ответе — и не отвергало
// ничего.
//
// # Почему каждое отрицание идёт в паре с положительным
//
// Отрицание в одиночку зеленеет на выдаче, отвергающей ВСЁ: «токен не выдан»
// одинаково верно и при работающем сужении, и при сломанном выпуске. Поэтому
// рядом с каждым отказом стоит вход, который обязан пройти.
package client_token_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/client_token"
	"github.com/PRO-Robotech/kacho-iam/internal/clientassertion"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// audExternal — адресат, которого посадка НЕ объявляла.
const audExternal = "https://sts.example.com"

// narrowedTo — клиент, объявивший сужение при выдаче ключа.
func narrowedTo(list ...string) func(*domain.AssertionClient) {
	return func(c *domain.AssertionClient) { c.DeclaredAudiences = list }
}

// TestDeclaredAudienceNarrowsWithinTheLandingList — ключ, объявивший ОДИН
// адресат, не получает токена для второго адресата посадки.
//
// Именно этот вход сужение обязано заворачивать, и именно он до задачи #1136
// проходил: перечень посадки в профилях `dev-prod`, `fe3455-prod` и `prod`
// называет два адресата, один из которых — адресат края.
func TestDeclaredAudienceNarrowsWithinTheLandingList(t *testing.T) {
	for _, kind := range assertionClientKindsUnderTest() {
		t.Run(string(kind), func(t *testing.T) {
			uc, _ := newUseCase(t)

			// ОТРИЦАНИЕ: заказан адресат ПОСАДКИ, которого ключ не объявлял.
			_, outcome, err := uc.Issue(context.Background(), client_token.Input{
				Client:            client(ofKind(kind), narrowedTo(audRegistry)),
				RequestedAudience: []string{audResource},
			})
			require.Error(t, err)
			require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)
			require.Contains(t, err.Error(), audResource,
				"отказ обязан назвать заказанный адресат — иначе оператор не поймёт, что именно отвергнуто")

			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный ключом адресат проходит.
			out, outcome, err := uc.Issue(context.Background(), client_token.Input{
				Client:            client(ofKind(kind), narrowedTo(audRegistry)),
				RequestedAudience: []string{audRegistry},
			})
			require.NoError(t, err)
			require.Equal(t, clientassertion.OutcomeAccepted, outcome)
			claims, _ := parse(t, out.AccessToken)
			require.Equal(t, []string{audRegistry}, audienceStrings(claims["aud"]))
		})
	}
}

// TestDeclaredAudienceRefusesTheWholeSetWhenOneElementIsOutside — набор, где
// хотя бы один адресат вне сужения, отвергается ЦЕЛИКОМ.
//
// Приняв такой набор частично, выдача выпустила бы токен, адресованный туда,
// куда ключ не объявлялся, — и положительный путь при этом выглядел бы
// исправным.
func TestDeclaredAudienceRefusesTheWholeSetWhenOneElementIsOutside(t *testing.T) {
	uc, _ := newUseCase(t)

	_, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client:            client(narrowedTo(audRegistry)),
		RequestedAudience: []string{audRegistry, audResource},
	})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)

	// Положительный контроль: тот же набор без чужого элемента проходит.
	_, outcome, err = uc.Issue(context.Background(), client_token.Input{
		Client:            client(narrowedTo(audRegistry, audResource)),
		RequestedAudience: []string{audRegistry, audResource},
	})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
}

// TestKeyWithoutDeclaredAudienceKeepsTheLandingList — ключ, сужения НЕ
// объявивший, ведёт себя ровно как прежде.
//
// Это и есть смысл пустого перечня: «сужения не объявлено», а не «любой
// адресат». Внешняя граница — перечень посадки — на месте, и её проба ниже
// утверждает отдельно.
func TestKeyWithoutDeclaredAudienceKeepsTheLandingList(t *testing.T) {
	uc, _ := newUseCase(t)

	for _, requested := range [][]string{nil, {audResource}, {audRegistry}} {
		_, outcome, err := uc.Issue(context.Background(), client_token.Input{
			Client:            client(),
			RequestedAudience: requested,
		})
		require.NoError(t, err, "заказано %v", requested)
		require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	}
}

// TestLandingListRemainsTheOuterBoundOfEveryNarrowing — сужение ключа НИКОГДА
// не расширяет объявленное посадкой.
//
// Иначе заказчик ключа сам решал бы, кому платформа вправе выдать токен: он
// назвал бы в поле выдачи любой адресат, и подписант чеканил бы удостоверение,
// адресованное поверхности, которую посадка не объявляла.
func TestLandingListRemainsTheOuterBoundOfEveryNarrowing(t *testing.T) {
	uc, _ := newUseCase(t)

	// Ключ объявил адресат, которого посадка не называла, и заказывает именно
	// его: сужение тут ни при чём — внешняя граница отвергает.
	_, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client:            client(narrowedTo(audExternal)),
		RequestedAudience: []string{audExternal},
	})
	require.Error(t, err)
	require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)

	// Положительный контроль: тот же ключ, объявивший ВДОБАВОК адресат из
	// перечня посадки, за ним и приходит.
	out, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client:            client(narrowedTo(audExternal, audRegistry)),
		RequestedAudience: []string{audRegistry},
	})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	claims, _ := parse(t, out.AccessToken)
	require.Equal(t, []string{audRegistry}, audienceStrings(claims["aud"]))
}

// TestOmittedAudienceOnANarrowedKeyResolvesInsideTheNarrowing — запрос, не
// назвавший адресата, получает адресат ИЗ СУЖЕНИЯ, а не умолчание посадки.
//
// Умолчание посадки — величина для ключа, о своём назначении не заявившего.
// Ключ, объявивший назначение, назвал его сам, и подставлять ему чужое значило
// бы выдать токен, адресованный не туда, — либо отвергнуть запрос, который
// заказчик составил ровно так, как составлял всегда.
func TestOmittedAudienceOnANarrowedKeyResolvesInsideTheNarrowing(t *testing.T) {
	uc, _ := newUseCase(t)

	out, outcome, err := uc.Issue(context.Background(), client_token.Input{
		Client: client(narrowedTo(audRegistry)),
	})
	require.NoError(t, err)
	require.Equal(t, clientassertion.OutcomeAccepted, outcome)
	claims, _ := parse(t, out.AccessToken)
	require.Equal(t, []string{audRegistry}, audienceStrings(claims["aud"]),
		"умолчание посадки %q не вправе перебить объявленное ключом", audResource)

	// Положительный контроль пустого сужения: умолчание посадки на месте.
	out, _, err = uc.Issue(context.Background(), client_token.Input{Client: client()})
	require.NoError(t, err)
	claims, _ = parse(t, out.AccessToken)
	require.Equal(t, []string{audResource}, audienceStrings(claims["aud"]))
}

// TestNarrowingDisjointFromTheLandingListRefusesAndSaysWhy — ключ, чьё сужение
// не пересекается с перечнем посадки, не получает токена НИ ПРИ КАКОМ запросе,
// и отказ называет предмет.
//
// Состояние законное и достижимое: ключ выдан под внешнюю федерацию, а посадка
// такого адресата не объявляла. Отвергать его на ВЫДАЧЕ ключа нельзя — перечень
// посадки меняется оператором и после выдачи, — поэтому отказ живёт здесь и
// обязан быть понятен: молчаливое умолчание на перечень посадки вернуло бы ровно
// то, что эта работа снимает.
func TestNarrowingDisjointFromTheLandingListRefusesAndSaysWhy(t *testing.T) {
	uc, _ := newUseCase(t)

	for _, requested := range [][]string{nil, {audExternal}, {audResource}, {audRegistry}} {
		_, outcome, err := uc.Issue(context.Background(), client_token.Input{
			Client:            client(narrowedTo(audExternal)),
			RequestedAudience: requested,
		})
		require.Error(t, err, "заказано %v", requested)
		require.Equal(t, clientassertion.OutcomeAudienceNotAllowed, outcome)
	}

	_, _, err := uc.Issue(context.Background(), client_token.Input{
		Client: client(narrowedTo(audExternal)),
	})
	require.Error(t, err)
	require.True(t,
		strings.Contains(err.Error(), "declared") && strings.Contains(err.Error(), audExternal),
		"отказ обязан назвать и предмет, и объявленное ключом: %v", err)
}

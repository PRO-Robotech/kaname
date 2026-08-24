// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// audience_narrowing_test.go — адресат докерной полосы сверяется с
// объявленным, а не берётся из запроса (задача #1184).
//
// # Что здесь измеряется
//
// Не «читается ли параметр», а КАКОЙ ВХОД ОН ЗАВОРАЧИВАЕТ. До этой работы
// множество отвергаемых входов было ПУСТО: значение `?service=` уезжало в
// адресат выпускаемого токена как есть, и предъявитель называл себе аудиторию
// сам. Полос выдачи по ключу служебной учётки две, и сверка действовала на
// одной.
//
// # Почему каждое отрицание идёт в паре с положительным
//
// Отрицание в одиночку зеленеет на выдаче, отвергающей ВСЁ: «токен не выдан»
// одинаково верно и при работающей сверке, и при сломанном выпуске. Поэтому
// рядом с каждым отказом стоит вход, который обязан пройти.
package registry_token_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	registrytokenuc "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/registry_token"
)

const (
	// audRegistry — адресат, объявленный посадкой этой полосы: имя службы
	// реестра, которое сам реестр называет докер-клиенту в вызове на
	// аутентификацию. Ровно его клиент и возвращает в `?service=`.
	audRegistry = "registry.kacho.local"
	// audForeign — адресат, которого посадка этой полосы не объявляла.
	audForeign = "sts.example.com"
)

// newDockerLane собирает полосу выдачи докер-токена на нашей чеканке.
//
// Дублёры не снисходительнее продукта: подписант выпускает то, что ему
// заказали, а проверяющий учётные данные возвращает ровно ту строку ключа,
// которую ему прописали, — включая объявленное этим ключом сужение.
func newDockerLane(t *testing.T, declared ...string) (*registrytokenuc.IssueRegistryTokenUseCase, *stubMinter) {
	t.Helper()
	m := &stubMinter{}
	uc := registrytokenuc.NewIssueRegistryTokenUseCase(
		registrytokenuc.Config{
			AssertionAudience: "https://hydra.kacho.local/oauth2/token",
			AllowedAudiences:  []string{audRegistry},
			DefaultService:    audRegistry,
		},
		stubValidator{cred: registrytokenuc.Credential{
			ClientID:          "cid-ci",
			KeyID:             "soc_0123456789abcdefg",
			Subject:           "sva_0123456789abcdefg",
			DeclaredAudiences: declared,
		}},
		nopSigner{}, &recordingExchanger{},
	).WithLocalMinter(m)
	return uc, m
}

func creds() registrytokenuc.IssueInput {
	return registrytokenuc.IssueInput{Username: "cid-ci", Password: "-----private-pem-----"}
}

// TestRequestedServiceOutsideTheLandingDeclarationIsRefused — предъявитель НЕ
// назначает себе аудиторию.
//
// Именно этот вход сверка обязана заворачивать, и именно он до задачи #1184
// проходил: значение параметра уезжало в адресат выпускаемого токена без
// единого читателя между запросом и подписантом.
func TestRequestedServiceOutsideTheLandingDeclarationIsRefused(t *testing.T) {
	uc, m := newDockerLane(t)

	// ОТРИЦАНИЕ: заказан адресат, которого посадка этой полосы не объявляла.
	in := creds()
	in.Service = audForeign
	_, err := uc.Execute(context.Background(), in)
	require.Error(t, err)
	require.Contains(t, err.Error(), audForeign,
		"отказ обязан назвать заказанный адресат — иначе оператор не поймёт, что именно отвергнуто")
	require.Empty(t, m.in.Audience, "подписант не вправе быть позван вовсе, раз адресат отвергнут")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный посадкой адресат проходит.
	in = creds()
	in.Service = audRegistry
	out, err := uc.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)
	require.Equal(t, audRegistry, m.in.Audience)
}

// TestDeclaredAudienceOfTheKeyNarrowsTheDockerLane — сужение, объявленное САМИМ
// ключом при выдаче, действует и на этой полосе.
//
// Расхождение полос никто не решал: оно возникло побочным эффектом того, что
// эта полоса писалась под фиксированный адресат реестра.
func TestDeclaredAudienceOfTheKeyNarrowsTheDockerLane(t *testing.T) {
	// ОТРИЦАНИЕ: ключ выдан под внешнюю федерацию — адресата этой полосы он не
	// объявлял, и получить для неё токен не вправе ни при каком запросе.
	uc, m := newDockerLane(t, audForeign)
	in := creds()
	in.Service = audRegistry
	_, err := uc.Execute(context.Background(), in)
	require.Error(t, err)
	require.Empty(t, m.in.Audience)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же ключ, объявивший ВДОБАВОК адресат этой
	// полосы, за ним и приходит.
	uc, m = newDockerLane(t, audForeign, audRegistry)
	in = creds()
	in.Service = audRegistry
	_, err = uc.Execute(context.Background(), in)
	require.NoError(t, err)
	require.Equal(t, audRegistry, m.in.Audience)
}

// TestKeyWithoutDeclaredAudienceKeepsTheDockerLanding — ключ, сужения НЕ
// объявивший, ведёт себя ровно как прежде.
//
// Это и есть смысл пустого перечня: «сужения не объявлено», а не «любой
// адресат». Внешняя граница на месте и утверждается пробой выше.
func TestKeyWithoutDeclaredAudienceKeepsTheDockerLanding(t *testing.T) {
	uc, m := newDockerLane(t)

	// Запрос, не назвавший адресата, получает объявленный посадкой.
	_, err := uc.Execute(context.Background(), creds())
	require.NoError(t, err)
	require.Equal(t, audRegistry, m.in.Audience,
		"запрос без ?service= обязан получить объявленный посадкой адресат, а не пустой")
}

// TestOmittedServiceOnANarrowedKeyResolvesInsideTheNarrowing — запрос, не
// назвавший адресата, получает адресат ИЗ СУЖЕНИЯ, а не умолчание посадки.
//
// Тем же правилом, что и на соседней полосе: умолчание — величина для ключа, о
// своём назначении не заявившего.
func TestOmittedServiceOnANarrowedKeyResolvesInsideTheNarrowing(t *testing.T) {
	uc, m := newDockerLane(t, audRegistry)
	_, err := uc.Execute(context.Background(), creds())
	require.NoError(t, err)
	require.Equal(t, audRegistry, m.in.Audience)
}

// TestAnonymousLaneIsBoundByTheSameLandingDeclaration — анонимный поток той же
// полосы адресата себе тоже не назначает.
//
// Учётных данных здесь нет вовсе, поэтому сужения ключа нет по построению —
// остаётся внешняя граница, и она обязана действовать.
func TestAnonymousLaneIsBoundByTheSameLandingDeclaration(t *testing.T) {
	m := &stubMinter{}
	uc := registrytokenuc.NewIssueRegistryTokenUseCase(
		registrytokenuc.Config{
			AssertionAudience: "https://hydra.kacho.local/oauth2/token",
			AllowedAudiences:  []string{audRegistry},
			DefaultService:    audRegistry,
			Anonymous: registrytokenuc.AnonymousIdentity{
				ClientID: "anon-cid", KeyID: "anon-kid", PrivateKeyPEM: "-----anon-pem-----",
			},
		},
		stubValidator{}, nopSigner{}, &recordingExchanger{},
	).WithLocalMinter(m)

	// ОТРИЦАНИЕ.
	_, err := uc.ExecuteAnonymous(context.Background(), audForeign)
	require.Error(t, err)
	require.Empty(t, m.in.Audience)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
	_, err = uc.ExecuteAnonymous(context.Background(), audRegistry)
	require.NoError(t, err)
	require.Equal(t, audRegistry, m.in.Audience)
}

// TestAudienceRefusalIsNotAnIssuerFault — отказ адресата НЕ выглядит
// неисправностью издателя.
//
// Различие не косметическое: недоступность издателя обработчик отдаёт как 503
// и повтор осмыслен, а отвергнутый адресат валидным не станет никогда. Слив их
// в один исход, мы предложили бы клиенту повторять вход, который не пройдёт.
func TestAudienceRefusalIsNotAnIssuerFault(t *testing.T) {
	uc, _ := newDockerLane(t)
	in := creds()
	in.Service = audForeign
	_, err := uc.Execute(context.Background(), in)
	require.Error(t, err)
	require.False(t, errors.Is(err, registrytokenuc.ErrIssuerUnavailable),
		"отвергнутый адресат — не недоступность издателя")
}

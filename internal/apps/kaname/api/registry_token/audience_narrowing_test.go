// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audience_narrowing_test.go — адресат докерной полосы сверяется с
// объявленным, а не берётся из запроса (задача #1184).
//
// # Что здесь измеряется
//
// Не «читается ли параметр», а КАКОЙ ВХОД ОН ЗАВОРАЧИВАЕТ. До задачи #1184
// множество отвергаемых входов было ПУСТО: значение `?service=` уезжало в
// адресат выпускаемого токена как есть, и предъявитель называл себе аудиторию
// сам.
//
// # Границы было ДВЕ, осталась ОДНА — и это решение, а не побочный эффект
//
// ВНУТРЕННЯЯ граница (`Declared`) — сужение, объявленное ЗАКАЗЧИКОМ при выдаче
// ключа, — жила на ключе служебной учётки. Приём ключевого материала в поле
// пароля снят задачей #1143, и сужение ушло вместе с полосой, которая его
// несла: у базового токена доступа поля адресатов нет — оно отвергается на
// выдаче, — а анонимный поток удостоверения не предъявляет вовсе. Пробы той
// границы сняты ВМЕСТЕ с её предметом, а не ослаблены.
//
// ВНЕШНЯЯ граница посадки осталась и осталась обязательной; именно она и
// заворачивает вход, ради которого этот файл заведён.
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

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
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
// заказали, а авторитет о предъявленном секрете разбирает его форму тем же
// единственным объявлением, что и продукт.
func newDockerLane(t *testing.T) (*registrytokenuc.IssueRegistryTokenUseCase, *stubMinter, string) {
	t.Helper()
	m := &stubMinter{}
	secret, authority := newBasicCredential(t)
	uc := registrytokenuc.NewIssueRegistryTokenUseCase(
		registrytokenuc.Config{
			AssertionAudience: "https://hydra.kacho.local/oauth2/token",
			AllowedAudiences:  []string{audRegistry},
			DefaultService:    audRegistry,
		},
		nopSigner{}, &recordingExchanger{},
	).WithLocalMinter(m).WithBasicCredentialResolver(authority)
	return uc, m, secret
}

// TestRequestedServiceOutsideTheLandingDeclarationIsRefused — предъявитель НЕ
// назначает себе аудиторию.
//
// Именно этот вход сверка обязана заворачивать, и именно он до задачи #1184
// проходил: значение параметра уезжало в адресат выпускаемого токена без
// единого читателя между запросом и подписантом.
func TestRequestedServiceOutsideTheLandingDeclarationIsRefused(t *testing.T) {
	uc, m, secret := newDockerLane(t)

	// ОТРИЦАНИЕ: заказан адресат, которого посадка этой полосы не объявляла.
	in := dockerLogin(secret)
	in.Service = audForeign
	_, err := uc.Execute(context.Background(), in)
	require.Error(t, err)
	require.Contains(t, err.Error(), audForeign,
		"отказ обязан назвать заказанный адресат — иначе оператор не поймёт, что именно отвергнуто")
	require.Empty(t, m.in.Audience, "подписант не вправе быть позван вовсе, раз адресат отвергнут")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный посадкой адресат проходит.
	in = dockerLogin(secret)
	in.Service = audRegistry
	out, err := uc.Execute(context.Background(), in)
	require.NoError(t, err)
	require.NotEmpty(t, out.Token)
	require.Equal(t, audRegistry, m.in.Audience)
}

// TestRequestOmittingTheServiceGetsTheLandingDefault — запрос, адресата не
// назвавший, получает объявленный посадкой, а не пустой.
//
// У принимаемого вида сужения не бывает по построению (#1143), поэтому
// умолчание посадки — единственная величина, из которой адресат здесь берётся.
func TestRequestOmittingTheServiceGetsTheLandingDefault(t *testing.T) {
	uc, m, secret := newDockerLane(t)

	// Запрос, не назвавший адресата, получает объявленный посадкой.
	_, err := uc.Execute(context.Background(), dockerLogin(secret))
	require.NoError(t, err)
	require.Equal(t, audRegistry, m.in.Audience,
		"запрос без ?service= обязан получить объявленный посадкой адресат, а не пустой")
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
		nopSigner{}, &recordingExchanger{},
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
	uc, _, secret := newDockerLane(t)
	in := dockerLogin(secret)
	in.Service = audForeign
	_, err := uc.Execute(context.Background(), in)
	require.Error(t, err)
	require.False(t, errors.Is(err, registrytokenuc.ErrIssuerUnavailable),
		"отвергнутый адресат — не недоступность издателя")
}

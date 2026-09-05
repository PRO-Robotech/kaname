// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_audience_guard_test.go — страж старта докерной полосы выдачи
// (задача #1184).
//
// Каждое отрицание идёт в паре с положительным: страж, отвергающий ВСЁ,
// проходил бы по всякому отрицанию и не проверял бы ничего.
package config_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

func platform(audiences string) config.ClientTokenConfig {
	return config.ClientTokenConfig{Enabled: true, AllowedAudiences: audiences, DefaultAudience: "registry.kacho.local"}
}

// TestLaneAudienceMustBeInsideThePlatformDeclaration — адресат, которому
// докерная полоса чеканит, обязан входить в перечень адресатов платформы.
//
// Иначе наш подписант выпускает удостоверение, адресованное поверхности,
// которую посадка не объявляла, — а соседняя полоса тот же адресат отвергает.
// Решал бы это не оператор, а порядок, в котором писались полосы.
func TestLaneAudienceMustBeInsideThePlatformDeclaration(t *testing.T) {
	// ОТРИЦАНИЕ.
	err := config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(platform("https://api.kacho.cloud,registry.kacho.local"))
	require.Error(t, err)
	require.Contains(t, err.Error(), "api-server.registry-token.service",
		"отказ обязан назвать настройку — его читает оператор, а не предъявитель")
	require.Contains(t, err.Error(), "authn.client-token.allowed-audiences",
		"и вторую настройку тоже: расхождение чинится сверкой двух объявлений")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный обеими сторонами адресат проходит.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "registry.kacho.local",
	}.Validate(platform("https://api.kacho.cloud,registry.kacho.local")))
}

// TestGuardJudgesTheEffectiveAudience — страж судит ДЕЙСТВУЮЩИЙ адресат, а не
// написанное в профиле.
//
// > [!note] Прежняя редакция этой пробы утверждала другое — и её ПРЕДМЕТ ИСЧЕЗ
// > Она подавала незаданный `service`, полагалась на встроенное умолчание и
// > требовала, чтобы отказ называло именно оно. Умолчания больше нет (оно и
// > было вторым объявлением предмета, см. registry_token.go), поэтому проба
// > ЗАМЕНЕНА, а не ослаблена: заголовок остаётся верным, утверждается то же
// > свойство — страж читает действующую величину, — но на входах, которые в
// > этом дереве существуют.
//
// Действующая величина отличается от сырого поля обрамляющими пробелами: строка
// из одних пробелов объявлением НЕ является (иначе профиль, где ключ есть, а
// значения нет, проезжал бы стража и чеканил пустой `aud`), а объявленная с
// пробелами судится обрезанной.
func TestGuardJudgesTheEffectiveAudience(t *testing.T) {
	// ОТРИЦАНИЕ (а): пробельная строка — не объявление.
	err := config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:9096", Service: "   "}.
		Validate(platform("registry.kacho.local"))
	require.Error(t, err, "пробельный адресат обязан читаться как необъявленный")
	require.Contains(t, err.Error(), "api-server.registry-token.service")

	// ОТРИЦАНИЕ (б): объявленный, но вне перечня платформы — судится обрезанным.
	err = config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:9096", Service: "  sts.example.com  "}.
		Validate(platform("https://api.kacho.cloud"))
	require.Error(t, err)
	require.Contains(t, err.Error(), `"sts.example.com"`,
		"отказ обязан назвать ДЕЙСТВУЮЩИЙ адресат — обрезанный, а не сырое поле профиля")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тот же адресат с пробелами при перечне, который
	// его называет, проходит. Без него оба отрицания зеленели бы на страже,
	// отвергающем всё.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "  registry.kacho.local  ",
	}.Validate(platform("https://api.kacho.cloud,registry.kacho.local")))
}

// TestGuardHasNoSubjectWithoutALane — у стража без предмета отказа нет.
//
// Слушателя нет — полосы нет; перечень платформы не объявлен — сверять не с чем,
// и внешней границей полосы остаётся её собственный объявленный адресат.
// Отказ в этих состояниях был бы отказом в старте без предмета.
func TestGuardHasNoSubjectWithoutALane(t *testing.T) {
	require.NoError(t, config.RegistryTokenConfig{Service: "sts.example.com"}.
		Validate(platform("registry.kacho.local")), "слушателя нет — предмета нет")
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(config.ClientTokenConfig{}), "перечень платформы не объявлен — сверять не с чем")

	// Пустой перечень при ВКЛЮЧЁННОМ эндпоинте — предмет соседнего стража, и он
	// о нём говорит сам. Второе сообщение о том же предмете разошлось бы с
	// первым; проба закрепляет, что второго тут нет.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "sts.example.com",
	}.Validate(config.ClientTokenConfig{Enabled: true, AllowedAudiences: " , "}))
}

// TestLaneAudienceMustBeDeclaredNotDefaulted — страж старта ловит
// НЕСВЯЗАННОСТЬ сторон, а не «неверное умолчание» (задача #1184).
//
// # Почему у этой величины НЕ МОЖЕТ быть встроенного умолчания
//
// Имя службы реестра законно СВОЁ у каждого кластера — его объявляет посадка,
// и объявляет ОДИН раз: сторона реестра и сторона личности читают одно
// значение. Встроенное умолчание здесь — это ВТОРОЕ объявление того же
// предмета, живущее в другом дереве: пока сверки адресата не было, оно молча
// расходилось с именем, которое реестр называет докер-клиенту, и полоса
// работала лишь потому, что клиент echo-ит услышанное, а подписант чеканил что
// просят. Со сверкой то же расхождение означает отказ во входе — и оператор
// увидит его на КАЖДОМ запросе арендатора вместо одного отказа при старте.
//
// Поэтому: полоса поднята, адресат не объявлен ⇒ отказ в старте. Умолчания,
// которое подставило бы «какое-нибудь» имя, не существует — подставить его
// значит выбрать за оператора то, что выбрать нельзя.
func TestLaneAudienceMustBeDeclaredNotDefaulted(t *testing.T) {
	// ОТРИЦАНИЕ: слушатель полосы поднят, адресат не объявлен.
	err := config.RegistryTokenConfig{Endpoint: "tcp://0.0.0.0:9096"}.
		Validate(platform("registry.kacho.local"))
	require.Error(t, err, "полоса поднята с необъявленным адресатом — старт обязан быть отвергнут")

	// Отказ называет ОБЕ величины: свою настройку и ту сторону, из которой она
	// выводится. Оператор чинит это за минуту, если ему сказали, ЧТО с ЧЕМ не
	// связано; без второй координаты он ищет вслепую.
	require.Contains(t, err.Error(), "api-server.registry-token.service",
		"отказ обязан назвать НАШУ настройку")
	require.Contains(t, err.Error(), "global.kacho.registry.serviceAud",
		"и единый источник, из которого она выводится")
	require.Contains(t, err.Error(), "KACHO_REGISTRY_SERVICE_AUD",
		"и переменную реестра — вторую сторону той же полосы")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный адресат при том же перечне проходит.
	// Без него отказ выше был бы неотличим от стража, отвергающего всё.
	require.NoError(t, config.RegistryTokenConfig{
		Endpoint: "tcp://0.0.0.0:9096", Service: "registry.kacho.local",
	}.Validate(platform("registry.kacho.local")))

	// ГРАНИЦА: слушателя нет — полосы нет, объявлять нечего, отказывать не за что.
	require.NoError(t, config.RegistryTokenConfig{}.Validate(platform("registry.kacho.local")),
		"без слушателя у стража нет предмета")
}

// TestUndeclaredLaneAudienceResolvesToNothing — у действующего адресата нет
// встроенной подмены.
//
// Парная к стражу выше и утверждает другое: не «старт отвергнут», а что
// подставлять НЕЧЕГО. Обе половины нужны — страж мог бы отказывать, а
// аксессор при этом возвращать унаследованное имя, и тогда всякий путь в обход
// стража (проба, одиночный запуск) снова чеканил бы адресату, которого никто
// не объявлял.
func TestUndeclaredLaneAudienceResolvesToNothing(t *testing.T) {
	if got := (config.RegistryTokenConfig{}).TokenService(); got != "" {
		t.Fatalf("необъявленный адресат резолвится в %q — это второе объявление предмета, живущее в коде", got)
	}
	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: объявленный — доезжает, и обрамляющие пробелы снимаются.
	if got := (config.RegistryTokenConfig{Service: "  lane.example  "}).TokenService(); got != "lane.example" {
		t.Fatalf("объявленный адресат = %q, ждали lane.example", got)
	}
}

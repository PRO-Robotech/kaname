// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_material_refused_test.go — ДОКЕРНАЯ ПОЛОСА БОЛЬШЕ НЕ ПРИНИМАЕТ КЛЮЧЕВОЙ
// МАТЕРИАЛ В ПОЛЕ ПАРОЛЯ (задача #1143).
//
// # Что здесь измеряется
//
// Не «есть ли ветка отказа», а КАКОЙ ВХОД ОНА ЗАВОРАЧИВАЕТ. До этой работы
// приватная половина пары ключей была законным паролем докер-входа: она ехала
// по сети и оседала в конфигурации клиента. Замена введена #1142 — базовый
// токен доступа, — и порядок был обязателен: ввести → перевести клиентов →
// снять приём.
//
// # Почему каждое отрицание идёт в паре с положительным
//
// «Ключевой материал отвергнут» одинаково верно и при снятом приёме, и при
// полосе, отвергающей ВСЁ. Поэтому рядом с каждым отказом стоит вход базовым
// токеном, который обязан пройти.
//
// # Почему отказ обязан быть НЕРАЗЛИЧИМ
//
// Отдельный отказ на «негодный вид» сказал бы предъявителю, что его строка
// разобрана как ключ, — то есть подтвердил бы существование учётной записи,
// на которую он не аутентифицировался. Наблюдаемый отказ здесь один и тот же
// для негодного вида, чужого имени и неверного секрета; называет годный вид
// он СТАТИЧЕСКИ, а не по разбору предъявленного.

package registry_token

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// pemLikeKeyMaterial — то, чем докер-вход пользовался до этой работы:
// приватная половина пары в поле пароля. Нарочито не похоже на настоящий
// ключ — правдоподобная фикстура сделала бы «прошло» неотличимым от
// исправного потока.
const pemLikeKeyMaterial = "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-1143\n-----END PRIVATE KEY-----"

// laneUnderTest — полоса с провязанным авторитетом базового секрета и живым
// удостоверением; возвращает саму полосу, годную строку и её идентификатор.
func laneUnderTest(t *testing.T) (*IssueRegistryTokenUseCase, *fakeMinter, string, string) {
	t.Helper()
	const credID, svaID = "soc_0000000000001143a", "sva0000000000001143a"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	res := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: svaID},
	}
	uc, minter := basicDockerLane(t, res)
	return uc, minter, credID, secret
}

// #1143 п.1 — ключевой материал в поле пароля отвергается; базовый токен
// проходит (положительный контроль в ТОЙ ЖЕ пробе).
func TestKeyMaterialInThePasswordFieldIsNoLongerAccepted(t *testing.T) {
	uc, minter, credID, secret := laneUnderTest(t)

	// Положительный контроль ПЕРВЫМ: без него «отвергнуто» ниже зеленело бы на
	// полосе, сломанной целиком.
	out, err := uc.Execute(context.Background(), IssueInput{
		Username: credID, Password: secret, Service: "registry",
	})
	if err != nil {
		t.Fatalf("вход базовым токеном отвергнут — полоса сломана целиком, и отрицание ниже вакуумно: %v", err)
	}
	if out.Token == "" {
		t.Fatal("удостоверение реестра не выдано на положительном контроле")
	}
	minted := minter.got.Subject

	_, err = uc.Execute(context.Background(), IssueInput{
		Username: credID, Password: pemLikeKeyMaterial, Service: "registry",
	})
	if err == nil {
		t.Fatal("ключевой материал в поле пароля принят — приватная половина пары по-прежнему ездит по сети")
	}
	if !errors.Is(err, ErrUnauthenticated) {
		t.Errorf("отказ = %v, ожидался единый отказ полосы (наружу он обязан быть 401-вызовом)", err)
	}
	// Внутрь — различимость, ради журнала: «клиент настроен по-старому» и
	// «секрет неверен» чинятся в разных местах и разными людьми. Наружу оба
	// отказа неразличимы — это утверждает проба обработчика.
	if !errors.Is(err, ErrCredentialKindNotAccepted) {
		t.Errorf("отказ не назван причиной %v — журнал не отличит старую настройку клиента от неверного секрета",
			ErrCredentialKindNotAccepted)
	}
	if minter.got.Subject != minted {
		t.Error("на ключевом материале чеканка всё-таки состоялась")
	}
}

// #1143 п.2 — отказ НЕ оракул: наблюдаемый исход одинаков для негодного вида,
// чужого имени и неверного секрета.
//
// Сравниваются ОБА наблюдаемых свойства: сорт отказа (наружу — один и тот же
// 401-вызов) и то, что ни один вход не отличается наличием токена.
func TestTheRefusalDoesNotTellTheKindApartFromTheSecret(t *testing.T) {
	uc, _, credID, secret := laneUnderTest(t)
	wrong, _, _ := credsecret.Mint(credID)

	inputs := map[string]IssueInput{
		"ключевой материал":     {Username: credID, Password: pemLikeKeyMaterial, Service: "registry"},
		"чужое имя":             {Username: "soc_0000000000001143z", Password: secret, Service: "registry"},
		"неверный секрет":       {Username: credID, Password: wrong, Service: "registry"},
		"строка не нашего вида": {Username: credID, Password: "just-a-password", Service: "registry"},
	}
	for name, in := range inputs {
		out, err := uc.Execute(context.Background(), in)
		if err == nil {
			t.Fatalf("вход %q прошёл", name)
		}
		if !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("вход %q дал отказ иного сорта (%v) — снаружи он был бы отличим, то есть оракулом", name, err)
		}
		if out.Token != "" {
			t.Errorf("вход %q получил токен", name)
		}
	}

	// Положительный контроль: годная строка по-прежнему проходит — иначе
	// «все отвергнуты одинаково» верно и для полосы, отвергающей всё.
	if _, err := uc.Execute(context.Background(), IssueInput{
		Username: credID, Password: secret, Service: "registry",
	}); err != nil {
		t.Fatalf("годная строка отвергнута: %v", err)
	}
}

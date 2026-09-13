// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// ПОСАДКА БЕЗ ВНЕШНЕГО ПОСТАВЩИКА: ДОРОГА К НЕМУ НЕ СТРОИТСЯ (задача kaname#21,
// преемник закрытой-при-живом-предмете kacho#2489).
//
// Предмет — НЕ «клиент отвечает ошибкой», а «адрес не резолвится и якорь не
// читается». Разница наблюдаемая: клиент, построенный на выведенном из
// доменного имени адресе, выглядит настроенным и уходит звонить в публичный
// ингресс с административным предъявителем в заголовке. Клиент, построенный
// здесь, не несёт адреса ВОВСЕ.
//
// Каждое утверждение стоит в паре с ЗАКОННЫМ БЛИЗНЕЦОМ — обычным клиентом: без
// него отрицание зеленело бы на любом клиенте, включая сломанный.
func TestAbsentProviderAdminClient_CarriesNoAddress(t *testing.T) {
	absent := clients.NewAbsentProviderAdminClient()
	if absent == nil {
		t.Fatal("NewAbsentProviderAdminClient() = nil; на посадке без поставщика " +
			"потребителям нужен объект, отказывающий по имени, а не пустой указатель")
	}
	if absent.BaseURL != "" {
		t.Errorf("BaseURL = %q; дорога, у которой есть адрес, построена — "+
			"а на этой посадке звонить некуда by construction", absent.BaseURL)
	}
	if absent.BearerToken != "" {
		t.Error("BearerToken непуст: административный предъявитель собран для дороги, которой нет")
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: обычный клиент адрес несёт. Без этой половины проверка
	// выше проходила бы на конструкторе, который вообще ничего не строит.
	real := clients.NewHydraAdminClient("https://hydra-admin.example.test", "bearer")
	if real.BaseURL == "" {
		t.Fatal("обычный клиент остался без адреса — проба утверждает не о том предмете")
	}
}

// ОТКАЗ НАЗЫВАЕТ ПРИЧИНУ И ОПОЗНАЁТСЯ МАШИННО.
//
// Вызывающему нужно отличить «поставщика на этой посадке нет» от «поставщик не
// ответил»: первое повтором не лечится никогда, второе лечится. Поэтому отказ
// сопоставим `errors.Is`, а не только читаем глазами.
func TestAbsentProviderAdminClient_EveryCallRefusesByName(t *testing.T) {
	absent := clients.NewAbsentProviderAdminClient()
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"DeleteLoginSessions", func() error { return absent.DeleteLoginSessions(ctx, "subject") }},
		{"DeleteOAuthClient", func() error { return absent.DeleteOAuthClient(ctx, "client-id") }},
		{"CreateOAuthClient", func() error {
			_, err := absent.CreateOAuthClient(ctx, clients.CreateOAuthClientRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		err := tc.call()
		if err == nil {
			t.Errorf("%s() = nil; вызов дороги, которой нет, обязан отказать, "+
				"а не сделать вид, что сходил", tc.name)
			continue
		}
		if !errors.Is(err, clients.ErrNoExternalIdentityProvider) {
			t.Errorf("%s(): отказ не опознаётся машинно (%v); вызывающий не отличит "+
				"«поставщика нет» от «поставщик не ответил», и будет повторять вечно", tc.name, err)
		}
		if !strings.Contains(err.Error(), "identity provider") {
			t.Errorf("%s(): текст отказа не называет предмет: %q", tc.name, err.Error())
		}
	}
}

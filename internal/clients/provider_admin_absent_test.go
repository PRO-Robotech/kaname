// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/clients"
)

// adminRoadClient — клиент административной дороги, названный ролью.
type adminRoadClient = clients.HydraAdminClient

// КЛИЕНТ АДМИНИСТРАТИВНОЙ ДОРОГИ БЕЗ АДРЕСА ОТКАЗЫВАЕТ ПО ИМЕНИ (задача kaname#21,
// преемник закрытой-при-живом-предмете kacho#2489).
//
// Производителя такого клиента в корне больше нет: развилка посадки
// (kaname#338) на посадке без поставщика дороги не строит и клиента не отдаёт
// никому. Здесь судится запасной отказ по умолчанию — нулевое значение типа
// звонить не может, чем бы его ни собрали.
//
// Вызывающему нужно отличить «дороги нет» от «поставщик не ответил»: первое
// повтором не лечится никогда, второе лечится. Поэтому отказ сопоставим
// `errors.Is`, а не только читаем глазами.
//
// ЗАКОННЫЙ БЛИЗНЕЦ отличается ОДНИМ фактом — адресом: тот же клиент с адресом
// сервера пробы именованного отказа не получает. Без него отрицание зеленело бы
// на клиенте, отказывающем всегда.
func TestProviderAdminClientWithoutAddress_EveryCallRefusesByName(t *testing.T) {
	absent := &adminRoadClient{}
	ctx := context.Background()

	cases := []struct {
		name string
		call func(c *adminRoadClient) error
	}{
		{"DeleteLoginSessions", func(c *adminRoadClient) error { return c.DeleteLoginSessions(ctx, "subject") }},
		{"DeleteOAuthClient", func(c *adminRoadClient) error { return c.DeleteOAuthClient(ctx, "client-id") }},
		{"CreateOAuthClient", func(c *adminRoadClient) error {
			_, err := c.CreateOAuthClient(ctx, clients.CreateOAuthClientRequest{})
			return err
		}},
	}
	for _, tc := range cases {
		err := tc.call(absent)
		if err == nil {
			t.Errorf("%s() = nil; вызов дороги без адреса обязан отказать, "+
				"а не сделать вид, что сходил", tc.name)
			continue
		}
		if !errors.Is(err, clients.ErrNoExternalIdentityProvider) {
			t.Errorf("%s(): отказ не опознаётся машинно (%v); вызывающий не отличит "+
				"«дороги нет» от «поставщик не ответил», и будет повторять вечно", tc.name, err)
		}
		if !strings.Contains(err.Error(), "identity provider") {
			t.Errorf("%s(): текст отказа не называет предмет: %q", tc.name, err.Error())
		}
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же клиент, но с адресом. Снятие у поставщика отвечает
	// 204, и ни один из методов снятия именованным отказом не отвечает.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	withAddress := *absent
	withAddress.BaseURL = srv.URL
	withAddress.HTTPClient = srv.Client()
	for _, tc := range cases[:2] {
		if err := tc.call(&withAddress); err != nil {
			t.Errorf("%s() с адресом = %v; клиент, у которого адрес есть, звонит, "+
				"а не отказывает — иначе отрицание выше зеленело бы на клиенте, "+
				"отказывающем всегда", tc.name, err)
		}
	}
}

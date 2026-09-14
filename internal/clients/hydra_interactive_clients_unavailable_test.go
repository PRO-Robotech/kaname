// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// hydra_interactive_clients_unavailable_test.go — отказ ПОСТАВЩИКА на полосе
// интерактивного клиента несёт признак недоступности, и 4xx — не несёт
// (задача #2481).
//
// # Почему проба стоит у ПРОИЗВОДИТЕЛЯ, а не у use-case
//
// Проба use-case уровня подаёт признак СВОЕЙ рукой и потому вакуумна об этом
// предмете: она доказывает, что признак, если он есть, доезжает, — а вопрос
// задачи был в том, ставит ли его кто-нибудь. Сегодня не ставил никто: отказ
// уходил в общий переводчик без признака, и ветвь по умолчанию давала
// внутреннюю ошибку. На крае это 500 вместо 503, а на 500 клиент НЕ повторяет.
//
// # Пара, а не одно утверждение
//
// Три соседние полосы к тому же поставщику отвечают недоступностью явно;
// четвёртая — нет, и это никем не решалось. Но «всё подряд стало
// недоступностью» — другая беда той же величины: отказ, который повтором не
// лечится (поставщик отверг вход), объявленный повторяемым, заводит вечный
// повтор. Поэтому у каждого утверждения здесь стоит близнец: транспорт и 5xx
// признак несут, 4xx — нет.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func interactiveProvider(baseURL string) *InteractiveClientProvider {
	return NewInteractiveClientProvider(NewHydraAdminClient(baseURL, "tok"))
}

// srvWithStatus — поставщик, отвечающий назначенным кодом.
func srvWithStatus(t *testing.T, code int) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"error":"provider said so"}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// unreachableURL — адрес, по которому никто не слушает. Сервер поднимается и
// тут же гасится, поэтому порт заведомо свободен и заведомо наш: выдуманный
// литерал мог бы случайно попасть в чужой слушатель машины.
func unreachableURL(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := srv.URL
	srv.Close()
	return url
}

func spec() interactiveclient.ProviderClientSpec {
	return interactiveclient.ProviderClientSpec{
		Name:         "console-a",
		RedirectURIs: []string{"https://api.example/cb"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
	}
}

func TestInteractiveProvider_TransportFailure_CarriesUnavailable(t *testing.T) {
	p := interactiveProvider(unreachableURL(t))

	_, err := p.Register(context.Background(), spec())
	if err == nil {
		t.Fatal("недостижимый поставщик обязан дать отказ")
	}
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("отказ транспорта не несёт признака недоступности (%v): общий переводчик "+
			"отдаст его внутренней ошибкой, на крае это 500 вместо 503, а на 500 клиент "+
			"не повторяет", err)
	}

	if derr := p.Deregister(context.Background(), "provider-abc"); derr == nil {
		t.Fatal("недостижимый поставщик обязан дать отказ и на снятии")
	} else if !errors.Is(derr, iamerr.ErrUnavailable) {
		t.Fatalf("снятие: отказ транспорта не несёт признака недоступности (%v)", derr)
	}
}

func TestInteractiveProvider_ProviderFault_CarriesUnavailable(t *testing.T) {
	srv := srvWithStatus(t, http.StatusBadGateway)
	p := interactiveProvider(srv.URL)

	_, err := p.Register(context.Background(), spec())
	if err == nil {
		t.Fatal("502 от поставщика обязан дать отказ")
	}
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("5xx поставщика не несёт признака недоступности (%v): это его неполадка, "+
			"и она лечится повтором — в отличие от отвергнутого входа", err)
	}
}

// Законный близнец: отказ, который повтором НЕ лечится, повторяемым не
// объявляется. Без него «всё стало недоступностью» прошло бы обе пробы выше.
func TestInteractiveProvider_RejectedInput_StaysTerminal(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusConflict} {
		srv := srvWithStatus(t, code)
		p := interactiveProvider(srv.URL)

		_, err := p.Register(context.Background(), spec())
		if err == nil {
			t.Fatalf("%d: отказ поставщика обязан дойти", code)
		}
		if errors.Is(err, iamerr.ErrUnavailable) {
			t.Fatalf("%d: отвергнутый вход объявлен повторяемым (%v) — одинаковый повтор "+
				"не изменит ни одного из входов, и вызывающий будет повторять вечно", code, err)
		}
		var apiErr *HydraAPIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != code {
			t.Fatalf("%d: отказ поставщика перестал быть распознаваемым по коду (%v) — "+
				"на этом признаке стоит идемпотентность создания (409 у *HydraAPIError)", code, err)
		}
	}
}

// Контроль предпосылки: дорога, которой НЕТ, остаётся своим отказом и
// недоступностью не притворяется — её повтор не лечит вовсе.
func TestInteractiveProvider_AbsentRoad_IsNotUnavailable(t *testing.T) {
	p := NewInteractiveClientProvider(NewAbsentProviderAdminClient())

	_, err := p.Register(context.Background(), spec())
	if err == nil {
		t.Fatal("несобранная дорога обязана отказать")
	}
	if !errors.Is(err, ErrNoExternalIdentityProvider) {
		t.Fatalf("отказ несобранной дороги перестал опознаваться (%v)", err)
	}
	if errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("«поставщика нет в этой установке» объявлено преходящим (%v): это выбор "+
			"оператора, а не неполадка, и повтор его не изменит", err)
	}
}

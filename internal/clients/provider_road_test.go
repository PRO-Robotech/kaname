// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// provider_road_test.go — исход КАЖДОГО обращения по дороге к поставщику
// попадает в клетку, и клетки различают причину (kacho#2491, #2492).
//
// Утверждается НАБЛЮДАЕМОЕ: что записал счётчик по факту ответа поставщика, —
// а не форма вызова. Проба, утверждающая «наблюдатель позван», осталась бы
// зелёной при классификации, складывающей настройку со сбоем, — то есть при
// ровно том дефекте, ради которого счёт и заводится.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// roadSpy — перехватчик исходов. Хранит пары, а не сумму: сложить их значило бы
// потерять ровно то различение, которое проверяется.
type roadSpy struct{ seen []string }

func (s *roadSpy) ObserveProviderRoad(road, outcome string) {
	s.seen = append(s.seen, road+"/"+outcome)
}

// Пробы АДМИНИСТРАТИВНОЙ дороги здесь больше нет: дорога снята вместе с
// посадкой внешнего поставщика (kaname#363). Её единственная клетка, которой
// нет у обмена, — «несобранная дорога обращением не является», — снята вместе
// с ней; разложение ответов по клеткам и различение транспорта от настройки
// судятся на дороге обмена ниже.

func TestProviderRoad_TokenExchangeTransportFailureIsUnavailableNotMisconfigured(t *testing.T) {
	// Отказ транспорта лечится временем и обязан лежать отдельно от настройки:
	// смешав их, оператор получил бы «поставщик лежит» на неверном адресе.
	spy := &roadSpy{}
	c := (&ProviderTokenClient{
		TokenURL:   "http://127.0.0.1:1",
		HTTPClient: &http.Client{Timeout: 200 * time.Millisecond},
	}).WithRoadObserver(spy)

	_, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{ClientAssertion: "a"})
	require.Error(t, err)
	require.Equal(t, []string{ProviderRoadTokenExchange + "/" + ProviderRoadOutcomeUnavailable}, spy.seen)
}

func TestProviderRoad_TokenExchangeSplitsUnavailableFromMisconfigured(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		outcome string
	}{
		{"обмен удался", http.StatusOK, `{"access_token":"t","expires_in":60}`, ProviderRoadOutcomeOK},
		{"успех с телом не по контракту — адрес", http.StatusOK, `<html>hi</html>`, ProviderRoadOutcomeMisconfigured},
		{"не найдено — адрес", http.StatusNotFound, `{}`, ProviderRoadOutcomeAbsent},
		{"метод не поддержан — адрес", http.StatusMethodNotAllowed, `{}`, ProviderRoadOutcomeMisconfigured},
		{"удостоверение отвергнуто", http.StatusUnauthorized, `{"error":"invalid_client"}`, ProviderRoadOutcomeRejected},
		{"издатель лёг", http.StatusServiceUnavailable, `{}`, ProviderRoadOutcomeUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			spy := &roadSpy{}
			c := (&ProviderTokenClient{TokenURL: srv.URL, HTTPClient: srv.Client()}).WithRoadObserver(spy)
			_, _ = c.ClientCredentials(context.Background(), ClientCredentialsRequest{ClientAssertion: "a"})
			require.Equal(t, []string{ProviderRoadTokenExchange + "/" + tc.outcome}, spy.seen)
		})
	}
}

// Граница названа вслух: расщепление КЛЕТОК не меняет возвращаемого сигнала.
// Обмен по-прежнему отдаёт retryable-сентинел на «по адресу не тот эндпоинт» —
// иначе докерный клиент получил бы иной код, и правка перестала бы быть правкой
// наблюдаемости.
func TestProviderRoad_TokenExchangeSentinelIsUnchangedByTheSplit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer srv.Close()
	c := &ProviderTokenClient{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{ClientAssertion: "a"})
	// ИМЕННО `ErrProviderTokenRejected`, и это не описка. 405 — четырёхсотый, и прежняя
	// ветка отдавала на нём сентинел отказа удостоверения. Клетка счётчика
	// теперь называет его настройкой, а сентинел ОСТАЛСЯ прежним: расщепление
	// клеток не имеет права сменить код, который получит докерный клиент.
	//
	// Первая редакция этой пробы ждала здесь сентинел недоступности — я взял его
	// из прозы шапки файла, не перемерив ветку. Проба опровергла постановку.
	require.ErrorIs(t, err, ErrProviderTokenRejected,
		"сентинел обмена сменился бы вместе с клеткой — это уже не правка наблюдаемости")
}

// nil-наблюдатель законен: счёта нет, решения дороги это не меняет.
func TestProviderRoad_NilObserverChangesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":60}`))
	}))
	defer srv.Close()
	c := &ProviderTokenClient{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{ClientAssertion: "a"})
	require.NoError(t, err)
}

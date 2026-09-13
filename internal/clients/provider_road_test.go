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

// adminAgainst поднимает поставщика, отвечающего названным кодом, и отдаёт
// клиента административной дороги с перехватчиком.
func adminAgainst(t *testing.T, status int, body string) (*HydraAdminClient, *roadSpy) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	spy := &roadSpy{}
	return NewHydraAdminClient(srv.URL, "").WithRoadObserver(spy), spy
}

func TestProviderRoad_AdminDeleteClassifiesEveryAnswerIntoItsOwnCell(t *testing.T) {
	// Ось, ради которой заведена клетка `absent`: 404 остаётся УСПЕХОМ вызова
	// (иначе строка очереди компенсаций перестаёт помечаться доставленной и
	// заклинивает партицию), но перестаёт быть НЕВИДИМЫМ.
	for _, tc := range []struct {
		name    string
		status  int
		outcome string
		wantErr bool
	}{
		{"снято", http.StatusNoContent, ProviderRoadOutcomeOK, false},
		{"не найдено — неразличимо, но видно", http.StatusNotFound, ProviderRoadOutcomeAbsent, false},
		{"метод не поддержан — адрес, а не сбой", http.StatusMethodNotAllowed, ProviderRoadOutcomeMisconfigured, true},
		{"не реализован — адрес, а не сбой", http.StatusNotImplemented, ProviderRoadOutcomeMisconfigured, true},
		{"отвергнуто по существу", http.StatusForbidden, ProviderRoadOutcomeRejected, true},
		{"поставщик лёг", http.StatusBadGateway, ProviderRoadOutcomeUnavailable, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, spy := adminAgainst(t, tc.status, "{}")
			err := c.DeleteOAuthClient(context.Background(), "cli-1")
			if tc.wantErr {
				require.Error(t, err, "ответ %d обязан остаться отказом вызова", tc.status)
			} else {
				require.NoError(t, err, "ответ %d обязан остаться успехом вызова", tc.status)
			}
			require.Equal(t, []string{ProviderRoadAdmin + "/" + tc.outcome}, spy.seen,
				"ответ %d попал не в свою клетку", tc.status)
		})
	}
}

func TestProviderRoad_AdminTransportFailureIsUnavailableNotMisconfigured(t *testing.T) {
	// Отказ транспорта лечится временем и обязан лежать отдельно от настройки:
	// смешав их, оператор получил бы «поставщик лежит» на неверном адресе.
	c := NewHydraAdminClient("http://127.0.0.1:1", "")
	c.HTTPClient = &http.Client{Timeout: 200 * time.Millisecond}
	spy := &roadSpy{}
	c = c.WithRoadObserver(spy)

	require.Error(t, c.DeleteOAuthClient(context.Background(), "cli-1"))
	require.Equal(t, []string{ProviderRoadAdmin + "/" + ProviderRoadOutcomeUnavailable}, spy.seen)
}

func TestProviderRoad_AbsentRoadIsNotCountedAsAnAnswer(t *testing.T) {
	// Посадка без внешнего поставщика дороги не строит вовсе. Считать такой
	// отказ исходом ОБРАЩЕНИЯ значило бы утверждать, что по дороге ходили.
	spy := &roadSpy{}
	c := NewAbsentProviderAdminClient().WithRoadObserver(spy)
	require.Error(t, c.DeleteOAuthClient(context.Background(), "cli-1"))
	require.Empty(t, spy.seen, "несобранная дорога обращением не является")
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
			c := (&HydraTokenClient{TokenURL: srv.URL, HTTPClient: srv.Client()}).WithRoadObserver(spy)
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
	c := &HydraTokenClient{TokenURL: srv.URL, HTTPClient: srv.Client()}
	_, err := c.ClientCredentials(context.Background(), ClientCredentialsRequest{ClientAssertion: "a"})
	// ИМЕННО `ErrHydraRejected`, и это не описка. 405 — четырёхсотый, и прежняя
	// ветка отдавала на нём сентинел отказа удостоверения. Клетка счётчика
	// теперь называет его настройкой, а сентинел ОСТАЛСЯ прежним: расщепление
	// клеток не имеет права сменить код, который получит докерный клиент.
	//
	// Первая редакция этой пробы ждала здесь сентинел недоступности — я взял его
	// из прозы шапки файла, не перемерив ветку. Проба опровергла постановку.
	require.ErrorIs(t, err, ErrHydraRejected,
		"сентинел обмена сменился бы вместе с клеткой — это уже не правка наблюдаемости")
}

// nil-наблюдатель законен: счёта нет, решения дороги это не меняет.
func TestProviderRoad_NilObserverChangesNothing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	c := NewHydraAdminClient(srv.URL, "")
	require.NoError(t, c.DeleteOAuthClient(context.Background(), "cli-1"))
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// methodrefusal_r36_test.go — ФОРМА отказа на неверный метод у REST-фронта
// совпадает с формой полосы входа (задача #261, решение R36 п. 3):
// `405`, `{"code":12,"message":"method not allowed","details":[]}` и заголовок
// `Allow` с методами, которые маршрутизатор фронта на этом пути обслуживает.
//
// Перечень методов не выписывается: его отвечает сам маршрутизатор фронта —
// проба монтирует пути под РАЗНЫМИ наборами методов и требует от каждого
// своего перечня.
package restfront

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// sameJSON — равны ли два документа как значения.
func sameJSON(t *testing.T, got, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Fatalf("тело не JSON: %q: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("ожидание не JSON: %v", err)
	}
	gb, _ := json.Marshal(g)
	wb, _ := json.Marshal(w)
	return string(gb) == string(wb)
}

const r36WrongMethodBody = `{"code":12,"message":"method not allowed","details":[]}`

// frontWithRoutes — фронт ТЕМ ЖЕ конструктором, что и живые, с маршрутами
// под заданными методами; счётчик вызовов доказывает, что выяснение перечня
// обработчиков не исполняет.
func frontWithRoutes(t *testing.T, routes map[string][]string) (*runtime.ServeMux, *int) {
	t.Helper()
	mux := newMux()
	calls := new(int)
	for path, methods := range routes {
		for _, m := range methods {
			err := mux.HandlePath(m, path, func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
				*calls++
				w.WriteHeader(http.StatusOK)
			})
			if err != nil {
				t.Fatalf("маршрут пробы %s %s не смонтирован: %v", m, path, err)
			}
		}
	}
	return mux, calls
}

func TestFront_261_WrongMethodAnswersTheOneFormOfBothSurfaces(t *testing.T) {
	mux, calls := frontWithRoutes(t, map[string][]string{
		"/probe/v1/things":      {http.MethodGet, http.MethodPost},
		"/probe/v1/things/{id}": {http.MethodGet, http.MethodPatch, http.MethodDelete},
		"/probe/v1/one":         {http.MethodPost},
	})

	cases := []struct {
		name, method, path, allow string
	}{
		{"collection", http.MethodDelete, "/probe/v1/things", "GET, POST"},
		{"item", http.MethodPost, "/probe/v1/things/abc", "GET, PATCH, DELETE"},
		{"single", http.MethodGet, "/probe/v1/one", "POST"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))

			if rec.Code != http.StatusMethodNotAllowed {
				t.Fatalf("статус %d, ожидался %d", rec.Code, http.StatusMethodNotAllowed)
			}
			// Сравнение — по значению документа, а не по байтам: печать
			// protojson намеренно не стабильна по пробелам.
			if !sameJSON(t, rec.Body.String(), r36WrongMethodBody) {
				t.Errorf("тело отказа %q, ожидалось %q (форма полосы входа)", rec.Body.String(), r36WrongMethodBody)
			}
			if got := rec.Header().Get("Allow"); got != tc.allow {
				t.Errorf("Allow=%q, ожидалось %q — методы, которые маршрутизатор обслуживает на пути", got, tc.allow)
			}
		})
	}
	if *calls != 0 {
		t.Fatalf("выяснение перечня методов исполнило обработчик %d раз(а); обязано — ни разу", *calls)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: верный метод того же пути обслуживается ровно один раз и
// заголовка перечня не получает.
func TestFront_261_RightMethodIsServedOnceWithoutAllow(t *testing.T) {
	mux, calls := frontWithRoutes(t, map[string][]string{
		"/probe/v1/things": {http.MethodGet, http.MethodPost},
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/probe/v1/things", nil))

	if rec.Code != http.StatusOK || *calls != 1 {
		t.Fatalf("верный метод: статус %d, вызовов %d; ожидалось 200 и 1", rec.Code, *calls)
	}
	if got := rec.Header().Get("Allow"); got != "" {
		t.Fatalf("успешный ответ несёт Allow=%q", got)
	}
}

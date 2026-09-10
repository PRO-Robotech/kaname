// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// methodrefusal_test.go — ФОРМА ОТКАЗА НА НЕВЕРНЫЙ МЕТОД у внешне досягаемых
// поверхностей службы (задача #2493).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Отдельно поставленная служба досягаема снаружи ДВУМЯ HTTP-поверхностями:
// собственным REST-фронтом и эндпоинтом выдачи токена. На один и тот же промах
// клиента — верный путь, неверный метод — они отвечали РАЗНЫМ:
//
//	REST-фронт        → 501 Not Implemented
//	эндпоинт токена   → 405 Method Not Allowed
//
// Каждая половина защитима в своём файле, неверна их РАЗНИЦА: клиент читает её
// как другое место продукта, а 501 вдобавок уводит с дороги — «не реализовано»
// означает для разработчика отсутствующую возможность, и он идёт заводить
// задачу вместо того, чтобы сменить глагол.
//
// 501 приходил НЕ по решению: умолчание маршрутизатора переводит промах метода
// в `Unimplemented`, а тот отображается в 501 таблицей библиотеки. То есть
// статус выбрала библиотека, а не продукт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СВЕДЕНО, А ЧТО ЗАПИСАНО РЕШЕНИЕМ
//
// СВЕДЁН СТАТУС: обе поверхности отвечают 405. Тело фронта при этом остаётся
// прежним ДОСЛОВНО — тот же документ статуса библиотеки с тем же кодом; меняется
// ровно одно число, потому что предмет находки — оно.
//
// ЗАПИСАН РЕШЕНИЕМ ЗАГОЛОВОК допустимых методов. Эндпоинт токена его несёт: у
// него один глагол, и перечень известен. Фронт его НЕ несёт, и это не забывчивость:
// множество глаголов пути знает маршрутизатор, наружу оно не выставлено ни
// одним экспортированным способом (перепись API `runtime.ServeMux` — Handle,
// HandlePath, ServeHTTP, GetForwardResponseOptions), а выписанный перечень был
// бы ложью: пути этой службы обслуживаются под разными наборами глаголов.
// ПРЕДИКАТ СНЯТИЯ: порождённая таблица маршрутов службы — тогда перечень
// становится известен и заголовок появляется у обеих поверхностей.
package restfront

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
)

// probePath — путь, который проба монтирует на фронт под ОДНИМ глаголом.
const probePath = "/probe/v1/things"

// frontWithOnePostRoute — фронт, собранный ТЕМ ЖЕ конструктором, что и живые,
// с единственным маршрутом под POST. Свой мультиплексор здесь не собирается:
// проба, построившая его сама, утверждала бы о своей копии, а не о фронте.
func frontWithOnePostRoute(t *testing.T) *runtime.ServeMux {
	t.Helper()
	mux := newMux()
	err := mux.HandlePath(http.MethodPost, probePath,
		func(w http.ResponseWriter, _ *http.Request, _ map[string]string) {
			w.WriteHeader(http.StatusOK)
		})
	if err != nil {
		t.Fatalf("маршрут пробы не смонтирован: %v", err)
	}
	return mux
}

// Неверный глагол на объявленном пути фронта — 405, как и у эндпоинта токена.
func TestFront_WrongMethodOnAKnownPathAnswers405(t *testing.T) {
	mux := frontWithOnePostRoute(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, probePath, nil))

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("фронт ответил %d, ожидалось %d: обе внешние поверхности службы "+
			"обязаны отвечать на неверный метод одним статусом",
			rec.Code, http.StatusMethodNotAllowed)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: верный глагол проходит. Без него утверждение выше
// зеленело бы на фронте, отвергающем вообще всё.
func TestFront_RightMethodStillReachesTheRoute(t *testing.T) {
	mux := frontWithOnePostRoute(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, probePath, nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("верный глагол ответил %d, ожидалось %d", rec.Code, http.StatusOK)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: НЕИЗВЕСТНЫЙ путь остаётся 404. Правка касается
// ровно промаха глагола; промах пути — другой предмет и другой ответ, и
// смешать их значило бы сказать клиенту, что путь существует.
func TestFront_UnknownPathStays404(t *testing.T) {
	mux := frontWithOnePostRoute(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/probe/v1/nothing", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("неизвестный путь ответил %d, ожидалось %d", rec.Code, http.StatusNotFound)
	}
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 3: тело отказа остаётся документом статуса библиотеки
// с прежним кодом — меняется ровно статус. Утверждение о теле стоит здесь
// потому, что своего обработчика ошибок фронт по-прежнему не заводит, и это
// свойство легко потерять, «заодно» переписав ответ.
func TestFront_WrongMethodKeepsTheLibraryBody(t *testing.T) {
	mux := frontWithOnePostRoute(t)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, probePath, nil))

	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("тип тела %q, ожидался application/json", ct)
	}
	if body := rec.Body.String(); body == "" {
		t.Fatal("тело отказа пусто: клиент не узнает, чем ошибся")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks_test

// recovery_route_exists_test.go — у восстановления пароля есть маршрут на том же
// слушателе, что у остальных хуков провайдера личности.
//
// # Предмет
//
// Провайдер личности зовёт наши хуки по HTTP на :9092. Три из четырёх туда и
// ведут (выдача токена, обновление, заведение пользователя). Четвёртый —
// завершение восстановления пароля — был оставлен на ЛЕГАСИ gRPC-порту с
// REST-подобным путём, которого на чистом gRPC не существует.
//
// Это ровно тот дефект, который уже чинили у заведения пользователя: хук
// молча падает, провайдер считает вызов сделанным, а до нас он не доезжает
// НИКОГДА. Разница лишь в предмете: там пользователь не зеркалился, здесь —
// восстановление пароля не снимает блокировку и не сдвигает отсечку сессий,
// то есть человек, восстановивший доступ, остаётся с прежним состоянием, а
// старые сессии переживают восстановление.
//
// # Почему это не заметили
//
// Комментарий чарта объяснял отсрочку словами «RPC не реализован, поэтому
// маршрута нет». Утверждение пережило свой предмет: RPC реализован
// (`internal_on_recovery.go`), не хватало ровно маршрута. Пока объяснение
// выглядело правдоподобным, никто не проверял его предикатом.
//
// Проба утверждает МЕСТО, а не поведение обработчика: обработчик проверяется
// своими пробами, а здесь предмет — что маршрут вообще есть на мультиплексоре.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
)

// hookStub — обработчик-отметчик: проба спрашивает про маршрут, а не про логику.
type hookStub struct{ hit *bool }

func (h hookStub) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	*h.hit = true
	w.WriteHeader(http.StatusOK)
}

func TestRecoveryHookHasARouteOnTheHooksListener(t *testing.T) {
	var provisionHit, recoveryHit bool
	mux := iamhooks.NewMux(iamhooks.Handlers{
		ProvisionHook: hookStub{hit: &provisionHit},
		RecoveryHook:  hookStub{hit: &recoveryHit},
	})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/recovery", strings.NewReader("{}")))

	if !recoveryHit {
		t.Fatalf("маршрута восстановления на слушателе хуков НЕТ (ответ %d): провайдер личности "+
			"зовёт его по HTTP, не находит и считает вызов сделанным — восстановление пароля не "+
			"доезжает до нас никогда", rec.Code)
	}

	// Законный близнец: соседний хук на месте — иначе утверждение выше зеленело
	// бы на мультиплексоре, который отвечает на что угодно.
	rec2 := httptest.NewRecorder()
	mux.ServeHTTP(rec2, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/provision", strings.NewReader("{}")))
	if !provisionHit {
		t.Fatal("соседний хук заведения пользователя тоже не отвечает — сломан сам мультиплексор, " +
			"и утверждение о восстановлении ничего не значит")
	}
}

// TestUnwiredHookGetsNoRoute — необъявленный хук маршрута НЕ получает.
//
// Иначе «маршрут есть» стало бы свойством мультиплексора, а не проводки: путь
// отвечал бы 200 при отсутствующем обработчике, и отказ провайдеру выглядел бы
// успехом.
func TestUnwiredHookGetsNoRoute(t *testing.T) {
	mux := iamhooks.NewMux(iamhooks.Handlers{})

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/iam/v1/hooks/recovery", strings.NewReader("{}")))

	if rec.Code == http.StatusOK {
		t.Fatal("непровязанный хук восстановления всё равно ответил 200 — значит маршрут есть " +
			"без обработчика, и провайдер получит успех на вызове, которого никто не обработал")
	}
}

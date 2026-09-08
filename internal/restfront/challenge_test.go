// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

// challenge_test.go — HTTP-поверхность отвечает не назвавшемуся `401` И НЕСЁТ
// ПОДСКАЗКУ, чем назваться (задача продукта #2103, находка Н1 приёмки
// KAN-REST-1).
//
// # Почему подсказка вообще понадобилась
//
// Её производил КРАЙ платформы. У отдельно поставленной службы края нет by
// construction — и вместе с ним исчез единственный производитель. Статус `401`
// приезжает сам: слушатель отвечает `UNAUTHENTICATED`, а отображение кода в
// статус делает библиотека. Заголовок вызова не приезжает ни от кого.
//
// # Почему обёртка ОТВЕТА, а не свой обработчик ошибок
//
// Свой обработчик ошибок сменил бы множество производимых статусов, и таблица
// статусов приёмки перестала бы описывать поведение (шапка пакета говорит это
// прямо). Обёртка ставит ЗАГОЛОВОК и не трогает ни кода, ни тела: множество
// статусов остаётся тем, что задаёт библиотека.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// TestChallenge_UnauthorizedCarriesTheHint — несущее утверждение.
func TestChallenge_UnauthorizedCarriesTheHint(t *testing.T) {
	h := withAuthenticationChallenge(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":16}`))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/projects", nil))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("статус = %d, ожидался %d", rec.Code, http.StatusUnauthorized)
	}
	if got := rec.Header().Get(challengeHeader); got != AuthenticationChallenge {
		t.Fatalf("подсказка = %q, ожидалась %q", got, AuthenticationChallenge)
	}
	if body := rec.Body.String(); body != `{"code":16}` {
		t.Fatalf("тело изменено обёрткой: %q", body)
	}
}

// TestChallenge_SuccessCarriesNothing — положительный близнец. Без него
// утверждение выше зеленело бы на обёртке, ставящей заголовок ВСЕГДА: подсказка
// на успешном ответе — приглашение назваться там, где уже назвались.
func TestChallenge_SuccessCarriesNothing(t *testing.T) {
	h := withAuthenticationChallenge(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"id":"prj-1"}`))
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/projects", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("статус = %d, ожидался %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get(challengeHeader); got != "" {
		t.Fatalf("подсказка приложена к успешному ответу: %q", got)
	}
}

// TestChallenge_ForbiddenCarriesNothing — второй близнец, и он про РАЗНИЦУ,
// ради которой задача заведена: «не пускают» — не повод называться заново.
func TestChallenge_ForbiddenCarriesNothing(t *testing.T) {
	h := withAuthenticationChallenge(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/projects", nil))

	if got := rec.Header().Get(challengeHeader); got != "" {
		t.Fatalf("подсказка приложена к отказу по правам: %q", got)
	}
}

// TestChallenge_HintNamesTheSchemeAndNothingElse — форма подсказки.
//
// RFC 6750 §3.1: запросу БЕЗ сведений об аутентификации код ошибки прилагать не
// следует. Значит подсказка называет схему и молчит о причине — и молчит она
// одинаково на обеих полосах отказа, поэтому оракулом не является.
func TestChallenge_HintNamesTheSchemeAndNothingElse(t *testing.T) {
	if AuthenticationChallenge != "Bearer" {
		t.Fatalf("подсказка = %q; ожидалась голая схема без кода ошибки", AuthenticationChallenge)
	}
}

// TestChallenge_PublicFrontIsWrapped — размещение. Обёртка, не провязанная в
// сборщик фронта, оставила бы утверждения выше вакуумными: они зелены на самой
// обёртке и ничего не говорят о том, стоит ли она на пути запроса.
//
// Спрашивается у самого сборщика, а не у перечня звеньев: перечень и есть тот
// дрейф, из-за которого проводка меняется, а замок этого не замечает. Адрес
// слушателя произволен — привязки поднимаются, не соединяясь.
func TestChallenge_PublicFrontIsWrapped(t *testing.T) {
	h, err := NewPublic(context.Background(), "127.0.0.1:1", dialOpts())
	if err != nil {
		t.Fatalf("сборка публичного фронта: %v", err)
	}
	if _, wrapped := h.(*challengeHandler); !wrapped {
		t.Fatalf("публичный REST-фронт собран БЕЗ обёртки подсказки")
	}
}

// TestChallenge_InternalFrontIsNotWrapped — зеркало решения, и оно обязательно.
// Внутренний фронт обслуживает модули, называющиеся клиентским сертификатом;
// совет «предъяви Bearer» указал бы им действие, которого у них нет. Различие
// полос названо утверждением, а не оставлено умолчанием.
func TestChallenge_InternalFrontIsNotWrapped(t *testing.T) {
	h, err := NewInternal(context.Background(), "127.0.0.1:1", dialOpts())
	if err != nil {
		t.Fatalf("сборка внутреннего фронта: %v", err)
	}
	if _, wrapped := h.(*challengeHandler); wrapped {
		t.Fatalf("внутренний REST-фронт несёт подсказку `Bearer`, которой его вызывающим не воспользоваться")
	}
}

func dialOpts() []grpc.DialOption {
	return []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
}

// TestChallenge_WrapperKeepsTheWritersAbilities — обёртка не отнимает у ответа
// возможностей обёрнутого писателя.
//
// Потоковые ответы библиотеки ходят через сбрасыватель, а сроки — через
// контроллер, который ищет их обходом `Unwrap`. Обёртка, потерявшая любую из
// них, ломает поток МОЛЧА: обработчик прочитает отказ контроллера как «сервер
// так не умеет».
func TestChallenge_WrapperKeepsTheWritersAbilities(t *testing.T) {
	var flushed bool
	h := withAuthenticationChallenge(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
			flushed = true
		}
		if _, unwrappable := w.(interface{ Unwrap() http.ResponseWriter }); !unwrappable {
			t.Errorf("обёртка не отдаёт обёрнутого писателя контроллеру")
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/iam/v1/projects", nil))

	if !flushed {
		t.Fatalf("обёртка потеряла сбрасыватель — поток стал бы ответом целиком и в конце")
	}
	// Сброс до выбора статуса не отнимает подсказки: заголовок ставится в
	// момент выбора, и `Flush` статуса не выбирает.
	if got := rec.Header().Get(challengeHeader); got != AuthenticationChallenge {
		t.Fatalf("подсказка потеряна после сброса: %q", got)
	}
}

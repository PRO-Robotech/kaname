// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registrytokenhttp_test

// cause_reaches_the_log_test.go — причина отказа выдачи docker-токена доходит до
// ЖУРНАЛА, а тело ответа остаётся фиксированным.
//
// # Два адресата, два требования
//
// Клиенту различать нечего: «провайдер лежит», «стучимся не туда» и «имя не
// резолвится» обязаны выглядеть одинаково, иначе тело ответа становится
// оракулом. Нам различать обязательно: чинятся они противоположно.
//
// До этой пробы причина не уходила НИКУДА — ни use-case, ни обработчик её не
// писали. Отказ выглядел исправным контролем: фиксированное тело, верный код,
// и ни слова о том, почему. На живом стенде такой же разрыв у соседней выдачи
// стоил двадцати минут разбора (провайдер был здоров, не резолвилось имя).
//
// Проба парная: без второго утверждения «причина в журнале» зеленело бы и на
// обработчике, который печатает её В ТЕЛО — то есть чинит наблюдаемость ценой
// оракула.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
)

// issuerStub — выдача, отвечающая заданной ошибкой на ОБОИХ путях.
//
// Дублёр выполняет контракт настоящего целиком: обработчик выбирает путь по
// наличию учётных данных, и заглушка, знающая только один, молча увела бы пробу
// на ветку, которой она не занимается.
type issuerStub struct{ err error }

func (s issuerStub) Execute(context.Context, registrytokenuc.IssueInput) (registrytokenuc.IssueOutput, error) {
	return registrytokenuc.IssueOutput{}, s.err
}

func (s issuerStub) ExecuteAnonymous(context.Context, string) (registrytokenuc.IssueOutput, error) {
	return registrytokenuc.IssueOutput{}, s.err
}

// AnonymousEnabled — false: предмет пробы — путь с учётными данными.
func (s issuerStub) AnonymousEnabled() bool { return false }

func TestUnavailabilityCauseReachesTheLogButNotTheBody(t *testing.T) {
	cause := errors.New("dial tcp: lookup kacho-umbrella-hydra-public.kacho.svc: no such host")
	wrapped := errors.Join(registrytokenuc.ErrIssuerUnavailable, cause)

	var log bytes.Buffer
	h := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, issuerStub{err: wrapped}).WithLogger(slog.New(slog.NewTextHandler(&log, nil)))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local&scope=repository:x:pull", nil)
	req.SetBasicAuth("sa", "key")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("код ответа %d, ожидался 503: полоса недоступности сменилась", rec.Code)
	}

	body := rec.Body.String()
	if strings.Contains(body, "no such host") || strings.Contains(body, "lookup") {
		t.Fatalf("причина уехала в ТЕЛО ответа — это оракул: клиент отличает «провайдер лежит» "+
			"от «мы стучимся не туда».\nтело: %q", body)
	}
	if !strings.Contains(body, `"unavailable"`) {
		t.Fatalf("тело перестало быть фиксированным: %q", body)
	}

	if !strings.Contains(log.String(), "no such host") {
		t.Fatalf("причина не дошла до журнала: отказ выглядит исправным контролем, а чинить его "+
			"нечем — ровно тот разрыв, ради которого проба и написана.\nжурнал: %q", log.String())
	}
}

// TestHandlerWithoutALoggerStillAnswers — отсутствие журнала не ломает ответ.
//
// Положительный контроль: проба выше не должна превращать журнал в обязательное
// условие работы обработчика (в пробах его нет).
func TestHandlerWithoutALoggerStillAnswers(t *testing.T) {
	h := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, issuerStub{err: registrytokenuc.ErrIssuerUnavailable})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
	req.SetBasicAuth("sa", "key")
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("без журнала обработчик ответил %d вместо 503", rec.Code)
	}
}

// TestRemovedCredentialKindReachesTheLogButNotTheBody — снятый вид удостоверения
// называется ЖУРНАЛУ и НЕ называется телу (задача #1143).
//
// # Зачем эта строка вообще нужна
//
// Снятие приёма ключевого материала — ЛОМАЮЩЕЕ изменение: клиент, настроенный
// по-старому, начинает получать отказ. Снаружи он неотличим от неверного
// секрета — и обязан быть неотличим. Значит единственное место, где оператор
// может увидеть «арендаторы всё ещё шлют ключ», — журнал. Без него количество
// таких входов равно нулю наблюдаемо и при тысяче их в час.
//
// # Проба ПАРНАЯ, и вторая половина здесь несущая
//
// Строка, печатаемая на ВСЯКОМ отказе, ничего не значит: она перестаёт отличать
// старую настройку клиента от опечатки в секрете. Поэтому рядом — обычный отказ
// аутентификации, на котором этой строки быть НЕ должно, и тело обоих ответов
// сверяется на равенство.
func TestRemovedCredentialKindReachesTheLogButNotTheBody(t *testing.T) {
	const marker = "no longer accepted"

	run := func(t *testing.T, err error) (string, string) {
		t.Helper()
		var log bytes.Buffer
		h := registrytokenhttp.NewTokenHandler(registrytokenhttp.Config{
			Realm:          "https://api.kacho.local/iam/token",
			DefaultService: "registry.kacho.local",
		}, issuerStub{err: err}).WithLogger(slog.New(slog.NewTextHandler(&log, nil)))

		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/iam/token?service=registry.kacho.local", nil)
		req.SetBasicAuth("sa", "presented")
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("код ответа %d, ожидался 401", rec.Code)
		}
		return rec.Body.String(), log.String()
	}

	kindBody, kindLog := run(t, errors.Join(
		registrytokenuc.ErrUnauthenticated, registrytokenuc.ErrCredentialKindNotAccepted))
	plainBody, plainLog := run(t, registrytokenuc.ErrUnauthenticated)

	if !strings.Contains(kindLog, marker) {
		t.Fatalf("снятый вид не назван журналу: оператор не узнает, что арендаторы всё ещё "+
			"настроены на снятый вход.\nжурнал: %q", kindLog)
	}
	if strings.Contains(plainLog, marker) {
		t.Fatalf("строка печатается и на обычном отказе — она перестаёт отличать старую "+
			"настройку клиента от неверного секрета.\nжурнал: %q", plainLog)
	}
	if kindBody != plainBody {
		t.Fatalf("тела отказов различаются — это оракул:\n  снятый вид: %q\n  прочий отказ: %q",
			kindBody, plainBody)
	}
	if strings.Contains(kindBody, "presented") {
		t.Fatalf("тело пересказывает предъявленное: %q", kindBody)
	}
}

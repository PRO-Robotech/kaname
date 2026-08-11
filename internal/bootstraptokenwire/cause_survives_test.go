// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package bootstraptokenwire

// cause_survives_test.go — причина недоступности провайдера доезжает до
// ЖУРНАЛА, а полоса ответа остаётся прежней.
//
// # Предмет
//
// Наружу отказ выдачи первого токена — одна и та же полоса недоступности с
// фиксированным текстом: различать «провайдер лежит», «мы стучимся не туда» и
// «сборка запроса не удалась» вызывающему нельзя, это оракул. Внутри — ровно
// наоборот: чинятся они противоположно, и первое, что спросит инженер, — что
// именно ответила сеть.
//
// Клиент причину СОХРАНЯЕТ (`fmt.Errorf("%w: %v", ErrHydraUnavailable, err)`).
// Адаптер её терял: увидев полосу недоступности, возвращал голый sentinel, и в
// журнал уходило «issuer unavailable» без единого слова о том, почему.
//
// # Чего это стоило (наблюдалось 2026-08-11)
//
// На живом стенде выдача первого токена отказывала, и разбор занял двадцать
// минут: провайдер здоров, issuer согласован, ключ подписи на месте, сеть есть.
// Причина оказалась в том, что адрес обмена задан полным доменным именем, а на
// той машине суффиксы хоста протекли в поды и полная форма `*.svc.cluster.local`
// не резолвилась — три коротких формы работали. Одна строка «no such host» в
// журнале закрыла бы вопрос сразу; вместо неё стоял пересказ собственного
// решения об отказе.
//
// # Что утверждает проба
//
// Причина оборачивается, а не подменяется: sentinel по-прежнему опознаётся
// `errors.Is` (поведение use-case не меняется), но текст ошибки НЕСЁТ исходную
// причину. Отдельно закреплено, что отказ провайдера (4xx) полосой
// недоступности не притворяется.

import (
	"context"
	"errors"
	"strings"
	"testing"

	bootstraptoken "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/bootstrap_token"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// exchangeStub — обмен, отвечающий заданной ошибкой.
type exchangeStub struct{ err error }

func (s exchangeStub) ClientCredentials(context.Context, clients.ClientCredentialsRequest) (clients.TokenResponse, error) {
	return clients.TokenResponse{}, s.err
}

func TestUnavailabilityKeepsItsCauseForTheLog(t *testing.T) {
	// Форма, в которой причину отдаёт клиент: sentinel + текст сети.
	cause := errors.New("dial tcp: lookup kacho-umbrella-hydra-public.kacho.svc.cluster.local: no such host")
	wrapped := errors.Join(clients.ErrHydraUnavailable, cause)

	a := hydraExchange{exchange: exchangeStub{err: wrapped}}
	_, err := a.Exchange(context.Background(), bootstraptoken.ExchangeInput{})

	if err == nil {
		t.Fatal("недоступность провайдера не дала ошибки — выдача первого токена открылась бы")
	}
	if !errors.Is(err, bootstraptoken.ErrIssuerUnavailable) {
		t.Fatalf("полоса ответа сменилась: use-case опознаёт недоступность по sentinel, "+
			"а получил %v", err)
	}
	if !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("причина потеряна: в журнал уйдёт пересказ собственного решения об отказе, "+
			"а не то, что ответила сеть.\nполучено: %q", err.Error())
	}
}

// TestRejectionIsNotDressedAsUnavailability — отказ провайдера (4xx) полосой
// недоступности не притворяется.
//
// Положительный контроль к пробе выше: без него «причина сохранена» зеленело бы
// и на адаптере, который сохраняет её ВСЕГДА — то есть перестал различать
// «не ответил» и «отверг», а это разные исходы с разной ценой.
func TestRejectionIsNotDressedAsUnavailability(t *testing.T) {
	rejection := errors.New("token endpoint rejected the assertion: invalid_client")

	a := hydraExchange{exchange: exchangeStub{err: rejection}}
	_, err := a.Exchange(context.Background(), bootstraptoken.ExchangeInput{})

	if err == nil {
		t.Fatal("отказ провайдера не дал ошибки")
	}
	if errors.Is(err, bootstraptoken.ErrIssuerUnavailable) {
		t.Fatalf("отказ провайдера выдан за недоступность — повтор такого запроса не пройдёт "+
			"никогда, а полоса недоступности обещает обратное: %v", err)
	}
	if !strings.Contains(err.Error(), "invalid_client") {
		t.Fatalf("причина отказа потеряна: %q", err.Error())
	}
}

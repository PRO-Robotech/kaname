// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package oauth_ceremony

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"
)

// ExchangeDeps — зависимости обмена. Все обязательны.
type ExchangeDeps struct {
	Engine ExchangeEngine
	Units  RequestUnits
	// SettleTimeout — срок урегулирования запроса: одно закрепление
	// транзакции. Тот же, что у одного вызова порта хранилища.
	SettleTimeout time.Duration
}

// ExchangeUseCase — обмен кода и оборот токена обновления: одна операция
// церемонии в своей единице запроса.
//
// # Граница транзакции запроса — здесь
//
// Погашение кода открывает транзакцию запроса (`RequestUnits`), и её
// урегулирование принадлежит тому, кто открыл единицу: урегулирование идёт на
// КАЖДОМ выходе — на успехе, на отказе и на панике посреди операции (отложенным
// вызовом, паника идёт дальше). Иначе транзакция оставалась бы открытой: связь
// пула не вернулась бы, а замок строки кода жил бы до потолка простоя в
// транзакции.
//
// Урегулирование — ДО ответа и отвязано от отмены вызывающего, со своим сроком:
// ответ «отказ» после незакреплённого погашения оставил бы код живым для
// повтора.
type ExchangeUseCase struct {
	d ExchangeDeps
}

// NewExchangeUseCase строит обмен. Неполная провязка — отказ построения.
func NewExchangeUseCase(d ExchangeDeps) (*ExchangeUseCase, error) {
	switch {
	case d.Engine == nil:
		return nil, errors.New("ceremony: exchange needs the ceremony")
	case d.Units == nil:
		return nil, errors.New("ceremony: exchange needs the exchange request units")
	case d.SettleTimeout <= 0:
		return nil, errors.New("ceremony: exchange needs the deadline of its settlement")
	}
	return &ExchangeUseCase{d: d}, nil
}

// ErrNotSettled — урегулирование запроса не состоялось. На успехе операции это
// отказ операции: токен при незакреплённом погашении не выдаётся.
var ErrNotSettled = errors.New("ceremony: the exchange request was not settled")

// Execute исполняет операцию церемонии в единице запроса и урегулирует её на
// каждом выходе. Отказ урегулирования сопровождает отказ операции, а на успехе
// заменяет его.
func (uc *ExchangeUseCase) Execute(ctx context.Context, req oauthceremony.TokenRequest) (res oauthceremony.TokenResult, err error) {
	unitCtx, settle := uc.d.Units.OpenRequest(ctx)
	defer func() {
		settleCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), uc.d.SettleTimeout)
		serr := settle(settleCtx)
		cancel()
		if serr == nil {
			return
		}
		serr = fmt.Errorf("%w: %w", ErrNotSettled, serr)
		if err == nil {
			res, err = oauthceremony.TokenResult{}, serr
			return
		}
		err = errors.Join(err, serr)
	}()
	return uc.d.Engine.Exchange(unitCtx, req)
}

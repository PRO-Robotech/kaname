// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport

import (
	"context"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/oauthceremony"
)

// Exchanger — обмен церемонии фундамента. Реализует `*oauthceremony.Ceremony`.
type Exchanger interface {
	Exchange(ctx context.Context, req oauthceremony.TokenRequest) (oauthceremony.TokenResult, error)
}

var _ Exchanger = (*oauthceremony.Ceremony)(nil)

// OperationScope — обмен церемонии, срок операции которого виден порту сверки
// секрета клиента (kaname#892).
//
// # Зачем
//
// Мост фундамента зовёт каждый порт со сроком ОДНОГО вызова
// (`oauthceremony.Config.PortTimeout`), и сверка секрета получает его же. Но
// сверка — не оператор базы: она ждёт места вычисления проверяющего по
// очереди с проверками входа людей, и очередь ёмкости длиннее срока одного
// вызова. Ждущая сверка, ограниченная сроком порта, кончалась бы отказом по
// сроку порта, хотя срок операции, посчитанный с очередью
// (`ceremonyOperationDeadline` композиционного корня), ещё не истёк.
//
// Срок порта — предок ничего не знает о сроке операции: контекст вызова порта
// несёт ближайший из двух, и дальний из него не достать. Поэтому обмен идёт
// здесь: срок операции назначается ДО фундамента и кладётся в контекст
// значением, а адаптер сверки (`ClientSecrets`) ждёт места под ним. Фундамент
// назначает операции свой срок той же величины поверх нашего — ближайший из
// двух наш, и сроки совпадают до мгновения.
//
// # Что остаётся под сроком порта
//
// Вызов справочника проверочных значений — оператор базы — идёт под сроком
// порта, как всякий вызов хранения. Под сроком операции идёт только ожидание
// места вычисления; начатое вычисление отмены не знает (`passwordverify`).
//
// Обмен вне этой обёртки сверку не ломает: адаптер ждёт тогда под сроком
// порта, ближайшим из двух, — к сроку, но с отказом раньше, чем позволяет
// операция.
type OperationScope struct {
	engine  Exchanger
	timeout time.Duration
}

// NewOperationScope оборачивает обмен сроком операции timeout — той же
// величиной, что `oauthceremony.Config.OperationTimeout` церемонии engine.
func NewOperationScope(engine Exchanger, timeout time.Duration) (*OperationScope, error) {
	switch {
	case engine == nil:
		return nil, errors.New("ceremonyport: the operation scope needs the ceremony")
	case timeout <= 0:
		return nil, errors.New("ceremonyport: the operation scope needs a positive operation deadline")
	}
	return &OperationScope{engine: engine, timeout: timeout}, nil
}

// operationKey — ключ контекста операции обмена.
type operationKey struct{}

// Exchange исполняет обмен под сроком операции, видимым порту сверки.
func (s *OperationScope) Exchange(ctx context.Context, req oauthceremony.TokenRequest) (oauthceremony.TokenResult, error) {
	op, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	return s.engine.Exchange(context.WithValue(op, operationKey{}, op), req)
}

// operationOf — контекст операции обмена, если вызов идёт под ней; иначе сам
// контекст вызова.
func operationOf(ctx context.Context) context.Context {
	if op, ok := ctx.Value(operationKey{}).(context.Context); ok {
		return op
	}
	return ctx
}

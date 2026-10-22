// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// anonymous_pace.go — темп анонимной выдачи на источник и исходы анонимного
// потока в переписи полосы (kaname#928).
//
// # Почему темп на источник, а не на принципала
//
// Анонимный вызывающий не предъявляет ничего, и субъект у всех анонимных
// токенов один — объявленный принципал. Ключ на принципала дал бы один общий
// предел на всех анонимных клиентов посадки: один поток выбирал бы чужой темп
// целиком. Различить анонимных вызывающих можно только адресом источника, и
// правило адреса — то же, что у прочих точек поверхности выдачи
// (`internal/issuingsource`, Р7): адрес от края только при проверенном
// сертификате края, иначе адрес пира.
//
// # Почему темп решает вариант использования, а не транспорт
//
// Перепись исходов полосы ведёт вариант использования
// ([CredentialKindObserver]); превышение темпа — такой же исход анонимного
// потока, как выдача и отказ адресата. Решённое транспортом, оно писалось бы в
// перепись вторым писателем, и полнота клеток зависела бы от того, оба ли
// писателя провязаны. Транспорт поставляет только адрес источника.
//
// # Почему каждый вход тратит темп
//
// Вход без удостоверения не может «не пройти проверку»: проверять нечего, и
// цена запроса для нас — чеканка подписантом. Поэтому темп тратит всякий
// анонимный вход, дошедший до выдачи, и возврата темпа на отказе нет.
package registry_token

import (
	"errors"
	"fmt"
	"time"
)

// AnonymousPacer — темп анонимных входов на ключ источника. Реализуется
// `internal/exchangepace.Pace` в композиционном корне.
type AnonymousPacer interface {
	// Reserve тратит один вход ключа. ok=false — темп исчерпан, retryAfter —
	// через сколько освободится следующий вход.
	Reserve(key string) (refund func(), retryAfter time.Duration, ok bool)
}

// AnonymousInput — вход анонимного потока.
type AnonymousInput struct {
	// Service — `?service=` запроса; пусто — «не назвал», и адресат выбирает
	// выдача.
	Service string
	// Source — адрес источника по правилу поверхности выдачи. Его выводит
	// транспорт, предъявитель его не выбирает.
	Source string
}

// ErrAnonymousPaceRequired — анонимный поток объявлен, а темп ему не задан:
// построитель отказывает. Анонимный поток без темпа — выдача без предела
// чеканок на источник.
var ErrAnonymousPaceRequired = errors.New("registry token: the anonymous lane needs its pace per source")

// ErrAnonymousPaceExceeded — источник исчерпал темп анонимной выдачи.
var ErrAnonymousPaceExceeded = errors.New("registry token: anonymous pace per source is exhausted")

// AnonymousPaceExceededError — отказ по темпу со сроком ожидания.
// errors.Is(err, ErrAnonymousPaceExceeded) истинно.
type AnonymousPaceExceededError struct {
	// RetryAfter — через сколько источнику освободится следующий вход.
	RetryAfter time.Duration
}

func (e *AnonymousPaceExceededError) Error() string {
	return fmt.Sprintf("%v (retry after %s)", ErrAnonymousPaceExceeded, e.RetryAfter)
}

// Is — отказ по темпу опознаётся общим признаком.
func (e *AnonymousPaceExceededError) Is(target error) bool { return target == ErrAnonymousPaceExceeded }

// Исходы анонимного потока — клетки той же переписи, что исходы полосы
// предъявленного удостоверения. Набор ЗАКРЫТ и приходит из констант.
const (
	// OutcomeAnonymousIssued — анонимный токен выдан. ЗНАМЕНАТЕЛЬ анонимного
	// потока: без него ноль отказов неотличим от потока, не обслужившего ни
	// одного входа.
	OutcomeAnonymousIssued = "anonymous_issued"
	// OutcomeAnonymousPaceExceeded — источник исчерпал темп; чеканки нет.
	OutcomeAnonymousPaceExceeded = "anonymous_pace_exceeded"
	// OutcomeAnonymousAudienceRefused — запрошенный адресат вне объявления
	// посадки.
	OutcomeAnonymousAudienceRefused = "anonymous_audience_refused"
	// OutcomeAnonymousIssuerUnavailable — наш подписант не выпустил токен.
	OutcomeAnonymousIssuerUnavailable = "anonymous_issuer_unavailable"
)

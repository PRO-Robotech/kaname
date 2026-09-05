// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package audiencepolicy — ОДИН предикат выбора адресата выпускаемого токена,
// общий для всех полос выдачи (задачи #1136, #1184).
//
// # Почему общий источник, а не одинаковая проверка в каждой полосе
//
// Полос выдачи по ключу служебной учётки ДВЕ: токен-эндпоинт платформы и
// докерная полоса реестра. Пока предикат существовал копией у одной из них,
// вторая писалась под фиксированный адресат — и адресат её токена называл
// вызывающий. Расхождение никто не решал: оно возникло побочным эффектом.
//
// Две копии предиката разошлись бы снова, и разошлись бы молча: обе полосы по
// отдельности выглядят исправными, неверна их РАЗНИЦА. Здесь копия одна, и
// расхождение невозможно by construction — а не удерживается гейтом, который
// сверял бы две реализации между собой.
//
// # Границы ДВЕ, и они не равноправны
//
// ВНЕШНЯЯ (`Landing`) — объявленная посадкой: каким поверхностям эта полоса
// вообще чеканит удостоверения. Пустая означает «любая», поэтому вызывающий
// обязан отвергнуть построение выдачи без неё.
//
// ВНУТРЕННЯЯ (`Declared`) — объявленная заказчиком при выдаче ключа: для чего
// заведён ЭТОТ ключ. Она действует ВНУТРИ внешней и никогда её не расширяет.
// Иначе заказчик ключа сам решал бы, кому платформа выдаёт токен.
package audiencepolicy

import (
	"errors"
	"fmt"
)

// Отказы ТРИ, и они различаются не ради красоты: «посадка такого адресата не
// объявляла», «ключ выдавался не под этот адресат» и «ключ выдан под адресата,
// которого эта посадка не знает вовсе» чинятся в разных местах и разными
// людьми. Наружу вызывающий отдаёт единый ответ (различимость снаружи была бы
// оракулом); в журнал — эти.
var (
	// ErrOutsideLanding — заказанный адресат вне объявленного посадкой.
	ErrOutsideLanding = errors.New("audiencepolicy: requested audience is outside the landing declaration")
	// ErrOutsideDeclared — заказанный адресат вне объявленного самим ключом.
	ErrOutsideDeclared = errors.New("audiencepolicy: requested audience is outside the audiences declared for the key")
	// ErrNarrowingDisjoint — сужение ключа не пересекается с перечнем посадки:
	// ключ не получит токена НИ ПРИ КАКОМ запросе.
	//
	// Состояние законное и достижимое (ключ выдан под внешнюю федерацию, а эта
	// посадка такого адресата не объявляла), поэтому отказ живёт здесь, а не на
	// выдаче ключа: перечень посадки меняет оператор и после неё. Молчаливый
	// откат на перечень посадки вернул бы сужение, переставшее сужать.
	ErrNarrowingDisjoint = errors.New("audiencepolicy: the audiences declared for the key are none of the ones this deployment declares")
	// ErrNoLanding — перечень посадки пуст. Не отказ вызывающему, а отказ
	// ПОСТРОЕНИЯ: выдача, у которой внешней границы нет, чеканит куда угодно.
	ErrNoLanding = errors.New("audiencepolicy: landing audiences must be declared (empty means 'any')")
)

// Scope — объявленное о выдаче: обе границы плюс адресат для запроса, ни одного
// не назвавшего.
type Scope struct {
	// Landing — внешняя граница, объявленная посадкой. Обязателен непустым.
	Landing []string
	// Default — адресат для запроса, не назвавшего ни одного. Обязан входить в
	// Landing, иначе умолчание отвергалось бы собственной проверкой и глагол не
	// работал бы НИ ПРИ КАКОМ входе.
	Default string
	// Declared — внутренняя граница, объявленная заказчиком при выдаче ключа.
	// Пустая означает «сужения не объявлено», а не «любой адресат».
	Declared []string
	// Subject — идентификатор ключа для ТЕКСТА ОТКАЗА. В решение не входит.
	Subject string
}

// Resolve выбирает адресатов выпускаемого токена.
//
// `requested` — то, что назвал ЗАПРОС. Пустой срез означает «не назвал»: тогда
// адресат берётся из сужения ключа, а при его отсутствии — из умолчания
// посадки. Умолчание посадки НЕ перебивает объявленное ключом: оно есть
// величина для ключа, о своём назначении не заявившего.
//
// Набор, где хотя бы один адресат вне границ, отвергается ЦЕЛИКОМ: приняв его
// частично, выдача выпустила бы токен, адресованный туда, куда ключ не
// объявлялся, — и положительный путь выглядел бы исправным.
func Resolve(s Scope, requested []string) ([]string, error) {
	effective, fallback, err := s.scope()
	if err != nil {
		return nil, err
	}
	if len(requested) == 0 {
		return []string{fallback}, nil
	}
	for _, a := range requested {
		if !Contains(s.Landing, a) {
			return nil, fmt.Errorf("requested audience %q is not in the declared list: %w", a, ErrOutsideLanding)
		}
		if !Contains(effective, a) {
			return nil, fmt.Errorf(
				"requested audience %q is outside the audiences declared for client %s at issuance (%v): %w",
				a, s.Subject, s.Declared, ErrOutsideDeclared)
		}
	}
	return requested, nil
}

// scope — множество, из которого выпуск вправе выбрать, и адресат для запроса,
// не назвавшего ни одного.
//
// Порядок при выборе умолчания не произволен: пока сужение допускает умолчание
// посадки, действует оно (наименьший радиус для уже выданных ключей); когда не
// допускает — берётся ПЕРВЫЙ объявленный ключом из числа допущенных посадкой.
// Перечень заказчика сохраняет порядок по контракту выдачи, поэтому «первый»
// есть его собственный выбор, а не наш.
func (s Scope) scope() ([]string, string, error) {
	if len(s.Landing) == 0 {
		return nil, "", ErrNoLanding
	}
	if len(s.Declared) == 0 {
		return s.Landing, s.Default, nil
	}
	effective := make([]string, 0, len(s.Declared))
	for _, a := range s.Declared {
		if Contains(s.Landing, a) && !Contains(effective, a) {
			effective = append(effective, a)
		}
	}
	if len(effective) == 0 {
		return nil, "", fmt.Errorf(
			"client %s declared audiences %v at issuance and this deployment declares none of them: %w",
			s.Subject, s.Declared, ErrNarrowingDisjoint)
	}
	if Contains(effective, s.Default) {
		return effective, s.Default, nil
	}
	return effective, effective[0], nil
}

// Contains — членство в перечне, ДОСЛОВНОЕ.
//
// Ни приведения регистра, ни отбрасывания хвостовой косой черты, ни разбора
// URL: адресат — непрозрачная строка контракта, и всякая нормализация здесь
// расширяла бы принимаемое молча.
func Contains(list []string, want string) bool {
	for _, a := range list {
		if a == want {
			return true
		}
	}
	return false
}

// DefaultWithin проверяет, что объявленное умолчание входит в объявленный
// посадкой перечень. Предикат стража построения, а не выдачи.
func DefaultWithin(landing []string, def string) bool { return Contains(landing, def) }

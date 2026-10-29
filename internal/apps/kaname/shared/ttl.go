// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"math"
	"time"
)

// MaxTTLSeconds — наибольший срок в секундах, который `time.Duration`
// представляет без заворота: 9223372036 секунд, около 292 лет.
const MaxTTLSeconds = int64(math.MaxInt64 / int64(time.Second))

// TTLFromSeconds переводит срок `ttl_seconds` с провода в длительность.
//
// Голое `time.Duration(s) * time.Second` заворачивается по модулю 2^64 для
// всякого s сверх MaxTTLSeconds: 2^55 даёт РОВНО ноль, то есть написание
// «срок не назван», а 9223372037 — отрицательную длительность, то есть срок
// истечения в прошлом. Всякое сравнение с потолком после такого умножения
// судит завёрнутое число и пропускает запрос (kaname#993).
//
// ok=false означает «срок вне области [0, MaxTTLSeconds]»; вызывающий
// отвергает запрос с именем поля, а нулевая длительность при этом не
// применяется. Отказ отрицательного срока у вызывающего стоит раньше и несёт
// свой текст; здесь отрицательный срок тоже вне области, чтобы функция не
// возвращала завёрнутого значения ни на каком входе.
func TTLFromSeconds(s int64) (d time.Duration, ok bool) {
	if s < 0 || s > MaxTTLSeconds {
		return 0, false
	}
	return time.Duration(s) * time.Second, true
}

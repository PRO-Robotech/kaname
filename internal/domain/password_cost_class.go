// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// password_cost_class.go — КЛАСС СТОИМОСТИ проверочного значения пароля:
// формат вместе с набором параметров стоимости (приёмка ID-PW-1 §3 Р4:
// «класс стоимости — формат вместе с набором параметров, и внутри формата их
// столько, сколько наборов лежит»). Решение kaname#188: время всякого исхода
// входа отсчитывается от потолка — калиброванной стоимости самого дорогого
// класса среди лежащих в хранилище и класса, которым продукт пишет.
//
// Класс — не значение: соли и тела он не несёт и нести не может, поэтому
// печатается, сравнивается и уходит в наблюдаемость свободно. Перечень форматов
// и их параметров — `password_hash_format.go`; здесь ничего не переобъявляется.

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// PasswordCostClass — формат и полный набор параметров стоимости этого формата.
type PasswordCostClass struct {
	Format PasswordHashFormat
	Params map[PasswordHashCostParam]uint32
}

// Validate — формат из перечня; названы ВСЕ параметры стоимости формата и ни
// одного чужого. Неназванный параметр читался бы нулём, а класс с нулём в
// стоимости — не класс.
func (c PasswordCostClass) Validate() error {
	if _, ok := PasswordHashFormatByMarker(string(c.Format)); !ok {
		return fmt.Errorf("Illegal argument password_cost_class.format %q: такого формата нет в перечне; допустимые: %v",
			c.Format, PasswordHashFormatMarkers())
	}
	known := map[PasswordHashCostParam]bool{}
	for _, p := range c.Format.CostParams() {
		known[p] = true
		if _, named := c.Params[p]; !named {
			return fmt.Errorf("Illegal argument password_cost_class.params %q/%q: required", c.Format, p)
		}
	}
	foreign := make([]string, 0, len(c.Params))
	for p := range c.Params {
		if !known[p] {
			foreign = append(foreign, string(p))
		}
	}
	if len(foreign) > 0 {
		sort.Strings(foreign)
		return fmt.Errorf("Illegal argument password_cost_class.params %q: параметры %v формату не принадлежат", c.Format, foreign)
	}
	return nil
}

// Key — ключ класса: формат и параметры в порядке, объявленном перечнем
// (`2a cost=12`, `argon2id memory=65536 iterations=3 parallelism=4`).
// Детерминирован: одна пара «формат, параметры» — один ключ, каким бы порядком
// ни обходилась карта.
func (c PasswordCostClass) Key() string {
	return string(c.Format) + " " + strings.Join(c.paramPairs(), " ")
}

// ParamsLabel — параметры одной строкой через запятую (`cost=12`,
// `memory=65536,iterations=3,parallelism=4`): значение метки наблюдаемости.
func (c PasswordCostClass) ParamsLabel() string {
	return strings.Join(c.paramPairs(), ",")
}

func (c PasswordCostClass) paramPairs() []string {
	params := c.Format.CostParams()
	parts := make([]string, 0, len(params))
	for _, p := range params {
		parts = append(parts, string(p)+"="+strconv.FormatUint(uint64(c.Params[p]), 10))
	}
	return parts
}

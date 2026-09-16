// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify

// declared.go — ОБЪЯВЛЕННОЕ: формат и параметры, которыми продукт пишет вновь
// заводимые значения (приёмка ID-PW-1 §5 PWV-16, производится Ф2 в части
// перечня, ручкой и стражем старта — Ф3).
//
// Здесь — не сама ручка, а то, чем её судят: область значений, которую
// объявляет перечень. Ручку читает полоса входа (`kacho#1269`), страж старта
// зовёт [Declared.Validate] и отказывает в пуске, когда объявленное вне области.
//
// Почему область именно такая:
//
//   - НАЗВАТЬ МОЖНО ТОЛЬКО ЗАПИСЫВАЕМЫЙ ФОРМАТ: наследуемый продукт не пишет и
//     писать не будет, а ручка, называющая его, требовала бы писать новые
//     пароли формой, от которой уходят;
//   - НЕ ВЫШЕ ПОТОЛКА ЗАПИСИ: иначе каждое вновь заводимое значение отвергалось
//     бы собственным проверяющим как «параметры вне потолка»;
//   - НЕ НИЖЕ ПОЛА ЗАПИСИ: иначе стойкость каждого нового пароля понизилась бы
//     молча, а лежащие значения перестали бы переписываться — они «не ниже
//     объявленного», когда объявленное опущено.

import (
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Declared — объявленный формат вновь заводимых значений и его параметры.
type Declared struct {
	Format domain.PasswordHashFormat
	Params map[domain.PasswordHashCostParam]uint32
}

// Validate — объявленное принадлежит области, которую задаёт перечень.
//
// Отказ называет ручку, причину и границу: отказ, не называющий их, не
// восстанавливает следующий шаг оператора.
func (d Declared) Validate() error {
	record, ok := domain.PasswordHashFormatByMarker(string(d.Format))
	if !ok {
		return fmt.Errorf("Illegal argument password_hasher.format %q: такого формата нет в перечне (registry); допустимые: %v",
			d.Format, domain.PasswordHashFormatMarkers())
	}
	if !record.Writable {
		return fmt.Errorf("Illegal argument password_hasher.format %q: формат только читаемый (only-readable) — "+
			"продукт его не пишет", d.Format)
	}

	params := record.Format.CostParams()
	for _, p := range params {
		value, named := d.Params[p]
		if !named {
			return fmt.Errorf("Illegal argument password_hasher.params %q/%q: required — величина не подставляется молча",
				d.Format, p)
		}
		if ceiling := record.Ceiling[p]; value > ceiling {
			return fmt.Errorf("Illegal argument password_hasher.params %q/%q = %d: выше потолка записи (ceiling) %d — "+
				"каждое вновь заводимое значение отвергалось бы как «параметры вне потолка»",
				d.Format, p, value, ceiling)
		}
		if floor := record.Floor[p]; value < floor {
			return fmt.Errorf("Illegal argument password_hasher.params %q/%q = %d: ниже пола записи (floor) %d — "+
				"стойкость каждого нового пароля понизилась бы молча", d.Format, p, value, floor)
		}
	}

	known := map[domain.PasswordHashCostParam]bool{}
	for _, p := range params {
		known[p] = true
	}
	unknown := make([]string, 0, len(d.Params))
	for p := range d.Params {
		if !known[p] {
			unknown = append(unknown, string(p))
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("Illegal argument password_hasher.params %q: параметры %v формату не принадлежат — "+
			"принятое и не прочитанное обещало бы возможность, которой нет", d.Format, unknown)
	}
	return nil
}

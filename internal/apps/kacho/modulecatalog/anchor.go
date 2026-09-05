// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

// anchor.go — ОПОРА паритета, выведенная из ДОСТАВЛЕННЫХ манифестов (задача #1861).
//
// # Зачем это здесь, а не в пакете стража
//
// Страж живёт в `seed` и о манифестах не знает: `seed` не импортирует ни
// `manifest`, ни этот пакет — импорт шёл бы в обратную сторону (`modulecatalog`
// → `seed`), и завести его значило бы получить цикл. Поэтому деривация
// «манифест → строки» остаётся ЗДЕСЬ, рядом с той, которой пользуется
// применитель, а страж принимает уже готовые строки.
//
// Производитель у обеих сторон ОДИН — `RowsOf`. Это несущее свойство, а не
// экономия: возьми опора свою деривацию, и «применитель записал» разошлось бы с
// «страж ожидает» молча — ровно на той величине, ради которой обе стороны и
// сверяются (каноническое написание действия, ярусные строки, исключение
// внутренней плоскости).
//
// # Почему отказ, а не пропуск негодного манифеста
//
// Манифест, не давший строк, есть манифест, которого применитель не применит.
// Пропусти его опора — и живые строки соседа оказались бы «объявленными», хотя
// объявить их было нечем. Отказ приходит ДО применения и до стража.

import (
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// AnchorOfDelivery собирает опору паритета из ДОСТАВЛЕННЫХ манифестов.
//
// Пустая доставка даёт опору ОДНОГО ОБРАЗА (`seed.ImageAnchor`), а не пустую
// опору: «доставки нет» обязано сужать допуск до сегодняшнего, а не открывать
// его. Пустая опора отвергла бы каждую живую строку разом.
func AnchorOfDelivery(manifests []*manifest.Manifest) (seed.Anchor, error) {
	if len(manifests) == 0 {
		return seed.ImageAnchor(), nil
	}
	var delivered catalog.Rows
	for _, m := range manifests {
		if m == nil {
			continue
		}
		d, err := RowsOf(m)
		if err != nil {
			return seed.Anchor{}, fmt.Errorf("опора паритета: манифест модуля %s не даёт "+
				"строк каталога: %w", m.Module, err)
		}
		delivered.Modules = append(delivered.Modules, d.Module)
		delivered.Resources = append(delivered.Resources, d.Resources...)
		delivered.Verbs = append(delivered.Verbs, d.Verbs...)
	}
	return seed.NewAnchor(delivered)
}

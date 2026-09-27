// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuing_source_fallback_collector.go — читатель переписи правила адреса
// источника поверхности выдачи (приёмка ceremony-pace-is-named-by-number.md,
// Р7 п.4; kaname#315).
//
// Клетка растёт, когда заголовок пересылки был и не прочитан (пир не край) либо
// край адреса не дал. Ноль, сложенный по всем репликам службы после прогонов
// стенда, — измеренное свидетельство того, что край и служба сошлись; поэтому
// каждая клетка выходит на витрину НУЛЁМ в том числе: клетка, появляющаяся при
// первом попадании, не отличает «ноль случаев» от «счёта нет».
package metrics

import "github.com/prometheus/client_golang/prometheus"

// IssuingSourceFallbacksMetric — случаи, когда источником стал адрес пира.
const IssuingSourceFallbacksMetric = Namespace + "_issuing_source_fallbacks_total"

// IssuingSourceFallbackCell — клетка витрины: точка и причина.
type IssuingSourceFallbackCell struct{ Point, Reason string }

type issuingSourceFallbackCollector struct {
	cells []IssuingSourceFallbackCell
	read  func() map[IssuingSourceFallbackCell]uint64
	desc  *prometheus.Desc
}

// NewIssuingSourceFallbackCollector регистрирует читателя переписи. Источник и
// непустой набор клеток обязательны: вечный ноль неотличим от непровязанного
// читателя, а пустой набор не вывел бы на витрину ни одного ряда.
func (r *Registry) NewIssuingSourceFallbackCollector(cells []IssuingSourceFallbackCell,
	read func() map[IssuingSourceFallbackCell]uint64,
) {
	if read == nil {
		panic("metrics: NewIssuingSourceFallbackCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(cells) == 0 {
		panic("metrics: NewIssuingSourceFallbackCollector с пустым набором клеток — " +
			"на витрину не выйдет ни одного ряда")
	}
	declared := make([]IssuingSourceFallbackCell, len(cells))
	copy(declared, cells)
	r.reg.MustRegister(&issuingSourceFallbackCollector{
		cells: declared,
		read:  read,
		desc: prometheus.NewDesc(IssuingSourceFallbacksMetric,
			"Requests of the issuing surface whose pace key became the peer address although a forwarding "+
				"header was present or expected: forwarded-from-non-edge (a forwarding header from a peer "+
				"that is not the edge) and edge-without-address (the edge gave no usable address), by point "+
				"(authorize, token). Every declared cell is printed, including the zero ones.",
			[]string{"point", "reason"}, nil),
	})
}

func (c *issuingSourceFallbackCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *issuingSourceFallbackCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, cell := range c.cells {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue,
			float64(census[cell]), cell.Point, cell.Reason)
	}
}

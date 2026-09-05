// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import "github.com/prometheus/client_golang/prometheus"

// retention_collector.go — величины фоновой уборки, снятые ПО КАЖДОМУ ПРЕДМЕТУ
// отдельно (задача #1292, приёмка §3.4).
//
// # Почему по предмету, а не одним числом
//
// Ноль по таблице утверждений означает либо «предъявлений не было», либо
// «уборка не доходит до этой записи реестра», и общая величина эти состояния не
// различает. Это `security.md` §Hardening-инвариант 8 в чистом виде: «ноль
// отказов за всю жизнь контроля» обязано быть заметно.
//
// # Почему число проходов — отдельная величина
//
// Без него ноль снятых строк неотличим от петли, которая не идёт вовсе. Число
// проходов растёт независимо от того, нашлось ли что убирать, поэтому именно
// оно отвечает на вопрос «жив ли механизм».

// RetentionCounts — снимок накопленного уборщиком.
//
// Зеркалит `retention.Counts`; отдельный тип здесь потому, что слой
// наблюдаемости не импортирует прикладной слой.
type RetentionCounts struct {
	// Passes — сколько проходов исполнено за жизнь процесса.
	Passes int64
	// Removed — снято строк по каждому предмету.
	Removed map[string]int64
	// Failures — отказов прохода по каждому предмету.
	Failures map[string]int64
}

// NewRetentionCollector заводит съём величин уборки.
//
// Величина обязана иметь ЧИТАТЕЛЯ: накопитель, чьё число наружу не выходит,
// считает в никуда, и его ноль не утверждает ничего.
func (r *Registry) NewRetentionCollector(read func() RetentionCounts) {
	passes := prometheus.NewDesc(
		"kacho_iam_retention_passes_total",
		"Retention sweep passes executed since process start. Zero here means the loop is not "+
			"running at all — which is a different state from 'nothing to remove', and the two "+
			"must not share one silence.",
		nil, nil)
	removed := prometheus.NewDesc(
		"kacho_iam_retention_rows_removed_total",
		"Rows removed by the retention sweep since process start, BY SUBJECT (one label value per "+
			"table whose growth an outsider sets the pace of). Reported per subject because zero on "+
			"one table means either 'nothing expired' or 'the sweep never reaches this registry entry'.",
		[]string{"subject"}, nil)
	failures := prometheus.NewDesc(
		"kacho_iam_retention_pass_failures_total",
		"Retention sweep passes that failed, BY SUBJECT. A lagging sweep is not fatal — the row "+
			"stays longer than needed while the reader's predicate keeps holding — but a sweep that "+
			"has failed every pass of its life must not be silent.",
		[]string{"subject"}, nil)

	r.reg.MustRegister(funcCollector{
		descs: []*prometheus.Desc{passes, removed, failures},
		collect: func(ch chan<- prometheus.Metric) {
			c := read()
			ch <- prometheus.MustNewConstMetric(passes, prometheus.CounterValue, float64(c.Passes))
			for subject, n := range c.Removed {
				ch <- prometheus.MustNewConstMetric(removed, prometheus.CounterValue, float64(n), subject)
			}
			for subject, n := range c.Failures {
				ch <- prometheus.MustNewConstMetric(failures, prometheus.CounterValue, float64(n), subject)
			}
		},
	})
}

// funcCollector — сборщик поверх замыкания-читателя.
type funcCollector struct {
	descs   []*prometheus.Desc
	collect func(chan<- prometheus.Metric)
}

func (f funcCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range f.descs {
		ch <- d
	}
}

func (f funcCollector) Collect(ch chan<- prometheus.Metric) { f.collect(ch) }

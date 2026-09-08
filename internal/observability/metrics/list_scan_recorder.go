// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// list_scan_recorder.go — стоимость страницы списка, снятая с пути чтения.
//
// # Что мерится и зачем
//
// Приёмка требует, чтобы число рассмотренных строк и обращений к модели прав НЕ
// росло с числом объектов в облаке. Свойство держится устройством пути чтения
// (страница набирается курсором, права спрашиваются партией на страницу), но
// без съёма оно проверяется только пробой — то есть на дереве, а не на живом
// стенде под настоящими данными.
//
// # Гистограмма, а не счётчик
//
// Предмет — РАСПРЕДЕЛЕНИЕ: важно не «сколько всего строк рассмотрено», а «бывают
// ли страницы, стоящие непропорционально дорого». Счётчик сумму даёт, хвост
// прячет.
//
// Границы корзин выбраны от размера страницы: 50 — умолчание, 1000 — потолок
// контракта. Страница, рассмотревшая больше нескольких потолков, означает, что
// видимых строк в наборе мало и догрузки идут одна за другой, — это законно, но
// обязано быть видно.

// ListScanRecorder снимает стоимость одной отданной страницы списка.
type ListScanRecorder struct {
	rows   *prometheus.HistogramVec
	checks *prometheus.HistogramVec
}

// NewListScanRecorder заводит съём и регистрирует его в реестре сервиса.
func (r *Registry) NewListScanRecorder() *ListScanRecorder {
	rec := &ListScanRecorder{
		rows: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: Namespace + "_list_rows_scanned",
			Help: "Rows examined while assembling one returned page of a list, by resource. " +
				"The page is assembled by cursor and re-filled until it is full, so this counts " +
				"ALL re-fills together — a page that costs many re-fills is legitimate but must be visible.",
			Buckets: []float64{50, 100, 250, 500, 1000, 2000, 5000, 10000},
		}, []string{"resource"}),
		checks: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name: Namespace + "_list_permission_checks",
			Help: "Permission-model calls made while assembling one returned page of a list, by resource. " +
				"One call per re-fill by construction: a value that grows with the size of the cloud " +
				"means the batch discipline was lost somewhere.",
			Buckets: []float64{1, 2, 3, 5, 8, 13, 21, 34},
		}, []string{"resource"}),
	}
	r.reg.MustRegister(rec.rows, rec.checks)
	return rec
}

// ObserveListScan принимает стоимость страницы: сколько строк рассмотрено всеми
// догрузками вместе и сколько раз спрошена модель прав.
func (r *ListScanRecorder) ObserveListScan(_ context.Context, resource string, rows, checks int) {
	if r == nil {
		return
	}
	r.rows.WithLabelValues(resource).Observe(float64(rows))
	r.checks.WithLabelValues(resource).Observe(float64(checks))
}

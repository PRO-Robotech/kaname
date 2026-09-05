// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"log/slog"
)

// OutboxScanObserver — ЕДИНСТВЕННЫЙ производитель реакции на исход скана
// очереди. Композиционный корень провязывает им КАЖДЫЙ сканер сервиса.
//
// # Зачем один производитель, а не по замыканию на сайт (#2062)
//
// Реакция на отказ скана — решение об наблюдаемости, и оно обязано быть одним
// для всех очередей сервиса, иначе это второе место об одном предмете: очередь,
// чей сайт забыли поправить, молчала бы на отказе, а её молчание было бы
// неотличимо от исправной работы. Сайты сверяются с этим производителем гейтом
// дерева (`outbox_scan_observer_wiring_test.go`), а не вниманием.
func OutboxScanObserver(rec *OutboxRecorder, table string, logger *slog.Logger, msg string) func(error) {
	if rec != nil {
		// Клетки заводятся ЗДЕСЬ, до первого прохода: ряд, появляющийся только
		// с первым исходом, снова сделал бы «проходов не было» неотличимым от
		// «сканера нет».
		rec.InitScanOutcomes(table)
	}
	return func(err error) {
		if rec != nil {
			rec.ObserveScanFailure(table)
		}
		if logger != nil {
			logger.Warn(msg, "table", table, "err", err)
		}
	}
}

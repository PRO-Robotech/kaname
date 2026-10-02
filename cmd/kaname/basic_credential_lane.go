// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// basic_credential_lane.go — сборка полосы базового секрета внутреннего
// слушателя: авторитет с объявленным пределом и читатель переписи её исходов
// (задача kaname#379).
//
// # Почему это отдельный файл композиционного корня
//
// Обе части по отдельности выглядят исправными и при полусобранной провязке:
// авторитет без предела отвечает, пока база отвечает, а перепись без читателя
// считает, пока никто не смотрит. Ни то, ни другое не проявляется отказом на
// положительном пути, поэтому у каждой части здесь своя проба сборки —
// `basic_credential_lane_deadline_integration_test.go` и
// `basic_credential_outcomes_wiring_test.go`.

import (
	"github.com/jackc/pgx/v5/pgxpool"

	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// newBasicCredentialAuthority собирает авторитет о предъявленном базовом
// секрете с объявленным пределом ОДНОГО обращения к базе.
//
// Предел — [credentialLanePeerTimeout], тот же, что у полос выдачи токена:
// оператор этой полосы для строки человека читает и отсечку отзыва-всех, а
// одно чтение одной строки несёт один предел на любой полосе.
func newBasicCredentialAuthority(pool *pgxpool.Pool) (*kanamepg.BasicCredentialRepo, error) {
	return kanamepg.NewBasicCredentialRepo(pool, credentialLanePeerTimeout)
}

// basicCredentialCells — объявленные клетки переписи строками витрины.
//
// Выведены из того же словаря, которым засеяна перепись обработчика
// ([internaliamapp.DeclaredBasicCredentialCells]), поэтому второй копией
// словаря не являются.
func basicCredentialCells() []metrics.BasicCredentialCell {
	declared := internaliamapp.DeclaredBasicCredentialCells()
	out := make([]metrics.BasicCredentialCell, 0, len(declared))
	for _, c := range declared {
		out = append(out, metricsCell(c))
	}
	return out
}

// basicCredentialOutcomeReader — переходник от переписи обработчика к
// читателю величин.
//
// Живёт в корне, а не в одном из двух пакетов: обработчик не знает реестра
// величин, а реестр не знает типа исхода. Перевод — работа того, кто знает
// обоих.
func basicCredentialOutcomeReader(h *internaliamapp.Handler) func() map[metrics.BasicCredentialCell]uint64 {
	return func() map[metrics.BasicCredentialCell]uint64 {
		census := h.BasicCredentialOutcomes()
		out := make(map[metrics.BasicCredentialCell]uint64, len(census))
		for cell, count := range census {
			out[metricsCell(cell)] = count
		}
		return out
	}
}

func metricsCell(c internaliamapp.BasicCredentialCell) metrics.BasicCredentialCell {
	return metrics.BasicCredentialCell{Verb: string(c.Verb), Outcome: string(c.Outcome)}
}

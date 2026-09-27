// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issuing_source.go — страж режима слушателя выдачи при собранной церемонии
// (приёмка ceremony-pace-is-named-by-number.md, Р7 п.5; kaname#315).
package main

import (
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/issuingsource"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// requireIssuingListenerAsksForACertificate — при собранной церемонии слушатель
// выдачи обязан ЗАПРАШИВАТЬ клиентский сертификат и проверять предъявленный
// (`optional-mutual`); иной режим — отказ старта.
//
// Адрес источника осей П3 и П4 берётся из заголовка края ТОЛЬКО у пира с
// проверенным сертификатом края (правило `issuingsource`). В режиме
// `server-tls-only` сертификата не спрашивают вовсе: каждый ретранслированный
// краем запрос получал бы ключ адреса самого края, и все люди за краем делили бы
// один предел — тихо, без единого отказа старта. `mutual` отверг бы
// вызывающих без сертификата, которым поверхность выдачи открыта.
//
// Судится ЭФФЕКТИВНЫЙ режим — тот, что уходит в транспорт: незаданная ручка
// читается своим умолчанием `server-tls-only` и потому отвергается так же.
func requireIssuingListenerAsksForACertificate(cfg config.Config, m config.MTLSConfig) error {
	if !cfg.AuthN.CeremonyAssembled() {
		return nil
	}
	want := config.IssuingListenerRequestingModeName()
	if got := m.RegistryTokenClientAuthModeValue(); got != want {
		return fmt.Errorf("the own OAuth ceremony is on, and the issuing listener does not ask for a client "+
			"certificate: KANAME_REGISTRYTOKEN_SERVER_MTLS_CLIENTAUTHMODE reads %q, and it must be %q — the "+
			"source address of the pace axes is taken from the edge header only on a verified edge certificate, "+
			"so without it everyone behind the edge would share the edge's own limit; refusing to start", got, want)
	}
	return nil
}

// issuingSourceFallbackCells — клетки переписи правила адреса источника
// строками меток витрины. Выведены из закрытого словаря правила, а не
// выписаны: набор рядов обязан совпадать с набором клеток by construction.
func issuingSourceFallbackCells() []metrics.IssuingSourceFallbackCell {
	cells := issuingsource.Cells()
	out := make([]metrics.IssuingSourceFallbackCell, 0, len(cells))
	for _, c := range cells {
		out = append(out, metrics.IssuingSourceFallbackCell{Point: string(c.Point), Reason: string(c.Reason)})
	}
	return out
}

// issuingSourceFallbackReader — переходник от переписи правила к читателю
// величин. Живёт в корне: правило не знает витрины, а витрина — правила.
func issuingSourceFallbackReader(rule *issuingsource.Rule) func() map[metrics.IssuingSourceFallbackCell]uint64 {
	return func() map[metrics.IssuingSourceFallbackCell]uint64 {
		read := rule.Read()
		out := make(map[metrics.IssuingSourceFallbackCell]uint64, len(read))
		for c, v := range read {
			out[metrics.IssuingSourceFallbackCell{Point: string(c.Point), Reason: string(c.Reason)}] = v
		}
		return out
	}
}

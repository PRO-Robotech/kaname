// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registry_token_source_fallback_collector.go — читатель переписи точки
// анонимной выдачи докерной полосы правила адреса источника (kaname#930).
//
// Клетка растёт, когда заголовок пересылки пришёл от пира, который ни край, ни
// объявленный доверенный пересыльщик: ключом темпа тогда стал адрес этого
// пира. Без клетки неверно названный пересыльщик (все клиенты за прокси
// реестра делят один предел) неотличим от залпа одного клиента: оба видны
// только ростом отказов по темпу. Рост клетки сам по себе значит одно из
// двух: вызывающий пришёл мимо прокси реестра либо пересыльщик назван не тем
// идентификатором. Каждая клетка выходит на витрину НУЛЁМ в том
// числе: клетка, появляющаяся при первом попадании, не отличает «ноль случаев»
// от «счёта нет».
//
// Словарь отделён от `kaname_issuing_source_fallbacks_total`: тот закрыт
// приёмкой ceremony-pace-is-named-by-number.md (Р7 п.4, KN-PACE-37) двумя
// точками.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// RegistryTokenSourceFallbacksMetric — случаи точки анонимной выдачи, когда
// источником стал адрес пира, хотя заголовок пересылки был.
const RegistryTokenSourceFallbacksMetric = Namespace + "_registry_token_source_fallbacks_total"

type registryTokenSourceFallbackCollector struct {
	reasons []string
	read    func() map[string]uint64
	desc    *prometheus.Desc
}

// NewRegistryTokenSourceFallbackCollector регистрирует читателя переписи.
// Источник и непустой набор причин обязательны: вечный ноль неотличим от
// непровязанного читателя, а пустой набор не вывел бы на витрину ни одного
// ряда.
func (r *Registry) NewRegistryTokenSourceFallbackCollector(reasons []string, read func() map[string]uint64) {
	if read == nil {
		panic("metrics: NewRegistryTokenSourceFallbackCollector без источника переписи — " +
			"вечный ноль неотличим от непровязанного читателя")
	}
	if len(reasons) == 0 {
		panic("metrics: NewRegistryTokenSourceFallbackCollector с пустым набором причин — " +
			"на витрину не выйдет ни одного ряда")
	}
	declared := make([]string, len(reasons))
	copy(declared, reasons)
	r.reg.MustRegister(&registryTokenSourceFallbackCollector{
		reasons: declared,
		read:    read,
		desc: prometheus.NewDesc(RegistryTokenSourceFallbacksMetric,
			"Anonymous requests of the docker lane /iam/token whose pace key became the peer address although "+
				"a forwarding header was present or expected: forwarded-from-unrecognized-peer (a forwarding "+
				"header from a peer that is neither the edge nor the declared forwarder "+
				"api-server.registry-token.anonymous-forwarder-san) and edge-without-address (the edge or the "+
				"declared forwarder gave no usable address: no header, two values, a comma list or not an "+
				"address). Growth of the first means either a caller reached the listener bypassing the "+
				"registry proxy, or the forwarder is declared by another identity; growth of the second means "+
				"the registry proxy does not pass the client address as one value. Either way every client "+
				"behind the proxy shares one pace limit. Every declared cell is printed, including the zero ones.",
			[]string{"reason"}, nil),
	})
}

func (c *registryTokenSourceFallbackCollector) Describe(ch chan<- *prometheus.Desc) { ch <- c.desc }

func (c *registryTokenSourceFallbackCollector) Collect(ch chan<- prometheus.Metric) {
	census := c.read()
	for _, reason := range c.reasons {
		ch <- prometheus.MustNewConstMetric(c.desc, prometheus.CounterValue, float64(census[reason]), reason)
	}
}

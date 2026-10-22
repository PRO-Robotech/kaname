// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// registry_token_source_fallback_collector_test.go — клетки
// `kaname_registry_token_source_fallbacks_total{reason}` выходят на витрину все,
// нулём в том числе, и идут из переписи точки анонимной выдачи правила адреса
// источника (kaname#930).

import (
	"testing"

	"github.com/stretchr/testify/require"
)

var registryTokenFallbackReasonsForTest = []string{"forwarded-from-unrecognized-peer"}

func TestRegistryTokenSourceFallbackCollector_PrintsEveryCellFromTheCensus(t *testing.T) {
	census := map[string]uint64{}
	reg := NewRegistry()
	reg.NewRegistryTokenSourceFallbackCollector(registryTokenFallbackReasonsForTest, func() map[string]uint64 {
		out := make(map[string]uint64, len(census))
		for k, v := range census {
			out[k] = v
		}
		return out
	})
	require.Equal(t, "kaname_registry_token_source_fallbacks_total", RegistryTokenSourceFallbacksMetric)
	labels := map[string]string{"reason": "forwarded-from-unrecognized-peer"}
	v, present := labelledCounter(t, reg, RegistryTokenSourceFallbacksMetric, labels)
	require.True(t, present, "клетка не вышла на витрину до первого запроса")
	require.Zero(t, v)

	census["forwarded-from-unrecognized-peer"] = 2
	v, _ = labelledCounter(t, reg, RegistryTokenSourceFallbacksMetric, labels)
	require.Equal(t, 2.0, v, "ряд идёт из переписи")
}

func TestRegistryTokenSourceFallbackCollector_RefusesAnUnwiredCensus(t *testing.T) {
	require.Panics(t, func() {
		NewRegistry().NewRegistryTokenSourceFallbackCollector(registryTokenFallbackReasonsForTest, nil)
	})
	require.Panics(t, func() {
		NewRegistry().NewRegistryTokenSourceFallbackCollector(nil, func() map[string]uint64 { return nil })
	})
}

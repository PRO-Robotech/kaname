// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
)

// TestAccessKeyRecorder_CountsByLaneReasonAndEvent — приёмник наблюдателя
// ключей (Ф7): отказ считается клеткой (полоса, причина), событие — своей,
// регрессия счётчика — отдельным счётчиком; клетки заведены нулём; один
// экземпляр на реестр.
func TestAccessKeyRecorder_CountsByLaneReasonAndEvent(t *testing.T) {
	reg := NewRegistry()
	rec := reg.AccessKeyRecorder()
	require.Same(t, rec, reg.AccessKeyRecorder(), "единственный экземпляр на реестр")
	var _ access_keys.Observer = rec

	rec.AccessKeyRefusalObserved(access_keys.LaneAssertion, access_keys.RefusalSignature)
	rec.AccessKeyRefusalObserved(access_keys.LaneAssertion, access_keys.RefusalSignature)
	rec.AccessKeyEventObserved(access_keys.EventAsserted)
	rec.SignCountRegressionObserved()

	v, ok := labelledCounter(t, reg, AccessKeyRefusalsMetric, map[string]string{"lane": "assertion", "reason": "signature"})
	require.True(t, ok)
	require.Equal(t, 2.0, v)
	v, ok = labelledCounter(t, reg, AccessKeyRefusalsMetric, map[string]string{"lane": "registration", "reason": "signature"})
	require.True(t, ok, "соседняя клетка заведена нулём до первого события")
	require.Equal(t, 0.0, v)
	v, ok = labelledCounter(t, reg, AccessKeyEventsMetric, map[string]string{"event": "asserted"})
	require.True(t, ok)
	require.Equal(t, 1.0, v)
	require.Equal(t, 1.0, gatherCounter(t, reg, AccessKeySignCountRegressionsMetric))
}

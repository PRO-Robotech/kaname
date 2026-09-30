// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// fakeRateProjector — записывает, что ему отдали.
type fakeRateProjector struct {
	calls  int
	max    int64
	window time.Duration
	err    error
}

func (f *fakeRateProjector) ApplyAdmissionRate(_ context.Context, maxEvents int64, window time.Duration) (kanamepg.AdmissionRateProjection, error) {
	f.calls++
	f.max, f.window = maxEvents, window
	return kanamepg.AdmissionRateProjection{Written: 1, MaxEvents: maxEvents, WindowSeconds: int64(window / time.Second)}, f.err
}

// TestAdmissionRate_F4_19_PostureValueIsProjectedOnEveryStart — объявленная
// величина уезжает в проекцию на каждом старте, боевом и нет: посадки, под
// которой строку правил администратор, больше нет (kaname#363); отказ
// проекции — отказ пуска.
func TestAdmissionRate_F4_19_PostureValueIsProjectedOnEveryStart(t *testing.T) {
	three := int64(3)
	own := loginLaneCfg()
	own.AuthN.Registration = config.RegistrationConfig{AdmissionsPerWindow: &three, AdmissionWindow: 90 * time.Minute}
	p := &fakeRateProjector{}
	require.NoError(t, projectAdmissionRate(context.Background(), slog.New(slog.DiscardHandler), p, own))
	require.Equal(t, 1, p.calls)
	require.EqualValues(t, 3, p.max)
	require.Equal(t, 90*time.Minute, p.window)

	dev := own
	dev.AuthN.Mode = config.ModeDev
	p2 := &fakeRateProjector{}
	require.NoError(t, projectAdmissionRate(context.Background(), slog.New(slog.DiscardHandler), p2, dev))
	require.Equal(t, 1, p2.calls, "проекция не выбирается режимом: строку авторитета больше не правит никто, кроме профиля")
	require.EqualValues(t, 3, p2.max)

	p3 := &fakeRateProjector{err: errors.New("db down")}
	err := projectAdmissionRate(context.Background(), slog.New(slog.DiscardHandler), p3, own)
	require.Error(t, err, "отказ проекции — отказ пуска: служба не поднимается с величиной предыдущего пуска")
}

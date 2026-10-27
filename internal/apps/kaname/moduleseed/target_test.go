// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed_test

// target_test.go — второй рубеж kaname#965: применитель посева сам отказывает
// выдаче, чья цель — не ярус целиком.
//
// Манифест подаётся В ОБХОД загрузчика: разобранный документ правится
// значением, потому что загрузчик такую выдачу отверг бы раньше, и проба
// судила бы его, а не применитель. Законный близнец — тот же манифест без
// правки: выдача пишется.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

func TestApply_SeedBindingNotOnTheWholeScopeIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(b *manifest.AccessBinding){
		"перечень объектов": func(b *manifest.AccessBinding) {
			b.Target = "resources"
			b.Resources = []manifest.TargetResource{{Type: "iam.cluster", ID: "cluster_root"}}
		},
		// Цель не названа вовсе: это тоже не ярус целиком.
		"цель не названа": func(b *manifest.AccessBinding) { b.Target = "" },
		// Непустая неизвестная цель: годное значение одно, прочие не перечисляются.
		"неизвестная цель": func(b *manifest.AccessBinding) { b.Target = "Resources" },
	} {
		t.Run(name, func(t *testing.T) {
			m := load(t, ownProbeManifest)
			require.Len(t, m.Seed.AccessBindings, 1, "фикстура: выдача ровно одна")
			mutate(&m.Seed.AccessBindings[0])

			w := &recordingWriter{changed: true}
			tx := &recordingTx{w: w}
			_, err := moduleseed.NewApplier(tx).Apply(context.Background(), m, nil)
			require.ErrorIs(t, err, moduleseed.ErrBindingTargetNotWholeScope)
			require.Contains(t, err.Error(), "seed.accessBindings[0]")
			require.Contains(t, err.Error(), "allInScope")
			require.Empty(t, w.calls, "строки записаны при отказе: %v", w.calls)
			require.Zero(t, tx.txs, "транзакция открыта при отказе")
		})
	}
}

// Судится КАЖДАЯ выдача: вторая с чужой целью останавливает посев целиком,
// хотя первая законна.
func TestApply_SecondSeedBindingIsJudged(t *testing.T) {
	m := load(t, ownProbeManifest)
	require.Len(t, m.Seed.AccessBindings, 1, "фикстура: выдача ровно одна")
	second := m.Seed.AccessBindings[0]
	second.Target = "resources"
	m.Seed.AccessBindings = append(m.Seed.AccessBindings, second)

	w := &recordingWriter{changed: true}
	tx := &recordingTx{w: w}
	_, err := moduleseed.NewApplier(tx).Apply(context.Background(), m, nil)
	require.ErrorIs(t, err, moduleseed.ErrBindingTargetNotWholeScope)
	require.Contains(t, err.Error(), "seed.accessBindings[1]")
	require.Empty(t, w.calls, "строки записаны при отказе: %v", w.calls)
	require.Zero(t, tx.txs, "транзакция открыта при отказе")
}

func TestApply_SeedBindingOnTheWholeScopeIsWritten(t *testing.T) {
	w := &recordingWriter{changed: true}
	_, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), load(t, ownProbeManifest), nil)
	require.NoError(t, err)
	require.NotEqual(t, -1, indexOf(w.calls, "relation "), "выдача на ярус целиком не записана: %v", w.calls)
}

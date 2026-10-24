// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// composed_by_865_test.go — отнесение типов вне канона к модулю своего
// документа (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// сценарий 865-36, производитель P16).
//
// На отнесении шаг корня старта «модель против каталога» (Д10) различает
// модуль, документ которого принёс в модель процесса тип вне канона, и модуль,
// все типы которого модель берёт из канона образа. Документы — те же, что в
// последовательности старта: собственный манифест службы с редакцией (`I(n)`)
// и фикстура контейнера `probemod` (`R`, `E`), каждый разобран загрузчиком.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// doc865I — I(n): собственный манифест службы (модуль `iam`) с редакцией n.
func doc865I(t *testing.T, n int64) *manifest.Manifest {
	t.Helper()
	doc, err := publicreadfixture.WithRevision(servicemanifest.Raw(), n)
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	return m
}

// doc865R — R(n, false), при emptyRoles — E(n, false).
func doc865R(t *testing.T, n int64, emptyRoles bool) *manifest.Manifest {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	doc, err = publicreadfixture.WithoutKey(doc)
	require.NoError(t, err)
	doc, err = publicreadfixture.WithRevision(doc, n)
	require.NoError(t, err)
	if emptyRoles {
		doc, err = publicreadfixture.WithEmptyRoles(doc)
		require.NoError(t, err)
	}
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	return m
}

// unionOf — объединение отнесённого по модулям, отсортированно.
func unionOf(by map[string][]string) []string {
	var out []string
	for _, ts := range by {
		out = append(out, ts...)
	}
	sort.Strings(out)
	return out
}

// Test865_36_OutOfCanonTypesBelongToTheModuleOfTheirDocument — 865-36.
func Test865_36_OutOfCanonTypesBelongToTheModuleOfTheirDocument(t *testing.T) {
	probemodTypes := []string{"probemod_box", "probemod_item"}

	_, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{doc865I(t, 1), doc865R(t, 6, true)})
	require.NoError(t, err)
	t.Logf("перепись: %s; отнесение %v", rep.Census(), rep.ComposedBy)

	require.Empty(t, rep.ComposedOf("iam"), "модуль iam ни одного типа вне канона не принёс")
	require.Equal(t, probemodTypes, rep.ComposedOf("probemod"))
	require.Equal(t, []string{"probemod_box", "probemod_item"}, rep.Composed)
	require.Equal(t, rep.Composed, unionOf(rep.ComposedBy),
		"объединение отнесённого по модулям обязано быть равно Report.Composed")
	require.NotEmpty(t, rep.Reaffirmed, "предпосылка: типы канона в доставке есть — иначе «не отнесён» ничего не утверждает")
	attributed := map[string]bool{}
	for _, ty := range unionOf(rep.ComposedBy) {
		attributed[ty] = true
	}
	for _, ty := range rep.Reaffirmed {
		require.False(t, attributed[ty], "тип канона %q отнесён модулю", ty)
	}

	t.Run("близнец: доставка I(1) одна", func(t *testing.T) {
		_, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{doc865I(t, 1)})
		require.NoError(t, err)
		require.Empty(t, rep.ComposedOf("iam"))
		require.Empty(t, rep.Composed)
		require.Empty(t, rep.ComposedBy)
	})

	t.Run("близнец: доставка R(3, false) одна", func(t *testing.T) {
		_, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{doc865R(t, 3, false)})
		require.NoError(t, err)
		require.Equal(t, probemodTypes, rep.ComposedOf("probemod"))
		require.Equal(t, rep.Composed, unionOf(rep.ComposedBy))
	})
}

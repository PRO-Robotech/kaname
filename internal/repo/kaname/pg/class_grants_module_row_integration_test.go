// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// class_grants_module_row_integration_test.go — ключ S7 модуля на строке
// каталога (kaname#950, Р11 п. 7): применитель пишет его из доставленного
// манифеста, читатель ворот выдачи видит его с той же доставки, и снятый с
// манифеста ключ снимается со строки. Условие изменения `UpsertModule` судится
// здесь, на базе: подставной писатель его не несёт.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

func TestClassGrantsKeyReachesTheModuleRowAndLeavesWithIt(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	repo := kanamepg.New(pool, nil)
	keyed := func() domain.ClassGrantsKeyedModules {
		t.Helper()
		rd, err := repo.Reader(ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(ctx) }()
		k, err := rd.AccessBindings().ClassGrantsKeyedModules(ctx)
		require.NoError(t, err)
		return k
	}
	load := func(doc []byte) *manifest.Manifest {
		t.Helper()
		m, err := manifest.Load(doc)
		require.NoError(t, err)
		return m
	}
	p6, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err)
	p7, err := publicreadfixture.WithClassGrantsKey(p6)
	require.NoError(t, err)

	require.Empty(t, keyed(), "посев: ни один модуль ключа S7 не объявил")

	_, err = applier.ApplyAll(ctx, []*manifest.Manifest{load(p7)})
	require.NoError(t, err, "доставка П7")
	got := keyed()
	require.Contains(t, got, "registry", "ключ П7 не доехал до строки модуля")
	require.Equal(t, []domain.ClassGrantsModuleType{
		{Resource: "registries", Container: true},
		{Resource: "repositories", Container: false},
	}, got["registry"], "живые типы модуля с ключом и признак контейнера")
	require.Len(t, got, 1, "ключ объявил только registry")

	_, err = applier.ApplyAll(ctx, []*manifest.Manifest{load(p6)})
	require.NoError(t, err, "доставка П6 после П7")
	require.Empty(t, keyed(), "снятый с манифеста ключ остался на строке модуля")
}

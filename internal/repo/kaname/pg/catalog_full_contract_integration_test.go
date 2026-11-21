// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestCatalogFullContractSurvivesIndependentRPCContext(t *testing.T) {
	r := writerProtocolRig(t)
	_, contract := fullContractActivate(t, r)
	legacy := kanamepg.NewCatalogWriteRepo(r.runtime)
	full, err := legacy.WithFullWriterContract(contract)
	require.NoError(t, err)
	// A new RPC context cannot see the startup token. The retained executor
	// must select its own exact immutable identity at the actual TX entry.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	before := stateFingerprint(t, ctx, r.admin)
	called := false
	err = legacy.RunInWriteTx(ctx, func(context.Context, modulecatalog.CatalogWriter) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called, "old executor must fail before body")
	require.Equal(t, before, stateFingerprint(t, ctx, r.admin))

	rollback := errors.New("reject after actual catalog write")
	err = full.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		changed, err := w.UpsertModule(ctx, "fullrollbackprobe")
		if err != nil {
			return err
		}
		require.True(t, changed)
		return rollback
	})
	require.ErrorIs(t, err, rollback)
	require.Equal(t, before, stateFingerprint(t, ctx, r.admin), "body error must roll back actual catalog effects")
	require.Equal(t, "active", catalogIdentityPhase(t, r))

	// Run the real applier, the same consumer as InternalModule.Apply. Its
	// protocol executor is retained; no context token or raw TX is injected.
	applier := modulecatalog.NewApplier(full)
	m := catalogAtomicManifest(t)
	report, err := applier.Apply(ctx, m)
	require.NoError(t, err)
	require.True(t, report.Changed())
	applied := stateFingerprint(t, ctx, r.admin)
	require.NotEqual(t, before, applied)
	require.Equal(t, "transition", catalogIdentityPhase(t, r))
	called = false
	err = full.RunInWriteTx(ctx, func(context.Context, modulecatalog.CatalogWriter) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called, "old retained contract must fail before body after changed commit")
	_, err = applier.Apply(ctx, m)
	require.Error(t, err)
	require.Equal(t, applied, stateFingerprint(t, ctx, r.admin))

	// ONLY explicit migration-owner lifecycle installs the actual recomposed
	// model + actual new catalog. The catalog writer never stages or activates.
	next := catalogAtomicBundle(t, r, m)
	require.NotEqual(t, r.bundle.Identity().ModelID, next.Identity().ModelID)
	require.NotEqual(t, r.bundle.Identity().CatalogID, next.Identity().CatalogID)
	require.NoError(t, lifecycleOwner(r).StageFullAuthorityBundle(ctx, next))
	require.NoError(t, lifecycleOwner(r).ActivateFullAuthorityBundle(ctx, next))
	profile, err := kanamepg.NewFullWriterContract(ctx, r.repo, next)
	require.NoError(t, err)
	refreshed, err := legacy.WithFullWriterContract(profile)
	require.NoError(t, err)
	report, err = modulecatalog.NewApplier(refreshed).Apply(ctx, m)
	require.NoError(t, err)
	require.False(t, report.Changed())
	require.Equal(t, "active", catalogIdentityPhase(t, r))
	require.Equal(t, applied, stateFingerprint(t, ctx, r.admin))
	called = false
	err = full.RunInWriteTx(ctx, func(context.Context, modulecatalog.CatalogWriter) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called, "even active new identity cannot upgrade the retained old identity")
	full = refreshed

	// A retained profile is not an everlasting grant. Every fresh TX must
	// recheck phase/generation/identity after owner lifecycle changes.
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(ctx))
	called = false
	err = full.RunInWriteTx(ctx, func(context.Context, modulecatalog.CatalogWriter) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called)
	require.Equal(t, applied, stateFingerprint(t, ctx, r.admin))
}

func TestCatalogFullContractRejectsForeignPoolAndNilProfile(t *testing.T) {
	r := writerProtocolRig(t)
	_, contract := fullContractActivate(t, r)
	_, err := kanamepg.NewCatalogWriteRepo(r.admin).WithFullWriterContract(contract)
	require.Error(t, err)
	_, err = kanamepg.NewCatalogWriteRepo(r.runtime).WithFullWriterContract(nil)
	require.Error(t, err)
	var absent *kanamepg.CatalogWriteRepo
	_, err = absent.WithFullWriterContract(contract)
	require.Error(t, err)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/stretchr/testify/require"
)

type publishedAuthorizationSourceStub struct {
	load    func(context.Context) (authzsnapshot.Snapshot, error)
	confirm func(context.Context, *authzsnapshot.Snapshot) (time.Time, error)
}

func (s publishedAuthorizationSourceStub) LoadActivePublication(ctx context.Context) (authzsnapshot.Snapshot, error) {
	return s.load(ctx)
}

func (s publishedAuthorizationSourceStub) ConfirmActivePublication(ctx context.Context, snapshot *authzsnapshot.Snapshot) (time.Time, error) {
	return s.confirm(ctx, snapshot)
}

func TestPreparePublishedAuthorizationRequiresConfirmationAndBoundedContext(t *testing.T) {
	for _, confirmed := range []bool{false, true} {
		t.Run(map[bool]string{false: "unconfirmed", true: "confirmed"}[confirmed], func(t *testing.T) {
			source := publishedAuthorizationSourceStub{load: func(ctx context.Context) (authzsnapshot.Snapshot, error) {
				deadline, ok := ctx.Deadline()
				require.True(t, ok)
				require.LessOrEqual(t, time.Until(deadline), time.Minute)
				if !confirmed {
					return authzsnapshot.Snapshot{}, authzsnapshot.ErrUnconfirmed
				}
				return authzsnapshot.Snapshot{Revision: 1, Digest: "model-1", ConfirmedAt: time.Now(),
					Plans: &authzmodel.Plans{}, Facts: &catalog.Facts{}}, nil
			}}
			store, err := preparePublishedAuthorization(context.Background(), source, time.Minute, time.Hour)
			if !confirmed {
				require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
				require.Nil(t, store)
				return
			}
			require.NoError(t, err)
			_, err = store.Pin(context.Background())
			require.NoError(t, err)
		})
	}
}

func TestPreparePublishedAuthorizationRejectsInvalidWindowAndCancellation(t *testing.T) {
	source := publishedAuthorizationSourceStub{load: func(context.Context) (authzsnapshot.Snapshot, error) {
		t.Fatal("source called after invalid input or cancellation")
		return authzsnapshot.Snapshot{}, nil
	}}
	for _, poll := range []time.Duration{0, time.Minute} {
		store, err := preparePublishedAuthorization(context.Background(), source, poll, time.Minute)
		require.Error(t, err)
		require.Nil(t, store)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store, err := preparePublishedAuthorization(ctx, source, time.Second, time.Minute)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, store)
}

func TestPublishedWriterGenerationsRequireExactConfirmedIdentity(t *testing.T) {
	snapshot := authzsnapshot.Snapshot{
		Revision: 2, Digest: "model-2", CatalogID: "catalog-2", ConfirmedAt: time.Now(),
		Plans: &authzmodel.Plans{}, Facts: &catalog.Facts{},
	}
	source := publishedAuthorizationSourceStub{load: func(context.Context) (authzsnapshot.Snapshot, error) {
		return snapshot, nil
	}}
	store, err := preparePublishedAuthorization(t.Context(), source, time.Second, time.Hour)
	require.NoError(t, err)
	current := &publishedWriterGeneration{snapshot: &snapshot}
	writers := &publishedWriterGenerations{store: store, current: current}

	pinned, selected, err := writers.resolve(t.Context())
	require.NoError(t, err)
	require.Same(t, current, selected)
	p, ok := authzsnapshot.FromContext(pinned)
	require.True(t, ok)
	require.Equal(t, snapshot.Revision, p.Revision)

	conflict := snapshot
	conflict.CatalogID = "another-catalog"
	_, err = writers.generationFor(pinned, &conflict)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)

	store.ObserveCommittedRevision(3, "model-3")
	_, err = writers.generationFor(pinned, p)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	_, selected, err = writers.resolve(pinned)
	require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
	require.Nil(t, selected)
	require.Same(t, current, writers.current)
}

func TestRunPublishedAuthorizationStopsInFlightReadOnLifecycleCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := publishedAuthorizationSourceStub{load: func(refreshCtx context.Context) (authzsnapshot.Snapshot, error) {
		_, bounded := refreshCtx.Deadline()
		require.True(t, bounded)
		cancel()
		require.ErrorIs(t, refreshCtx.Err(), context.Canceled)
		return authzsnapshot.Snapshot{}, refreshCtx.Err()
	}}
	store, err := authzsnapshot.NewStore(source, time.Hour)
	require.NoError(t, err)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	require.NoError(t, runPublishedAuthorization(ctx, store, time.Minute, logger))
}

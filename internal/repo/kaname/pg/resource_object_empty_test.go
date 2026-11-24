// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func resourceEmptyFixture(t *testing.T) (*resourceObjectPreparation, *resourceParentCapture, *resourceSourceTx) {
	t.Helper()
	source, tx, _ := resourceSourceFixture(t)
	root := &resourceOutputCapture{object: domain.ResourceRef{Type: "vpc.box", ID: "gone"}, modelType: "vpc_box"}
	preparation := &resourceObjectPreparation{lifetime: source.lifetime, source: source, route: resourceObjectFull, root: root, outputs: []*resourceOutputCapture{root}}
	source.entries[resourceSourceKey{kind: resourceSourceMirror, typ: "vpc.box", id: "gone"}] = nil
	for _, k := range []resourceSourceKind{resourceSourcePointerFacts, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceRegistrationPointers, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceFactLedgerHolders} {
		typ := "vpc_box"
		if k == resourceSourceObjectMembers || k == resourceSourceObjectLedger {
			typ = "vpc.box"
		}
		source.entries[resourceSourceKey{kind: k, typ: typ, id: "gone"}] = nil
	}
	return preparation, &resourceParentCapture{tx: tx, source: source}, tx
}
func TestResourceEmptySnapshotRequiresCompleteAbsence(t *testing.T) {
	p, parents, tx := resourceEmptyFixture(t)
	empty, err := p.emptySnapshot(context.Background(), parents)
	require.NoError(t, err)
	require.True(t, empty)
	require.Len(t, tx.limits, 4, "четыре оставшиеся exact projection predicates прочитаны")
	require.Nil(t, p.lifetime.prepared)
	require.Nil(t, p.lifetime.writer)
	require.True(t, p.lifetime.at.IsZero(), "no-op не создаёт final clock")
	for _, kind := range []resourceSourceKind{resourceSourcePointerFacts, resourceSourceObjectReceipts, resourceSourceObjectPublication, resourceSourceObjectRetirement, resourceSourceRegistrationPointers, resourceSourceObjectMembers, resourceSourceObjectLedger, resourceSourceFactLedgerHolders} {
		t.Run(string(rune('a'+kind)), func(t *testing.T) {
			p, parents, _ := resourceEmptyFixture(t)
			typ := "vpc_box"
			if kind == resourceSourceObjectMembers || kind == resourceSourceObjectLedger {
				typ = "vpc.box"
			}
			p.source.entries[resourceSourceKey{kind: kind, typ: typ, id: "gone"}] = []resourceSourceRow{{state: "retained"}}
			empty, err := p.emptySnapshot(context.Background(), parents)
			require.NoError(t, err)
			require.False(t, empty, "любая retained строка исключает no-op")
		})
	}
}
func TestResourceEmptySnapshotDoesNotHideIncompleteOrFailedCapture(t *testing.T) {
	t.Run("missing holder capture", func(t *testing.T) {
		p, parents, _ := resourceEmptyFixture(t)
		delete(p.source.entries, resourceSourceKey{kind: resourceSourceObjectLedger, typ: "vpc.box", id: "gone"})
		empty, err := p.emptySnapshot(context.Background(), parents)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		require.False(t, empty)
	})
	t.Run("retained projection", func(t *testing.T) {
		p, parents, tx := resourceEmptyFixture(t)
		tx.rows = []resourceSourceRow{{state: "standing", value: []byte(`{}`)}}
		empty, err := p.emptySnapshot(context.Background(), parents)
		require.NoError(t, err)
		require.False(t, empty)
	})
	t.Run("budget", func(t *testing.T) {
		p, parents, tx := resourceEmptyFixture(t)
		require.NoError(t, p.source.budget.Charge(100000, 0))
		empty, err := p.emptySnapshot(context.Background(), parents)
		require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
		require.False(t, empty)
		require.Empty(t, tx.limits)
	})
	t.Run("backend", func(t *testing.T) {
		p, parents, tx := resourceEmptyFixture(t)
		failure := errors.New("failed source read")
		tx.err = failure
		empty, err := p.emptySnapshot(context.Background(), parents)
		require.ErrorIs(t, err, failure)
		require.False(t, empty)
	})
	t.Run("cancel", func(t *testing.T) {
		p, parents, tx := resourceEmptyFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		empty, err := p.emptySnapshot(ctx, parents)
		require.ErrorIs(t, err, context.Canceled)
		require.False(t, empty)
		require.Empty(t, tx.limits)
	})
	for _, route := range []resourceObjectRoute{resourceObjectForward, resourceObjectForwardNoStale} {
		p, parents, tx := resourceEmptyFixture(t)
		p.route = route
		empty, err := p.emptySnapshot(context.Background(), parents)
		require.NoError(t, err)
		require.False(t, empty)
		require.Empty(t, tx.limits)
	}
}

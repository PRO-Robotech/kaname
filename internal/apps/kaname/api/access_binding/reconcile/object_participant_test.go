// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package reconcile

import (
	"context"
	"errors"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestObjectParticipantRoutesAllThreeDoorsAndKeepsGroup(t *testing.T) {
	denied := errors.New("participant refused")
	legacy, common, group := &objectTransactionProbe{err: denied}, &objectTransactionProbe{err: denied}, &objectTransactionProbe{err: denied}
	outer, inner, groupEngine := &Reconciler{tx: legacy}, &Reconciler{tx: common}, &Reconciler{tx: group}
	require.NoError(t, outer.WithGroupObjectReconciler(groupEngine))
	require.NoError(t, outer.WithObjectReconciler(inner))
	for _, fn := range []func(context.Context, string, string) error{outer.ReconcileObject, outer.ReconcileObjectForward, outer.ReconcileObjectForwardNoStale} {
		require.ErrorIs(t, fn(context.Background(), "vpc.network", "net-one"), denied)
		require.ErrorIs(t, fn(context.Background(), "iam.group", "grp-one"), denied)
	}
	require.Len(t, common.calls, 3)
	require.Len(t, group.calls, 3)
	require.Empty(t, legacy.calls)
	require.Zero(t, legacy.legacy)
	require.Error(t, inner.WithGroupObjectReconciler(outer), "цикл через общий object route запрещён")
	require.Error(t, outer.WithObjectReconciler(nil))
	for _, fn := range []func(context.Context, string, string) error{outer.ReconcileObject, outer.ReconcileObjectForward, outer.ReconcileObjectForwardNoStale} {
		require.ErrorIs(t, fn(context.Background(), "vpc.network", "net-one"), errObjectParticipantAbsent)
	}
	require.Len(t, common.calls, 3)
	require.Empty(t, legacy.calls)
	require.Zero(t, legacy.legacy)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type objectTransactionProbe struct {
	calls  []string
	legacy int
	err    error
}

func (p *objectTransactionProbe) WithTx(context.Context, func(context.Context, ReconcileStore) error) error {
	p.legacy++
	return p.err
}
func (p *objectTransactionProbe) WithObjectTx(_ context.Context, typ, id string, _ func(context.Context, ReconcileStore) error) error {
	p.calls = append(p.calls, typ+":"+id)
	return p.err
}
func TestGroupObjectRoutingPreservesClosedObjectIntent(t *testing.T) {
	denied := errors.New("entry refused")
	legacy := &objectTransactionProbe{err: denied}
	scoped := &objectTransactionProbe{err: denied}
	outer := &Reconciler{tx: legacy}
	inner := &Reconciler{tx: scoped}
	require.NoError(t, outer.WithGroupObjectReconciler(inner))
	for _, fn := range []func(context.Context, string, string) error{outer.ReconcileObject, outer.ReconcileObjectForward, outer.ReconcileObjectForwardNoStale} {
		require.ErrorIs(t, fn(context.Background(), "iam.group", "grp-object"), denied)
	}
	require.Equal(t, []string{"iam.group:grp-object", "iam.group:grp-object", "iam.group:grp-object"}, scoped.calls)
	require.Empty(t, legacy.calls)
	require.Zero(t, legacy.legacy)
	require.ErrorIs(t, outer.ReconcileObjectForward(context.Background(), "iam.project", "prj-object"), denied)
	require.Equal(t, []string{"iam.project:prj-object"}, legacy.calls)
	require.Error(t, outer.WithGroupObjectReconciler(nil))
	require.Error(t, outer.WithGroupObjectReconciler(outer))
	require.Error(t, inner.WithGroupObjectReconciler(outer))
}

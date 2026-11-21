// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type readonlySelectorTx struct {
	pgx.Tx
	queries int
}

func (tx *readonlySelectorTx) Query(context.Context, string, ...any) (pgx.Rows, error) {
	tx.queries++
	return &readonlySelectorRows{}, nil
}

type readonlySelectorRows struct {
	pgx.Rows
	done bool
}

func (r *readonlySelectorRows) Next() bool {
	if r.done {
		return false
	}
	r.done = true
	return true
}
func (r *readonlySelectorRows) Close()     {}
func (r *readonlySelectorRows) Err() error { return nil }
func (r *readonlySelectorRows) Scan(dest ...any) error {
	for i, v := range []string{"compute.instance", "id", "project", "account"} {
		*dest[i].(*string) = v
	}
	*dest[4].(*[]byte) = []byte(`{"env":"prod"}`)
	return nil
}

// Явная capability не появляется у generic/signed reconcileStore. Даже legacy
// обычный MatchSelector сохраняет прежнее владение; sharing живёт только во view.
func TestLegacyReadOnlyRuleMemberViewHasPrivateLifetime(t *testing.T) {
	tx := &readonlySelectorTx{}
	base := &reconcileStore{tx: tx}
	_, genericHasCapability := any(base).(interface {
		ReadOnlyRuleMemberStore() reconcile.ReconcileStore
	})
	require.False(t, genericHasCapability)
	legacy := &legacyForwardStore{reconcileStore: base}
	firstView := legacy.ReadOnlyRuleMemberStore()
	secondView := legacy.ReadOnlyRuleMemberStore()
	ctx := context.Background()
	types := []string{"compute.instance"}
	labels := map[string]string{"env": "prod"}
	a, err := firstView.MatchSelector(ctx, types, labels)
	require.NoError(t, err)
	b, err := firstView.MatchSelector(ctx, types, labels)
	require.NoError(t, err)
	c, err := secondView.MatchSelector(ctx, types, labels)
	require.NoError(t, err)
	require.Equal(t, a, b)
	require.Equal(t, a, c)
	require.Equal(t, fmt.Sprintf("%p", a[0].Labels), fmt.Sprintf("%p", b[0].Labels))
	require.NotEqual(t, fmt.Sprintf("%p", a[0].Labels), fmt.Sprintf("%p", c[0].Labels))
	normal, err := legacy.MatchSelector(ctx, types, labels)
	require.NoError(t, err)
	normal[0].Labels["env"] = "mutated"
	next, err := legacy.MatchSelector(ctx, types, labels)
	require.NoError(t, err)
	require.Equal(t, "prod", next[0].Labels["env"])
	require.Equal(t, "prod", a[0].Labels["env"])
	require.Equal(t, 5, tx.queries, "decode reuse must not remove fresh SQL reads")
}

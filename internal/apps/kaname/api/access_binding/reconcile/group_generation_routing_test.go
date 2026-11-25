// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

type groupGenerationProbe struct {
	objectDecisionProbe
	groups  []string
	handled bool
}

func (p *groupGenerationProbe) RunPendingGroupGeneration(_ context.Context, id string) ([]ObjectDecisionSize, bool, error) {
	p.groups = append(p.groups, id)
	return p.sizes, p.handled, p.err
}

func TestBackgroundGroupGenerationSelectsExactlyOneParticipant(t *testing.T) {
	ctx := context.Background()
	probe := &groupGenerationProbe{objectDecisionProbe: objectDecisionProbe{sizes: []ObjectDecisionSize{{Objects: 1, Tuples: 2}}}}
	object, err := NewObjectDecisionReconciler(probe, nil, catalogfixture.Source())
	require.NoError(t, err)
	groupErr := errors.New("membership participant")
	group := &objectTransactionProbe{err: groupErr}
	scoped := &Reconciler{tx: group}
	recorder := &sizeSpy{}
	outer := New(&objectTransactionProbe{}, nil, catalogfixture.Source()).WithSizeRecorder(recorder)
	require.NoError(t, outer.WithObjectReconciler(object))
	require.NoError(t, outer.WithGroupObjectReconciler(scoped))
	// Синхронный lifecycle вход всегда сохраняет прежний participant.
	require.ErrorIs(t, outer.ReconcileObject(ctx, "iam.group", "grpSync"), groupErr)
	require.Empty(t, probe.groups)

	require.NoError(t, outer.WithBackgroundGroupObjectReconciler(scoped))
	require.ErrorIs(t, outer.ReconcileObject(ctx, "iam.group", "grpClean"), groupErr)
	probe.handled = true
	require.NoError(t, outer.ReconcileObject(ctx, "iam.group", "grpDirty"))
	probe.err = errors.New("generation commit failed")
	require.ErrorIs(t, outer.ReconcileObject(ctx, "iam.group", "grpError"), probe.err)
	require.ErrorIs(t, outer.ReconcileObjectForward(ctx, "iam.group", "grpForward"), groupErr)
	require.ErrorIs(t, outer.ReconcileObjectForwardNoStale(ctx, "iam.group", "grpNew"), groupErr)
	require.Equal(t, []string{"grpClean", "grpDirty", "grpError"}, probe.groups)
	require.Equal(t, []string{"iam.group:grpSync", "iam.group:grpClean", "iam.group:grpForward", "iam.group:grpNew"}, group.calls)
	require.Empty(t, probe.routes)
	require.Equal(t, 1, recorder.calls)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

type objectDecisionProbe struct {
	routes []ObjectDecisionRoute
	keys   []string
	sizes  []ObjectDecisionSize
	err    error
	during func()
}

func (p *objectDecisionProbe) RunObjectDecision(_ context.Context, typ, id string, route ObjectDecisionRoute) ([]ObjectDecisionSize, error) {
	p.routes = append(p.routes, route)
	p.keys = append(p.keys, typ+":"+id)
	if p.during != nil {
		p.during()
	}
	return p.sizes, p.err
}

// Все три реальные app entrypoints передают неизменный object intent. Сценарий
// group сохраняет приоритет, legacy callback не исполняется ни в одной двери.
func TestObjectDecisionThreeRoutesKeepGroupAndOuterRecorder(t *testing.T) {
	legacy := &objectTransactionProbe{err: errors.New("legacy reached")}
	group := &objectTransactionProbe{err: errors.New("group route")}
	probe := &objectDecisionProbe{sizes: []ObjectDecisionSize{{Objects: 2, Tuples: 3}, {}}}
	inner, err := NewObjectDecisionReconciler(probe, nil, catalogfixture.Source())
	require.NoError(t, err)
	innerRecorder, outerRecorder := &sizeSpy{}, &sizeSpy{}
	inner.WithSizeRecorder(innerRecorder)
	outer := New(legacy, nil, catalogfixture.Source()).WithSizeRecorder(outerRecorder)
	require.NoError(t, outer.WithGroupObjectReconciler(New(group, nil, catalogfixture.Source())))
	require.NoError(t, outer.WithObjectReconciler(inner))
	methods := []func(context.Context, string, string) error{outer.ReconcileObject, outer.ReconcileObjectForward, outer.ReconcileObjectForwardNoStale}
	for i, method := range methods {
		before := i * 2
		probe.during = func() {
			require.Equal(t, before, outerRecorder.calls, "наблюдение до успешного возврата runner")
		}
		require.NoError(t, method(context.Background(), "vpc.network", "net_same"))
		require.ErrorIs(t, method(context.Background(), "iam.group", "grp_same"), group.err)
	}
	require.Equal(t, []ObjectDecisionRoute{ObjectDecisionFull, ObjectDecisionForward, ObjectDecisionForwardNoStale}, probe.routes)
	require.Equal(t, []string{"vpc.network:net_same", "vpc.network:net_same", "vpc.network:net_same"}, probe.keys)
	require.Equal(t, []int{2, 0, 2, 0, 2, 0}, outerRecorder.objects)
	require.Equal(t, []int{3, 0, 3, 0, 3, 0}, outerRecorder.tuples)
	require.Zero(t, innerRecorder.calls, "не заменять recorder внешнего engine собственным")
	require.Len(t, group.calls, 3)
	require.Empty(t, legacy.calls)
	require.Zero(t, legacy.legacy)
}

func TestObjectDecisionFailureAndExplicitNilCannotFallBackOrObserve(t *testing.T) {
	refused := errors.New("commit failed")
	probe := &objectDecisionProbe{sizes: []ObjectDecisionSize{{Objects: 99, Tuples: 99}}, err: refused}
	inner, err := NewObjectDecisionReconciler(probe, nil, catalogfixture.Source())
	require.NoError(t, err)
	legacy, recorder := &objectTransactionProbe{}, &sizeSpy{}
	outer := New(legacy, nil, catalogfixture.Source()).WithSizeRecorder(recorder)
	require.NoError(t, outer.WithObjectReconciler(inner))
	methods := []func(context.Context, string, string) error{outer.ReconcileObject, outer.ReconcileObjectForward, outer.ReconcileObjectForwardNoStale}
	for _, method := range methods {
		require.ErrorIs(t, method(context.Background(), "vpc.network", "net_same"), refused)
	}
	require.Zero(t, recorder.calls, "частичный результат ошибки не является наблюдением")
	require.Len(t, probe.routes, 3)
	require.Error(t, outer.WithObjectReconciler(nil))
	for _, method := range methods {
		require.ErrorIs(t, method(context.Background(), "vpc.network", "net_same"), errObjectParticipantAbsent)
	}
	require.Len(t, probe.routes, 3)
	require.Empty(t, legacy.calls)
	require.Zero(t, legacy.legacy)
}

func TestObjectDecisionAsyncNilDoesNotReuseInnerRecorder(t *testing.T) {
	probe := &objectDecisionProbe{sizes: []ObjectDecisionSize{{Objects: 4, Tuples: 9}}}
	inner, err := NewObjectDecisionReconciler(probe, nil, catalogfixture.Source())
	require.NoError(t, err)
	recorder := &sizeSpy{}
	inner.WithSizeRecorder(recorder)
	outer := New(&objectTransactionProbe{}, nil, catalogfixture.Source())
	require.NoError(t, outer.WithObjectReconciler(inner))
	require.NoError(t, outer.ReconcileObject(context.Background(), "vpc.network", "net_same"))
	require.Zero(t, recorder.calls)
	require.NoError(t, inner.ReconcileObjectForward(context.Background(), "vpc.network", "net_same"))
	require.Equal(t, []int{4}, recorder.objects)
	require.Equal(t, []int{9}, recorder.tuples)
}

func TestObjectDecisionConstructorAndBindingDoorsFailClosed(t *testing.T) {
	engine, err := NewObjectDecisionReconciler(nil, nil, catalogfixture.Source())
	require.ErrorIs(t, err, errObjectParticipantAbsent)
	require.Nil(t, engine)
	probe := &objectDecisionProbe{}
	engine, err = NewObjectDecisionReconciler(probe, nil, nil)
	require.ErrorIs(t, err, errObjectParticipantAbsent)
	require.Nil(t, engine)
	engine, err = NewObjectDecisionReconciler(probe, nil, catalogfixture.Source())
	require.NoError(t, err)
	for _, method := range []func(context.Context, domain.AccessBindingID) error{engine.ReconcileBinding, engine.ConvergeBinding, engine.ReconcileBindingForward, engine.ExpireBinding} {
		require.ErrorIs(t, method(context.Background(), "ab_forbidden"), errObjectDecisionOnly)
	}
	require.Empty(t, probe.routes)
	called := false
	err = engine.tx.WithTx(context.Background(), func(context.Context, ReconcileStore) error { called = true; return nil })
	require.ErrorIs(t, err, errObjectDecisionOnly)
	require.False(t, called)
}

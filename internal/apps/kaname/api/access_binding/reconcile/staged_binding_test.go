// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

type stagedRoute struct {
	modes   []bool
	failure error
}

func (s *stagedRoute) ReconcileStagedBinding(ctx context.Context, _ domain.AccessBindingID, converge bool, _ SizeRecorder) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.modes = append(s.modes, converge)
	return s.failure
}
func TestBindingStageRoutesActualFullForwardConvergeAndErrors(t *testing.T) {
	r := New(nil, nil, catalogfixture.Source())
	var absent *stagedRoute
	require.Error(t, r.WithStagedBindingReconciler(absent))
	route := &stagedRoute{}
	require.NoError(t, r.WithStagedBindingReconciler(route))
	require.Error(t, r.WithStagedBindingReconciler(&stagedRoute{}))
	require.NoError(t, r.ReconcileBinding(context.Background(), "acb-stage"))
	require.NoError(t, r.ReconcileBindingForward(context.Background(), "acb-stage"))
	require.NoError(t, r.ConvergeBinding(context.Background(), "acb-stage"))
	require.Equal(t, []bool{false, false, true}, route.modes)
	route.failure = errors.New("apply failed")
	require.ErrorIs(t, r.ReconcileBinding(context.Background(), "acb-stage"), route.failure)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, r.ConvergeBinding(ctx, "acb-stage"), context.Canceled)
}

func TestBindingStageTypedSpoolPreservesFullDiffAndForeignContainment(t *testing.T) {
	for _, arm := range []domain.Arm{domain.ArmAnchor, domain.ArmLabels} {
		for _, foreign := range []bool{false, true} {
			t.Run(map[domain.Arm]string{domain.ArmAnchor: "anchor", domain.ArmLabels: "labels"}[arm]+map[bool]string{false: "-own", true: "-foreign"}[foreign], func(t *testing.T) {
				project := "prj-own"
				if foreign {
					project = "prj-other"
				}
				obj := domain.MirrorObject{ObjectType: "compute.instance", ObjectID: "instance", ParentProjectID: project, Labels: map[string]string{"env": "prod"}}
				factory := func() *fakeStore {
					return &fakeStore{scope: domain.ScopeAnchor{Type: "project", ID: "prj-own"}, subjectType: "user", subjectID: "usr-stage", active: true, selectors: []domain.RuleSelector{{Arm: arm, RuleFP: "stage-rule", ObjectTypes: []string{"compute.instance"}, MatchLabels: map[string]string{"env": "prod"}, Verbs: []string{"get"}}}, mirror: map[string][]domain.MirrorObject{"compute.instance": {obj}}}
				}
				legacy := factory()
				require.NoError(t, New(fakeRunner{s: legacy}, nil, catalogfixture.Source()).ReconcileBinding(context.Background(), "acb-stage"))
				snapshot := factory()
				bs, _, err := snapshot.LoadBinding(context.Background(), "acb-stage")
				require.NoError(t, err)
				var spool [][]byte
				err = New(nil, nil, catalogfixture.Source()).StageBindingCoordinate(context.Background(), snapshot, bs, MemberCoord{ObjectType: obj.ObjectType, ObjectID: obj.ObjectID}, obj, true, nil, false, func(c BindingCommand) error { raw, e := json.Marshal(c); spool = append(spool, raw); return e }, nil)
				require.NoError(t, err)
				require.False(t, snapshot.wrote)
				require.Zero(t, snapshot.locks)
				require.Empty(t, snapshot.rowLocks)
				require.Zero(t, snapshot.currentMembersCalls)
				require.Zero(t, snapshot.matchAllCalls)
				applied := factory()
				for _, raw := range spool {
					var c BindingCommand
					require.NoError(t, json.Unmarshal(raw, &c))
					require.NoError(t, c.Apply(context.Background(), applied))
				}
				require.Equal(t, legacy.upserts, applied.upserts)
				require.Equal(t, allWrites(legacy), allWrites(applied))
				require.Equal(t, legacy.audits, applied.audits)
				if foreign {
					require.Empty(t, allWrites(applied))
					require.NotEmpty(t, applied.upserts)
					for _, member := range applied.upserts {
						require.Equal(t, domain.VerificationRejected, member.VerificationStatus)
					}
					require.Contains(t, applied.audits, obj.ObjectID)
				} else {
					require.True(t, hasTuple(allWrites(applied), "v_get", "compute_instance:instance"))
				}
			})
		}
	}
}
func TestBindingStageCommandCancellationUnknownAndSinkFailureAreClosed(t *testing.T) {
	f := &fakeStore{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, (BindingCommand{Kind: "members"}).Apply(ctx, f), context.Canceled)
	require.Error(t, (BindingCommand{Kind: "unknown"}).Apply(context.Background(), f))
	require.False(t, f.wrote)
	f.current = []domain.TargetMember{{BindingID: "acb-stage", RuleFP: "old", ObjectType: "compute.instance", ObjectID: "gone", VerificationStatus: domain.VerificationActive}}
	failure := errors.New("spool unavailable")
	err := New(nil, nil, catalogfixture.Source()).StageBindingCoordinate(context.Background(), f, BindingScope{BindingID: "acb-stage"}, MemberCoord{ObjectType: "compute.instance", ObjectID: "gone"}, domain.MirrorObject{}, false, nil, false, func(BindingCommand) error { return failure }, nil)
	require.ErrorIs(t, err, failure)
	require.False(t, f.wrote)
}

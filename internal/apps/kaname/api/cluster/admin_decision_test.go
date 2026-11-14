// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

type clusterDecisionCapture struct {
	begins, calls int
	intent        AdminDecisionIntent
}

func (r *clusterDecisionCapture) Begin(context.Context) (service.Tx, error) {
	r.begins++
	return nil, iamerr.ErrUnavailable
}
func (r *clusterDecisionCapture) RunAdminDecision(_ context.Context, in AdminDecisionIntent, _ func(context.Context, service.Tx) (domain.ClusterAdminGrant, error)) (domain.ClusterAdminGrant, error) {
	r.calls++
	r.intent = in
	return domain.ClusterAdminGrant{}, iamerr.ErrAborted
}
func TestClusterAdminBothMutationsDispatchTypedFinalRunnerWithoutFallback(t *testing.T) {
	for _, kind := range []string{"user", "service_account"} {
		t.Run(kind, func(t *testing.T) {
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: kind, ID: "actor"})
			runner := &clusterDecisionCapture{}
			grant := &GrantAdminUseCase{txb: runner}
			_, err := grant.doGrant(ctx, domain.GrantSubjectTypeServiceAccount, "target", "actor")
			require.ErrorIs(t, err, iamerr.ErrAborted)
			require.Equal(t, AdminActionGrant, runner.intent.Action)
			require.Equal(t, domain.SubjectType(kind), runner.intent.Actor.Type)
			require.Equal(t, domain.SubjectID("actor"), runner.intent.Actor.ID)
			require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "target"}, runner.intent.Target)
			revoke := &RevokeAdminUseCase{txb: runner}
			_, err = revoke.doRevoke(ctx, domain.GrantSubjectTypeUser, "target", "actor")
			require.ErrorIs(t, err, iamerr.ErrAborted)
			require.Equal(t, AdminActionRevoke, runner.intent.Action)
			require.Equal(t, domain.SubjectTypeUser, runner.intent.Target.Type)
			require.Equal(t, 2, runner.calls)
			require.Zero(t, runner.begins)
		})
	}
}
func TestClusterAdminAnonymousFinalIntentDoesNotReachRunner(t *testing.T) {
	runner := &clusterDecisionCapture{}
	_, err := (&GrantAdminUseCase{txb: runner}).doGrant(context.Background(), domain.GrantSubjectTypeUser, "target", "bootstrap")
	require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	_, err = (&RevokeAdminUseCase{txb: runner}).doRevoke(context.Background(), domain.GrantSubjectTypeUser, "target", "bootstrap")
	require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	require.Zero(t, runner.calls)
	require.Zero(t, runner.begins)
}

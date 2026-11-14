// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"
	"time"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

func TestClusterAdminFinalDecisionMissingParticipantAndFinalClock(t *testing.T) {
	var missing *ClusterAdminParticipant
	called := false
	_, err := missing.RunAdminDecision(context.Background(), clusterapp.AdminDecisionIntent{}, func(context.Context, service.Tx) (domain.ClusterAdminGrant, error) {
		called = true
		return domain.ClusterAdminGrant{}, nil
	})
	require.Error(t, err)
	require.False(t, called)
	at := time.Date(2026, 11, 14, 10, 0, 0, 0, time.UTC)
	tx := &clusterAdminParticipantTx{owner: &authorityWriteTx{fence: authorityFence{decisionAt: at}}}
	require.Nil(t, clusterAdminMutationAt(tx), "простое participant entry не выдаёт final timestamp")
	tx.finalDecision = true
	require.Equal(t, at, clusterAdminMutationAt(tx))
}
func TestClusterAdminFinalDecisionAcceptsActualPinnedDirectModel(t *testing.T) {
	p := &ClusterAdminParticipant{repo: &Repository{}, bundle: nativeBoundaryBundle(t)}
	require.NoError(t, p.validateDecisionModel())
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type nilRevokeFactory struct{}

func (*nilRevokeFactory) GrantDelegationRevokeWriter(context.Context, domain.GrantDelegationID) (kaname.GrantDelegationRevokeWriter, error) {
	panic("typed nil must be rejected")
}

func TestRevokeExplicitMissingParticipantNeverFallsBack(t *testing.T) {
	var typedNil *nilRevokeFactory
	for _, factory := range []kaname.GrantDelegationRevokeWriterFactory{nil, typedNil} {
		repo := &retryRepo{}
		uc := NewRevokeGrantDelegationUseCase(repo, nil).WithRevokeAuthorityWriter(factory)
		_, err := uc.doRevoke(context.Background(), retryID, domain.GrantDelegationActor{Type: "user", ID: retryUser}, retryUser)
		require.Equal(t, codes.Unavailable, status.Code(err))
		require.Zero(t, repo.attempts, "raw legacy writer не открывается при configured отказе")
	}
}

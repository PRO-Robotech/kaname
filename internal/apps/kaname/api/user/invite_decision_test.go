// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package user

import (
	"context"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

type missingInviteRunner struct{}

func (*missingInviteRunner) RunInviteDecision(context.Context, InviteDecisionIntent, func(context.Context, InviteMutationWriter, PreparedInvite) error) error {
	panic("nil runner must not run")
}
func TestInviteDecisionConfiguredNilDoesNotUseLegacyWriter(t *testing.T) {
	var typed *missingInviteRunner
	for _, runner := range []InviteDecisionRunner{nil, typed} {
		uc := NewInviteUserUseCase(nil, nil, nil).WithInviteDecisions(runner)
		// Selection отказывает до repo/authz/operation даже при пустом вводе.
		_, err := uc.Execute(context.Background(), InviteUserInput{})
		require.Equal(t, codes.Unavailable, status.Code(err))
	}
	require.NoError(t, NewInviteUserUseCase(nil, nil, nil).validateInviteDecisionSelection())
}

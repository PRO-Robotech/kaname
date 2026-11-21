// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package group

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAddMemberActivePolicyNeverFallsBackToParticipant(t *testing.T) {
	u := NewAddMemberUseCase(nil, nil).WithGroupAdditionAuthorityWriter(nil)
	called := false
	err := u.runAddition(context.Background(), domain.GroupMember{}, func(context.Context, Writer) error { called = true; return nil })
	require.Error(t, err)
	require.False(t, called)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestUserChildFinalAuthorizationBindsHumanTargetAndDecisionClock(t *testing.T) {
	r, owner, _, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	fullContractActivate(t, r)
	conn, err := r.admin.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	got := kanamepg.ProbeUserChildFinalAuthorization(t, ctx, conn.Conn(), r.bundle,
		kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/candidate"}, principal)
	require.NoError(t, got.AllowError)
	require.True(t, got.Allowed)
	require.False(t, got.OtherTargetAllowed)
	require.ErrorIs(t, got.OtherTargetError, domain.ErrUserChildRegistrationRefused)
	require.False(t, got.OtherPrincipalAllowed)
	require.ErrorIs(t, got.OtherPrincipalError, domain.ErrUserChildRegistrationRefused)
	require.False(t, got.StaleClockAllowed)
	require.ErrorIs(t, got.StaleClockError, kaname.ErrSourceUnconfirmed)
	require.False(t, got.ChildExists, "финальная проверка не исполняет регистрацию")
}

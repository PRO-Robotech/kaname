// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestIdentityLifecycleRejectsInvalidIntentBeforeTransaction(t *testing.T) {
	// Пустой pool нельзя вызвать: неверный intent обязан отвергаться до BeginTx.
	p := &HumanAdmissionParticipant{repo: &Repository{master: &pgxpool.Pool{}}}
	valid := domain.UserID(ids.NewID(domain.PrefixUser))
	for _, tc := range []struct {
		kind kaname.IdentityMutation
		id   domain.UserID
	}{
		{"unknown", valid}, {kaname.IdentityUpdate, ""}, {kaname.IdentityDelete, "usr-short"},
		{kaname.IdentityBlock, domain.UserID("acc" + strings.Repeat("a", 17))},
		{kaname.IdentityUnblock, domain.UserID("usr" + strings.Repeat("a", 16) + " ")},
	} {
		w, err := p.IdentityLifecycleWriter(context.Background(), tc.kind, tc.id)
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		require.Nil(t, w)
	}
	var absent *HumanAdmissionParticipant
	w, err := absent.IdentityLifecycleWriter(context.Background(), kaname.IdentityUpdate, valid)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	require.Nil(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w, err = p.IdentityLifecycleWriter(ctx, kaname.IdentityUpdate, valid)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, w)
}

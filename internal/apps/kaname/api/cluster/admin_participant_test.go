// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster

import (
	"context"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

type adminParticipantTestBeginner struct{ calls int }

func (b *adminParticipantTestBeginner) Begin(context.Context) (service.Tx, error) {
	b.calls++
	return nil, iamerr.ErrUnavailable
}

func TestAdminParticipantInjectionReplacesBothAndNilDenies(t *testing.T) {
	old, replacement := &adminParticipantTestBeginner{}, &adminParticipantTestBeginner{}
	h := NewHandler(nil, &GrantAdminUseCase{txb: old}, &RevokeAdminUseCase{txb: old}, nil)
	require.Same(t, h, h.WithAdminTxBeginner(replacement))
	for _, b := range []service.TxBeginner{h.grant.txb, h.revoke.txb} {
		_, err := b.Begin(context.Background())
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
	}
	require.Equal(t, 2, replacement.calls)
	require.Zero(t, old.calls)
	h.WithAdminTxBeginner(nil)
	for _, b := range []service.TxBeginner{h.grant.txb, h.revoke.txb} {
		tx, err := b.Begin(context.Background())
		require.Nil(t, tx)
		require.ErrorIs(t, err, iamerr.ErrUnavailable)
	}
	require.Equal(t, 2, replacement.calls)
	require.Zero(t, old.calls)
}

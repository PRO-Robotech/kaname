// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type resourceBodyEntryRow struct{}

func (resourceBodyEntryRow) Scan(dest ...any) error { *dest[0].(*bool) = true; return nil }

type resourceBodyEntryTx struct {
	*resourceLifecycleTx
	admissions int
}

func (t *resourceBodyEntryTx) QueryRow(_ context.Context, query string, _ ...any) pgx.Row {
	if query != `SELECT kaname.authority_resource_assert_body_v2($1::jsonb)` {
		panic("unexpected body query")
	}
	t.admissions++
	return resourceBodyEntryRow{}
}
func TestResourceWithdrawalUsesAlreadyAdmittedOuterBodyExactlyOnce(t *testing.T) {
	lifetime, owner, raw := resourceLifetimeFixture(t)
	entry := &resourceBodyEntryTx{resourceLifecycleTx: raw}
	owner.writeTx.tx = entry
	source := &resourceSourceCapture{lifetime: lifetime, sealed: true}
	preparation := &resourceRegistrationPreparation{input: kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister}, parents: &resourceParentCapture{source: source}}
	withdrawal := &resourceWithdrawalBody{preparation: preparation}
	tx := &resourceDecisionTx{Tx: entry, lifetime: lifetime, owner: owner}
	require.ErrorIs(t, withdrawal.apply(context.Background(), tx), kaname.ErrSourceUnconfirmed, "вложенный шаг до outer admission запрещён")
	require.Zero(t, entry.admissions)
	require.NoError(t, preparation.assertBody(context.Background(), tx))
	require.Equal(t, 1, entry.admissions)
	require.NoError(t, withdrawal.apply(context.Background(), tx), "вложенный pure-empty план не пытается второй final→body переход")
	require.Equal(t, 1, entry.admissions)
	require.ErrorIs(t, preparation.assertBody(context.Background(), tx), kaname.ErrSourceUnconfirmed)
	other := *preparation
	withdrawal.preparation = &other
	require.ErrorIs(t, withdrawal.apply(context.Background(), tx), kaname.ErrSourceUnconfirmed, "одинаковые значения другой preparation не являются тем же body")
	withdrawal.preparation = preparation
	lifetime.close()
	require.ErrorIs(t, withdrawal.apply(context.Background(), tx), kaname.ErrSourceUnconfirmed)
	require.Equal(t, 1, entry.admissions)
}

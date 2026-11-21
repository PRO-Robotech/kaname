// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"testing"
	"time"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestSpecialMemberInputBudgetMatchesFrozenCapturedCoordinates(t *testing.T) {
	r := capturedGroupRequest(t, writerProtocolRig(t))
	stageSeedGroups(t, r, r.a, 2, "blue")
	r = capturedGroupRequest(t, r)
	binding := stageBinding(t, r, r.a, true)
	r = capturedGroupRequest(t, r)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, tx.Rollback(cleanup))
	}()
	kanamepg.SpecialMemberBudgetCapturedForTest(t, r.ctx, tx, r.repo, r.bundle, binding)
}

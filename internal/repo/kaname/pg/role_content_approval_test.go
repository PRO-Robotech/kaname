// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type roleContentApprovalTx struct {
	pgx.Tx
	calls   int
	query   string
	failure error
}

func (tx *roleContentApprovalTx) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	tx.calls++
	tx.query = query
	if len(args) != 0 {
		panic("content receipt must not accept caller authority")
	}
	return pgconn.NewCommandTag("SELECT 1"), tx.failure
}

// Здесь проверяется только Go порядок/стоимость. Owner proof проверяет PG fixture.
func roleContentApprovalFixture() (*preparedRoleWriteTx, *roleContentApprovalTx, *relverdict.AdministrativeReadBudget) {
	tx := &roleContentApprovalTx{}
	budget := &relverdict.AdministrativeReadBudget{}
	boundary := &nativeReadBoundary{}
	return &preparedRoleWriteTx{
		semanticAuthorityWriteTx: &semanticAuthorityWriteTx{
			authorityWriteTx: &authorityWriteTx{
				writeTx:        &writeTx{readTx: readTx{tx: tx}},
				fence:          authorityFence{decisionAt: time.Unix(1000, 0)},
				producerBudget: budget,
				nativeRead:     &protectedNativeRead{boundary: boundary, budget: budget},
			},
			bundle: &granteffect.Bundle{},
		},
		conn: &pgxpool.Conn{},
		stage: &roleMutationStage{
			request:         kaname.RoleMutationRequest{Create: true, Rules: true},
			accessLabelMode: roleAccessLabelApply,
			plan:            &policyPlan{request: policyWriteRequest{kind: kaname.AuthorityRole}, native: boundary, nativeBudget: budget},
		},
	}, tx, budget
}

func TestRoleContentApprovalOwnerModeIsMandatory(t *testing.T) {
	for _, raw := range []string{`{}`, `{"access_label_mode":null}`, `{"access_label_mode":""}`, `{"access_label_mode":"metadata"}`} {
		var receipt struct {
			Mode roleAccessLabelMode `json:"access_label_mode"`
		}
		require.NoError(t, json.Unmarshal([]byte(raw), &receipt))
		require.ErrorIs(t, receipt.Mode.requireSupported(), kaname.ErrSourceUnconfirmed)
	}
	require.NoError(t, roleAccessLabelOrdinary.requireSupported())
	require.NoError(t, roleAccessLabelApply.requireSupported())
	require.NoError(t, roleAccessLabelRevoke.requireSupported())
}

func TestRoleContentApprovalOrdinaryDoesNotReadSQL(t *testing.T) {
	w, tx, budget := roleContentApprovalFixture()
	w.stage.accessLabelMode = roleAccessLabelOrdinary
	rows, reads := budget.RemainingRows(), budget.RemainingReads()
	require.NoError(t, w.RecordRoleContentApproval(context.Background()))
	require.Zero(t, tx.calls)
	require.Equal(t, rows, budget.RemainingRows())
	require.Equal(t, reads, budget.RemainingReads())
}

func TestRoleContentApprovalApplyChargesOnceAndCannotRepeat(t *testing.T) {
	for _, failure := range []error{nil, errors.New("backend rejected custody")} {
		w, tx, budget := roleContentApprovalFixture()
		tx.failure = failure
		rows, reads := budget.RemainingRows(), budget.RemainingReads()
		require.ErrorIs(t, w.RecordRoleContentApproval(context.Background()), failure)
		require.Equal(t, 1, tx.calls)
		require.Equal(t, roleContentApprovedSQL, tx.query)
		require.Equal(t, rows-8, budget.RemainingRows())
		require.Equal(t, reads-4, budget.RemainingReads())
		require.ErrorIs(t, w.RecordRoleContentApproval(context.Background()), kaname.ErrSourceUnconfirmed)
		require.Equal(t, 1, tx.calls)
	}
}

func TestRoleContentApprovalRefusesBeforeSQL(t *testing.T) {
	for name, alter := range map[string]func(*preparedRoleWriteTx){
		"revoke on create":    func(w *preparedRoleWriteTx) { w.stage.accessLabelMode = roleAccessLabelRevoke },
		"absent mode":         func(w *preparedRoleWriteTx) { w.stage.accessLabelMode = "" },
		"own write":           func(w *preparedRoleWriteTx) { w.roleWriteStarted = true },
		"closed":              func(w *preparedRoleWriteTx) { w.closed = true },
		"missing final clock": func(w *preparedRoleWriteTx) { w.fence.decisionAt = time.Time{} },
		"foreign budget":      func(w *preparedRoleWriteTx) { w.producerBudget = &relverdict.AdministrativeReadBudget{} },
	} {
		t.Run(name, func(t *testing.T) {
			w, tx, _ := roleContentApprovalFixture()
			alter(w)
			require.ErrorIs(t, w.RecordRoleContentApproval(context.Background()), kaname.ErrSourceUnconfirmed)
			require.Zero(t, tx.calls)
		})
	}
	for _, remaining := range [][2]int{{7, 4}, {8, 3}} {
		w, tx, budget := roleContentApprovalFixture()
		require.NoError(t, budget.Charge(budget.RemainingRows()-remaining[0], budget.RemainingReads()-remaining[1]))
		require.ErrorIs(t, w.RecordRoleContentApproval(context.Background()), kaname.ErrSourceReadLimit)
		require.Zero(t, tx.calls)
	}
	w, tx, _ := roleContentApprovalFixture()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	require.ErrorIs(t, w.RecordRoleContentApproval(ctx), context.Canceled)
	require.Zero(t, tx.calls)
}

func TestRoleContentApprovalRevokeUsesFullReceipt(t *testing.T) {
	w, tx, budget := roleContentApprovalFixture()
	w.stage.accessLabelMode = roleAccessLabelRevoke
	w.stage.request.Create = false
	w.stage.request.Update = true
	rows, reads := budget.RemainingRows(), budget.RemainingReads()
	require.NoError(t, w.RecordRoleContentApproval(context.Background()))
	require.True(t, w.contentApprovalRecorded)
	require.Equal(t, 1, tx.calls)
	require.Equal(t, rows-8, budget.RemainingRows())
	require.Equal(t, reads-4, budget.RemainingReads())
}

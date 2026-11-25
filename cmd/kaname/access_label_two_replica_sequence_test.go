// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

type nativeAccessLabelDecision struct {
	VGet             bool `json:"v_get"`
	VGetStatus       int  `json:"v_get_status"`
	CatalogGet       bool `json:"catalog_get"`
	CatalogGetStatus int  `json:"catalog_get_status"`
	GetStatus        int  `json:"get_status"`
}
type nativeAccessLabelBaseline struct {
	nativeAccessLabelDecision
	ActiveMembers int `json:"active_members"`
	LedgerHolders int `json:"ledger_holders"`
}
type nativeAccessLabelRetained struct {
	nativeAccessLabelDecision
	LosingHolderPresent  bool `json:"losing_holder_present"`
	KeepingHolderPresent bool `json:"keeping_holder_present"`
}
type nativeAccessLabelPending struct {
	nativeAccessLabelDecision
	PhysicalFactPresent bool `json:"physical_fact_present"`
	DirtyFactPresent    bool `json:"dirty_fact_present"`
	FactFresh           bool `json:"fact_fresh"`
}
type nativeAccessLabelSequenceObservation struct {
	Baseline nativeAccessLabelBaseline
	Retained nativeAccessLabelRetained
	Pending  nativeAccessLabelPending
}

// Сценарий начинается с двух работающих процессов, отдельного читателя и двух
// материализованных привязок к аккаунту с {team:before,keep:yes}.
// assertSameProcesses сверяет исходные PID, конфигурации и владельцев портов.
func runAccessLabelTwoReplicaSequence(t *testing.T, ctx context.Context,
	writerA, readerB *installruntime.Wire, ownerObserver *pgxpool.Pool,
	writerBearer, readerBearer, rootID, readerID, losingBinding, keepingBinding string,
	assertSameProcesses func()) nativeAccessLabelSequenceObservation {
	var observations nativeAccessLabelSequenceObservation
	t.Helper()
	require.NotNil(t, assertSameProcesses)
	subject := "user:" + readerID
	path := "/iam/v1/accounts/" + url.PathEscape(rootID)
	check := func(stage string, pending bool) nativeAccessLabelDecision {
		var observed nativeAccessLabelDecision
		t.Helper()
		assertSameProcesses()
		for _, explicit := range []bool{true, false} {
			request := map[string]any{
				"subject": subject, "resource": map[string]string{"type": "account", "id": rootID},
				"action": "iam.account.get",
			}
			if explicit {
				request["requiredRelation"] = "v_get"
			}
			var result struct {
				Allowed bool `json:"allowed"`
				Code    int  `json:"code"`
			}
			code, err := readerB.JSON(ctx, http.MethodPost, "/iam/v1/authorize:check", readerBearer, request, &result)
			require.NoError(t, err)
			if pending && code == http.StatusServiceUnavailable {
				require.Equal(t, int(codes.Unavailable), result.Code, "%s: Authorize.Check, явное отношение=%t", stage, explicit)
				require.False(t, result.Allowed)
			} else {
				require.Equal(t, http.StatusOK, code, "%s: Authorize.Check, явное отношение=%t", stage, explicit)
				require.Equal(t, !pending, result.Allowed, "%s: Authorize.Check, явное отношение=%t", stage, explicit)
			}
			if explicit {
				observed.VGet, observed.VGetStatus = result.Allowed, code
			} else {
				observed.CatalogGet, observed.CatalogGetStatus = result.Allowed, code
			}
		}
		var result struct {
			Code int `json:"code"`
		}
		code, err := readerB.JSON(ctx, http.MethodGet, path, readerBearer, nil, &result)
		require.NoError(t, err)
		switch {
		case !pending:
			require.Equal(t, http.StatusOK, code, "%s: Account.Get", stage)
		case code == http.StatusServiceUnavailable:
			require.Equal(t, int(codes.Unavailable), result.Code, "%s: Account.Get", stage)
		default:
			require.Equal(t, http.StatusForbidden, code, "%s: Account.Get", stage)
		}
		observed.GetStatus = code
		return observed
	}
	update := func(labels map[string]string) {
		t.Helper()
		var operation installruntime.Operation
		code, err := writerA.JSON(ctx, http.MethodPatch, path, writerBearer, map[string]any{
			"accountId": rootID, "accessLabels": labels, "updateMask": "accessLabels",
		}, &operation)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		operation, err = writerA.AwaitOperation(ctx, writerBearer, operation)
		require.NoError(t, err)
		require.True(t, operation.Done)
		require.Nil(t, operation.Error)
		assertSameProcesses()
	}
	observations.Baseline.nativeAccessLabelDecision = check("baseline", false)
	update(map[string]string{"team": "after", "keep": "yes"})
	check("retained-after-update", false)
	// Дожидаемся первого пересчёта, чтобы его рабочий процесс уже освободил
	// блокировки источников, когда начнём удерживать строку старого факта.
	require.Eventually(t, func() bool {
		var losingPresent, keepingPresent bool
		err := ownerObserver.QueryRow(ctx, `SELECT
   EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1
    AND member_object_type='iam.account' AND member_object_id=$3 AND object='account:'||$3
    AND relation='v_get' AND fga_user=$4)
   , EXISTS(SELECT 1 FROM kaname.access_binding_emitted_tuples WHERE binding_id=$2
    AND member_object_type='iam.account' AND member_object_id=$3 AND object='account:'||$3
    AND relation='v_get' AND fga_user=$4)`, losingBinding, keepingBinding, rootID, subject).Scan(&losingPresent, &keepingPresent)
		observations.Retained.LosingHolderPresent = losingPresent
		observations.Retained.KeepingHolderPresent = keepingPresent
		return err == nil && !losingPresent && keepingPresent
	}, 45*time.Second, 50*time.Millisecond)
	observations.Retained.nativeAccessLabelDecision = check("retained", false)

	// KEY SHARE совместим с SHARE при повторной сверке метаданных и задерживает
	// удаление факта. Второй процесс читает своим обычным ограниченным LOGIN.
	barrier, err := ownerObserver.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = barrier.Rollback(cleanup)
	}()
	_, err = barrier.Exec(ctx, `SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='30s'`)
	require.NoError(t, err)
	var held bool
	require.NoError(t, barrier.QueryRow(ctx, `SELECT true FROM kaname.relation_fact
  WHERE object_type='account' AND object_id=$1 AND relation='v_get' AND subject=$2 FOR KEY SHARE`, rootID, subject).Scan(&held))
	require.True(t, held)
	update(map[string]string{"team": "after", "keep": "no"})
	var physical, dirty, fresh bool
	require.NoError(t, barrier.QueryRow(ctx, `SELECT
  EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='v_get' AND subject=$2),
  EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact d
   JOIN kaname.authority_access_label_dirty_root r USING(root_type,root_id,generation)
   WHERE d.root_type='iam.account' AND d.root_id=$1 AND d.object_type='account' AND d.object_id=$1 AND d.relation='v_get' AND d.subject=$2
    AND r.new_labels='{"team":"after","keep":"no"}'::jsonb),
  kaname.authority_access_label_fact_fresh_v1('account',$1,'v_get',$2)`, rootID, subject).Scan(&physical, &dirty, &fresh))
	require.True(t, physical, "the stale physical fact is deliberately still present")
	require.True(t, dirty, "the exact committed metadata generation is pending")
	require.False(t, fresh)
	// Только при подтверждённой незавершённой проекции допустимо Unavailable.
	observations.Pending.nativeAccessLabelDecision = check("pending", true)
	observations.Pending.PhysicalFactPresent, observations.Pending.DirtyFactPresent, observations.Pending.FactFresh = physical, dirty, fresh
	require.NoError(t, barrier.Rollback(ctx))
	assertSameProcesses()
	return observations
}

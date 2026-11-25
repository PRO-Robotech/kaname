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
	Viewer           bool `json:"viewer"`
	ViewerStatus     int  `json:"viewer_status"`
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
	FactRelation        string `json:"fact_relation"`
	PhysicalFactPresent bool   `json:"physical_fact_present"`
	DirtyFactPresent    bool   `json:"dirty_fact_present"`
	FactFresh           bool   `json:"fact_fresh"`
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
	assertSameProcesses func(), recordFailure func(string, string)) nativeAccessLabelSequenceObservation {
	var observations nativeAccessLabelSequenceObservation
	t.Helper()
	require.NotNil(t, assertSameProcesses)
	subject := "user:" + readerID
	path := "/iam/v1/accounts/" + url.PathEscape(rootID)
	const factRelation = "viewer"
	check := func(callCtx context.Context, stage string, pending bool) nativeAccessLabelDecision {
		var observed nativeAccessLabelDecision
		t.Helper()
		assertSameProcesses()
		for _, relation := range []string{"v_get", "", factRelation} {
			request := map[string]any{
				"subject": subject, "resource": map[string]string{"type": "account", "id": rootID},
				"action": "iam.account.get",
			}
			if relation != "" {
				request["requiredRelation"] = relation
			}
			var result struct {
				Allowed bool `json:"allowed"`
				Code    int  `json:"code"`
			}
			code, err := readerB.JSON(callCtx, http.MethodPost, "/iam/v1/authorize:check", readerBearer, request, &result)
			require.NoError(t, err)
			if pending && code == http.StatusServiceUnavailable {
				require.Equal(t, int(codes.Unavailable), result.Code, "%s: Authorize.Check, requiredRelation=%q", stage, relation)
				require.False(t, result.Allowed)
			} else {
				require.Equal(t, http.StatusOK, code, "%s: Authorize.Check, requiredRelation=%q", stage, relation)
				require.Equal(t, !pending, result.Allowed, "%s: Authorize.Check, requiredRelation=%q", stage, relation)
			}
			switch relation {
			case "v_get":
				observed.VGet, observed.VGetStatus = result.Allowed, code
			case "":
				observed.CatalogGet, observed.CatalogGetStatus = result.Allowed, code
			case factRelation:
				observed.Viewer, observed.ViewerStatus = result.Allowed, code
			}
		}
		var result struct {
			Code int `json:"code"`
		}
		code, err := readerB.JSON(callCtx, http.MethodGet, path, readerBearer, nil, &result)
		require.NoError(t, err)
		switch {
		case !pending:
			require.Equal(t, http.StatusOK, code, "%s: Account.Get", stage)
		case code == http.StatusServiceUnavailable:
			require.Equal(t, int(codes.Unavailable), result.Code, "%s: Account.Get", stage)
		default:
			require.Equal(t, http.StatusNotFound, code, "%s: Account.Get", stage)
			require.Equal(t, int(codes.NotFound), result.Code, "%s: Account.Get", stage)
		}
		observed.GetStatus = code
		return observed
	}
	startUpdate := func(callCtx context.Context, labels map[string]string) installruntime.Operation {
		t.Helper()
		var operation installruntime.Operation
		code, err := writerA.JSON(callCtx, http.MethodPatch, path, writerBearer, map[string]any{
			"accountId": rootID, "accessLabels": labels, "updateMask": "accessLabels",
		}, &operation)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		require.NotEmpty(t, operation.ID)
		return operation
	}
	finishUpdate := func(callCtx context.Context, operation installruntime.Operation) {
		t.Helper()
		operation, err := writerA.AwaitOperation(callCtx, writerBearer, operation)
		require.NoError(t, err)
		require.True(t, operation.Done)
		require.Nil(t, operation.Error)
		assertSameProcesses()
	}
	observations.Baseline.nativeAccessLabelDecision = check(ctx, "baseline", false)
	finishUpdate(ctx, startUpdate(ctx, map[string]string{"team": "after", "keep": "yes"}))
	check(ctx, "retained-after-update", false)
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
	observations.Retained.nativeAccessLabelDecision = check(ctx, "retained", false)

	pendingCtx, cancelPending := context.WithTimeout(ctx, 60*time.Second)
	defer cancelPending()
	rollback := func(tx pgx.Tx) {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}
	var pendingOperation installruntime.Operation
	defer func() {
		if t.Failed() && pendingOperation.ID != "" {
			recordFailure("pending", pendingOperation.ID)
		}
	}()

	// Сначала пропускаем настоящий Update через захват общей блокировки
	// производителя. Блокировка таблицы задерживает только его физическую
	// запись. Пока Update ждёт её, рабочий пересчёт не может занять очередь
	// раньше производителя и удержать общую блокировку.
	staging, err := ownerObserver.BeginTx(pendingCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer rollback(staging)
	_, err = staging.Exec(pendingCtx, `SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='0';
		LOCK TABLE ONLY kaname.accounts IN SHARE MODE`)
	require.NoError(t, err)
	var stagingPID int32
	require.NoError(t, staging.QueryRow(pendingCtx, `SELECT pg_backend_pid()`).Scan(&stagingPID))
	pendingOperation = startUpdate(pendingCtx, map[string]string{"team": "after", "keep": "no"})
	require.False(t, pendingOperation.Done)
	require.Eventually(t, func() bool {
		var waiting bool
		err := ownerObserver.QueryRow(pendingCtx, `SELECT count(*)=1
			FROM pg_catalog.pg_locks AS account_lock
			JOIN pg_catalog.pg_locks AS producer_lock USING(pid,database)
			JOIN pg_catalog.pg_stat_activity AS session ON session.pid=account_lock.pid
			WHERE account_lock.relation='kaname.accounts'::regclass
			AND account_lock.locktype='relation' AND account_lock.mode='RowExclusiveLock' AND NOT account_lock.granted
			AND producer_lock.relation='kaname.authority_producer_population_latch'::regclass
			AND producer_lock.locktype='relation' AND producer_lock.mode='ShareLock' AND producer_lock.granted
			AND $1=ANY(pg_catalog.pg_blocking_pids(account_lock.pid))
			AND session.application_name='writer-a' AND session.state='active' AND session.wait_event_type='Lock'
			AND session.query='SELECT kaname.authority_metadata_access_label_retention_inputs_v1($1::jsonb,$2,$3,$4,$5)'
			AND EXISTS(SELECT FROM ONLY kaname.operations WHERE id=$2 AND NOT done)`,
			stagingPID, pendingOperation.ID).Scan(&waiting)
		return err == nil && waiting
	}, 15*time.Second, 40*time.Millisecond, "Update должен ждать физической записи после захвата блокировки производителя")

	// Удерживаем поколение и материальный viewer только после доказанной
	// остановки производителя. Два захвата нужны для разных путей пересчёта.
	barrier, err := ownerObserver.BeginTx(pendingCtx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer rollback(barrier)
	// Время жизни барьера задаёт pendingCtx. Отдельный таймер бездействия
	// PostgreSQL мог снять защитную блокировку посреди штатной операции.
	_, err = barrier.Exec(pendingCtx, `SET LOCAL lock_timeout='2s'; SET LOCAL idle_in_transaction_session_timeout='0'`)
	require.NoError(t, err)
	var generationLocked bool
	require.NoError(t, barrier.QueryRow(pendingCtx, `SELECT pg_try_advisory_xact_lock(
		1262569306,hashtext(jsonb_build_array('iam.account'::text,$1::text)::text COLLATE "C"))`,
		rootID).Scan(&generationLocked))
	require.True(t, generationLocked, "пересчёт не должен получить поколение раньше удержанного производителя")
	var factXmin, factCTID string
	var initiallyFresh, retainedHolder bool
	require.NoError(t, barrier.QueryRow(pendingCtx, `SELECT f.xmin::text,f.ctid::text,
  kaname.authority_access_label_fact_fresh_v1(f.object_type,f.object_id,f.relation,f.subject),
  EXISTS (SELECT FROM ONLY kaname.access_binding_emitted_tuples et
    WHERE et.binding_id=$4 AND et.member_object_type='iam.account' AND et.member_object_id=f.object_id
      AND et.object='account:'||f.object_id AND et.relation=f.relation AND et.fga_user=f.subject)
 FROM ONLY kaname.relation_fact f
 WHERE f.object_type='account' AND f.object_id=$1 AND f.relation=$3 AND f.subject=$2
 FOR KEY SHARE OF f`, rootID, subject, factRelation, keepingBinding).Scan(&factXmin, &factCTID, &initiallyFresh, &retainedHolder),
		"должен существовать физический факт viewer")
	require.True(t, initiallyFresh)
	require.True(t, retainedHolder, "оставшаяся выдача должна держать этот факт viewer")
	require.NoError(t, staging.Rollback(pendingCtx))
	finishUpdate(pendingCtx, pendingOperation)
	var physical, dirty, fresh bool
	require.NoError(t, barrier.QueryRow(pendingCtx, `SELECT
  EXISTS(SELECT FROM ONLY kaname.relation_fact f WHERE f.object_type='account' AND f.object_id=$1
   AND f.relation=$3 AND f.subject=$2 AND f.xmin::text=$4 AND f.ctid::text=$5),
  EXISTS(SELECT 1 FROM kaname.authority_access_label_dirty_fact d
   JOIN kaname.authority_access_label_dirty_root r USING(root_type,root_id,generation)
   WHERE d.root_type='iam.account' AND d.root_id=$1 AND d.object_type='account' AND d.object_id=$1 AND d.relation=$3 AND d.subject=$2
    AND r.new_labels='{"team":"after","keep":"no"}'::jsonb),
  kaname.authority_access_label_fact_fresh_v1('account',$1,$3,$2)`, rootID, subject, factRelation, factXmin, factCTID).Scan(&physical, &dirty, &fresh))
	require.True(t, physical, "the stale physical fact is deliberately still present")
	require.True(t, dirty, "the exact committed metadata generation is pending")
	require.False(t, fresh)
	// Только при подтверждённой незавершённой проекции допустимо Unavailable.
	observations.Pending.nativeAccessLabelDecision = check(pendingCtx, "pending", true)
	observations.Pending.FactRelation = factRelation
	observations.Pending.PhysicalFactPresent, observations.Pending.DirtyFactPresent, observations.Pending.FactFresh = physical, dirty, fresh
	require.NoError(t, barrier.Rollback(pendingCtx))
	assertSameProcesses()
	return observations
}

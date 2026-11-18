// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func mirrorLocalityFixture(t *testing.T) (protocolRig, domain.AccessBindingID, string, string) {
	t.Helper()
	r := writerProtocolRig(t)
	r.ctx = context.WithoutCancel(r.ctx)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	setup := r
	setup.ctx = ctx
	uid := seedMemberUser(t, ctx, r.admin, r.a, "mirror-locality-"+ids.NewID("usr"))
	_, err := r.admin.Exec(ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, uid)
	require.NoError(t, err)
	binding := groupLifecycleBinding(t, setup, r.a, uid, "mirror_"+ids.NewID("rol"), domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}})
	id := ids.NewID("net")
	// Native grant ищет область в канонических рёбрах, а не в parent_account_id зеркала.
	// Команда зеркала валидирует и записывает цепь project → account до FULL activation.
	// Здесь нет relation outbox: исходный oracle требует пустой журнал команд привязки.
	project := seedProject(t, ctx, lifecycleOwner(setup), domain.AccountID(r.a), "mirror-locality")
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer mirrorLocalityRollback(t, tx)
	applied, _, err := kanamepg.NewResourceMirrorEmitter().UpsertTx(ctx, tx, service.ResourceMirrorRow{
		ObjectType: "vpc.network", ObjectID: id,
		ParentProjectID: string(project.ID), ParentAccountID: r.a,
		ParentChain: []string{"project:" + string(project.ID), "account:" + r.a},
	})
	require.NoError(t, err)
	require.True(t, applied)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id) VALUES('vpc_network',$1,$2,$3)`, id, string(project.ID), r.a)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return r, binding, id, uid
}

func mirrorLocalityRollback(t *testing.T, tx pgx.Tx) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := tx.Rollback(ctx)
	if err != pgx.ErrTxClosed {
		require.NoError(t, err)
	}
}
func mirrorLocalityError(t *testing.T, err error, code string) {
	t.Helper()
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, code, pgerr.Code)
}

func TestBindingMirrorLocalityFullCurrentRetainedAndDeleted(t *testing.T) {
	for _, shape := range []string{"same", "retained_foreign", "current_foreign", "deleted_retained"} {
		t.Run(shape, func(t *testing.T) {
			r, binding, id, uid := mirrorLocalityFixture(t)
			ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
			defer cancel()
			setup := r
			setup.ctx = ctx
			engine := bindingStageEngine(t, setup, nil)
			// OLD claims настоящие: создаются исходным runtime reconciler до move/delete.
			require.NoError(t, engine.ReconcileBinding(ctx, binding))
			require.True(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id))
			var err error
			switch shape {
			case "retained_foreign":
				_, err = r.runtime.Exec(ctx, `INSERT INTO kaname.resource_registration_scope VALUES('vpc_network',$1,'',$2)`, id, r.b)
			case "current_foreign":
				_, err = r.runtime.Exec(ctx, `UPDATE kaname.resource_mirror SET parent_account_id=$2 WHERE object_type='vpc.network' AND object_id=$1`, id, r.b)
			case "deleted_retained":
				_, err = r.runtime.Exec(ctx, `DELETE FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1`, id)
			}
			require.NoError(t, err)
			global := shape == "retained_foreign" || shape == "current_foreign"
			// Дифференциал actual RR источников проводится с owner LOGIN только
			// ради прямого вызова private pure helper, без изменения ACL.
			tx, err := r.admin.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
			require.NoError(t, err)
			func() {
				defer mirrorLocalityRollback(t, tx)
				kanamepg.BindingMirrorLocalityDifferentialForTest(t, ctx, tx, r.bundle, binding, id, !global)
			}()
			r.repo, _ = fullContractActivate(t, setup)
			want := []string{r.a}
			if global {
				want = nil
			}
			kanamepg.BindingMirrorStageForTest(t, ctx, r.repo, r.bundle, binding, global, want, nil, false)
			engine = bindingStageEngine(t, r, nil)
			require.NoError(t, engine.ReconcileBinding(ctx, binding))
			if shape == "deleted_retained" || shape == "current_foreign" {
				require.False(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id))
			} else {
				require.True(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id))
				allow, e := (delegationNativeDoor{r}).Check(ctx, "user:"+uid, "v_get", "vpc_network:"+id)
				require.NoError(t, e)
				if !allow {
					mirrorLogPublicVGet(t, ctx, r, binding, uid, id, allow)
				}
				require.True(t, allow)
			}
		})
	}
}

func TestBindingMirrorLocalityUnsignedPhantomInvalidatesRoot(t *testing.T) {
	for _, change := range []string{"insert_foreign", "delete_last", "move", "aba", "truncate"} {
		t.Run(change, func(t *testing.T) {
			r, binding, id, _ := mirrorLocalityFixture(t)
			ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
			defer cancel()
			kanamepg.BindingMirrorStageForTest(t, ctx, r.repo, r.bundle, binding, false, []string{r.a}, func() {
				var err error
				switch change {
				case "insert_foreign":
					_, err = r.runtime.Exec(ctx, `INSERT INTO kaname.resource_registration_scope VALUES('vpc_network',$1,'',$2)`, id, r.b)
				case "delete_last":
					_, err = r.runtime.Exec(ctx, `DELETE FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1`, id)
				case "move", "aba":
					_, err = r.runtime.Exec(ctx, `UPDATE kaname.resource_registration_scope SET account_id=$2 WHERE object_type='vpc_network' AND object_id=$1`, id, r.b)
					if change == "aba" {
						require.NoError(t, err)
						_, err = r.runtime.Exec(ctx, `UPDATE kaname.resource_registration_scope SET account_id=$2 WHERE object_type='vpc_network' AND object_id=$1`, id, r.a)
					}
				case "truncate":
					_, err = r.admin.Exec(ctx, `TRUNCATE kaname.resource_registration_scope`)
				}
				require.NoError(t, err)
			}, true)
		})
	}
}

func TestBindingMirrorLocalityUnsignedRRBeforeCompatibilityBarrier(t *testing.T) {
	r, binding, id, _ := mirrorLocalityFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	setup := r
	setup.ctx = ctx
	require.NoError(t, bindingStageEngine(t, setup, nil).ReconcileBinding(ctx, binding))
	_, err := r.runtime.Exec(ctx, `DELETE FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1`, id)
	require.NoError(t, err)
	_, err = r.runtime.Exec(ctx, `DELETE FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1`, id)
	require.NoError(t, err)
	old, err := r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.NoError(t, err)
	defer mirrorLocalityRollback(t, old)
	var count int
	require.NoError(t, old.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1`, id).Scan(&count))
	require.Zero(t, count, "RR установлен до нового owner и compatibility barrier")
	writer, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	defer mirrorLocalityRollback(t, writer)
	_, err = writer.Exec(ctx, `INSERT INTO kaname.resource_registration_scope VALUES('vpc_network',$1,'',$2)`, id, r.a)
	require.NoError(t, err)
	// Только existing public NULL stamp получает настоящий unsigned barrier.
	// Private attestation runtime не вызывается и прав ему не выдаётся.
	pid := old.Conn().PgConn().PID()
	type stampResult struct {
		stamp *time.Time
		err   error
	}
	done := make(chan stampResult, 1)
	joined := make(chan struct{})
	go func() {
		defer close(joined)
		var result stampResult
		result.err = old.QueryRow(ctx, `SELECT kaname.authority_binding_insert_stamp_v3($1)`, ids.NewID("acb")).Scan(&result.stamp)
		done <- result
	}()
	defer func() {
		cancel()
		select {
		case <-joined:
		case <-time.After(5 * time.Second):
			t.Error("unsigned barrier worker did not stop")
		}
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting bool
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock' AND wait_event='advisory')`, pid).Scan(&waiting))
		if waiting {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	require.NoError(t, writer.Commit(ctx))
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Nil(t, result.stamp)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	// Stage наблюдает нового retained A, пока старый RR уже получил barrier,
	// но ещё не выполнил INSERT B. Root UPDATE обязан сериализовать stale RR.
	kanamepg.BindingMirrorStageForTest(t, ctx, r.repo, r.bundle, binding, false, []string{r.a}, func() {
		_, err := old.Exec(ctx, `INSERT INTO kaname.resource_registration_scope VALUES('vpc_network',$1,'',$2)`, id, r.b)
		mirrorLocalityError(t, err, "40001")
		mirrorLocalityRollback(t, old)
	}, false)
	var foreign int
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_registration_scope WHERE object_id=$1 AND account_id=$2`, id, r.b).Scan(&foreign))
	require.Zero(t, foreign)
}

func TestBindingMirrorLocalitySignedNonManifestRetainedDenied(t *testing.T) {
	r, _, id, _ := mirrorLocalityFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	tx, err := r.runtime.Begin(ctx)
	require.NoError(t, err)
	intent := r.intent(r.a)
	intent.Plan.Mode = kaname.AuthorityFenceGlobal
	intent.Plan.Accounts = nil
	intent.Owners = nil
	_, err = protocolEnter(ctx, tx, intent, "participant")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.resource_registration_scope VALUES('vpc_network',$1,'',$2)`, id, r.b)
	mirrorLocalityRollback(t, tx)
	mirrorLocalityError(t, err, "42501")
	var pgerr *pgconn.PgError
	require.ErrorAs(t, err, &pgerr)
	require.Equal(t, "signed retained write requires prepared resource manifest", pgerr.Message)
	var count int
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_registration_scope WHERE object_id=$1 AND account_id=$2`, id, r.b).Scan(&count))
	require.Zero(t, count)
}

func TestBindingMirrorLocalityFullRegistrationInvalidatesPreparedFootprint(t *testing.T) {
	trace := &fullMeasurementTrace{}
	f := fullMeasurementResourceFixture(t, trace)
	ctx, cancel := fullMeasurementContext(f.ctx, "mirror_initial")
	defer cancel()
	id := ids.NewID("net")
	version := time.Now().UTC()
	require.NoError(t, f.uc.Register(ctx, f.request(0, id, version)))
	var beforeRoot, afterRoot int64
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT revision FROM kaname.authority_binding_epoch WHERE scope=''`).Scan(&beforeRoot))
	kanamepg.BindingMirrorStageForTest(t, ctx, f.r.repo, f.r.bundle, f.bindings[0], false, []string{f.scenes[0].Account}, func() {
		moveCtx, stop := fullMeasurementContext(f.ctx, "mirror_move")
		defer stop()
		require.NoError(t, f.uc.Register(moveCtx, f.request(1, id, version.Add(time.Second))))
	}, true)
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT revision FROM kaname.authority_binding_epoch WHERE scope=''`).Scan(&afterRoot))
	require.Equal(t, beforeRoot, afterRoot, "FULL invalidation использует preheld accounts, не root fallback")
	f.native(t, 0, id, false)
	f.native(t, 1, id, true)
	for _, label := range []string{"mirror_initial", "mirror_move"} {
		entries := 0
		for _, q := range trace.get(label) {
			if fullMeasurementIsEntry(q.SQL) {
				entries++
				require.Equal(t, "accounts", fmt.Sprint(q.Args[0]))
			}
			if strings.Contains(q.SQL, "resource_registration_scope") && strings.HasPrefix(strings.TrimSpace(q.SQL), "SELECT") {
				// Конкретное отсутствие late discovery проверяет обязательный
				// existing final-clock suite; здесь сохраняем actual SQL trace.
				t.Logf("retained source query label=%s pid=%d sql=%s", label, q.PID, q.SQL)
			}
		}
		require.Greater(t, entries, 0)
	}
}

func TestBindingMirrorLocalityAbsentOwnerFailsBeforeEntry(t *testing.T) {
	r, binding, id, uid := mirrorLocalityFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	setup := r
	setup.ctx = ctx
	require.NoError(t, bindingStageEngine(t, setup, nil).ReconcileBinding(ctx, binding))
	_, err := r.runtime.Exec(ctx, `DELETE FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1`, id)
	require.NoError(t, err)
	_, err = r.runtime.Exec(ctx, `DELETE FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1`, id)
	require.NoError(t, err)
	trace := &fullMeasurementTrace{}
	r = fullMeasurementPool(t, r, trace)
	engine := bindingStageEngine(t, r, nil)
	call, stop := fullMeasurementContext(ctx, "missing_owner")
	defer stop()
	err = engine.ReconcileBinding(call, binding)
	require.Error(t, err)
	for _, query := range trace.get("missing_owner") {
		require.False(t, fullMeasurementIsEntry(query.SQL), "неполный owner не превращается в GLOBAL")
	}
	require.True(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id), "refusal не частично удаляет OLD claims")
}

func TestBindingMirrorLocalityClosureRejectsTriggerAndPrivateHelperTamper(t *testing.T) {
	r := writerProtocolRig(t)
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 30*time.Second)
	defer cancel()
	const signature = `kaname._authority_binding_mirror_locality_v3(jsonb,jsonb,jsonb,jsonb,jsonb,jsonb)`
	for _, fault := range []string{"missing_trigger", "disabled_trigger", "extra_trigger", "body", "public_acl", "nonowner_acl", "search_path", "owner", "strict", "apply_body", "receipt_acl", "epoch_lock_body", "probe_body", "probe_public_acl", "probe_nonowner_acl", "probe_owner", "probe_strict", "probe_path"} {
		t.Run(fault, func(t *testing.T) {
			tx, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer mirrorLocalityRollback(t, tx)
			var good bool
			require.NoError(t, tx.QueryRow(ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&good))
			require.True(t, good)
			var sql string
			switch fault {
			case "missing_trigger":
				sql = `DROP TRIGGER binding_epoch_insert ON kaname.resource_registration_scope`
			case "disabled_trigger":
				sql = `ALTER TABLE kaname.resource_registration_scope DISABLE TRIGGER binding_epoch_update`
			case "extra_trigger":
				sql = `CREATE TRIGGER extra_binding_epoch AFTER DELETE ON kaname.resource_registration_scope REFERENCING OLD TABLE AS old_epoch_rows FOR EACH STATEMENT EXECUTE FUNCTION kaname.authority_binding_epoch_changed()`
			case "body":
				sql = `CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_locality_v3(p_index jsonb,p_catalog jsonb,p_graph jsonb,p_binding jsonb,p_coordinate jsonb,p_ledger jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$ BEGIN RETURN true;END $fault$`
			case "public_acl":
				sql = `GRANT EXECUTE ON FUNCTION ` + signature + ` TO PUBLIC`
			case "nonowner_acl":
				sql = `GRANT EXECUTE ON FUNCTION ` + signature + ` TO ` + pgx.Identifier{r.role}.Sanitize()
			case "search_path":
				sql = `ALTER FUNCTION ` + signature + ` SET search_path=pg_catalog,kaname,pg_temp`
			case "owner":
				sql = `ALTER FUNCTION ` + signature + ` OWNER TO ` + pgx.Identifier{r.role}.Sanitize()
			case "strict":
				sql = `ALTER FUNCTION ` + signature + ` STRICT`
			case "apply_body":
				sql = `CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_before_write_v3(p_table text,p_operation text,p_old jsonb,p_new jsonb) RETURNS boolean LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$ BEGIN RETURN true;END $fault$`
			case "receipt_acl":
				sql = `GRANT EXECUTE ON FUNCTION kaname._authority_binding_mirror_epoch_v3(text[],jsonb,timestamptz) TO PUBLIC`
			case "probe_body":
				sql = `CREATE OR REPLACE FUNCTION kaname._authority_binding_mirror_probe_v4() RETURNS TABLE(proof jsonb,metadata jsonb) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$ BEGIN RETURN NEXT;END $fault$`
			case "probe_public_acl":
				sql = `GRANT EXECUTE ON FUNCTION kaname._authority_binding_mirror_probe_v4() TO PUBLIC`
			case "probe_nonowner_acl":
				sql = `GRANT EXECUTE ON FUNCTION kaname._authority_binding_mirror_probe_v4() TO ` + pgx.Identifier{r.role}.Sanitize()
			case "probe_owner":
				sql = `ALTER FUNCTION kaname._authority_binding_mirror_probe_v4() OWNER TO ` + pgx.Identifier{r.role}.Sanitize()
			case "probe_strict":
				sql = `ALTER FUNCTION kaname._authority_binding_mirror_probe_v4() STRICT`
			case "probe_path":
				sql = `ALTER FUNCTION kaname._authority_binding_mirror_probe_v4() SET search_path=pg_catalog,kaname,pg_temp`
			case "epoch_lock_body":
				sql = `CREATE OR REPLACE FUNCTION kaname.authority_binding_epoch_lock(p_accounts text[],p_expected jsonb) RETURNS timestamptz LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$ BEGIN RETURN clock_timestamp();END $fault$`
			}
			_, err = tx.Exec(ctx, sql)
			require.NoError(t, err)
			require.NoError(t, tx.QueryRow(ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&good))
			require.False(t, good, fault)
		})
	}
	// Исполняемые Down/Up обязаны восстановить точные тела, старые OID/ACL
	// и закрыть новый helper. Исторические migrations/reports не переписываются.
	t.Run("corrective_down_up", func(t *testing.T) {
		raw, err := migrations.FS.ReadFile("20261118120000_binding_mirror_reuses_invocation_attestation.sql")
		require.NoError(t, err)
		parts := strings.Split(string(raw), "-- +goose Down")
		require.Len(t, parts, 2)
		// Каждый drain — первое выражение своей свежей TX. DDL Down получает
		// XID, поэтому следующий Up выполняется только после реального COMMIT.
		apply := func(callCtx context.Context, sql string) error {
			tx, e := r.admin.Begin(callCtx)
			if e != nil {
				return e
			}
			defer mirrorLocalityRollback(t, tx)
			if _, e = tx.Exec(callCtx, sql); e != nil {
				return e
			}
			return tx.Commit(callCtx)
		}
		restoreUp := false
		// Cleanup subtest выполняется до проверок родителя и закрытия private DB.
		// После committed Down любой Fatal ниже восстанавливает Up в свежей TX,
		// с отдельным cleanup-контекстом даже при отмене исходного ctx.
		t.Cleanup(func() {
			if restoreUp {
				cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer stop()
				require.NoError(t, apply(cleanup, parts[0]), "восстановить Up после committed Down")
			}
		})
		state := func() string {
			var value string
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT jsonb_agg(jsonb_build_object(
 'signature',p.oid::regprocedure::text,'oid',CASE WHEN p.proname='_authority_binding_mirror_probe_v4' THEN NULL ELSE p.oid END,
 'definition',pg_get_functiondef(p.oid),'owner',p.proowner,'acl',p.proacl) ORDER BY p.proname)::text
 FROM pg_catalog.pg_proc p WHERE p.pronamespace='kaname'::regnamespace AND p.proname IN (
 '_authority_binding_mirror_probe_v4','_authority_binding_mirror_store_v3','_authority_binding_mirror_before_write_v3',
 '_authority_crud_storage_v3','_authority_full_contract_storage_v3','_authority_protocol_snapshot_v3','authority_protocol_attestation')`).Scan(&value))
			return value
		}
		before := state()
		require.NoError(t, apply(ctx, parts[1]))
		restoreUp = true
		var absent bool
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT to_regprocedure('kaname._authority_binding_mirror_probe_v4()') IS NULL`).Scan(&absent))
		require.True(t, absent)
		require.NoError(t, apply(ctx, parts[0]))
		restoreUp = false
		require.JSONEq(t, before, state())
		var good bool
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&good))
		require.True(t, good)
	})
	var good bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&good))
	require.True(t, good, "rollback восстанавливает точный closure")
	var granted bool
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, signature).Scan(&granted))
	require.False(t, granted)
}

func TestBindingMirrorLocalityPreparedApplyRejectsForgedImages(t *testing.T) {
	r, binding, id, uid := mirrorLocalityFixture(t)
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	setup := r
	setup.ctx = ctx
	other := groupLifecycleBinding(t, setup, r.a, uid, "other_"+ids.NewID("rol"), domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}})
	r.repo, _ = fullContractActivate(t, setup)
	// Owner-only дверь меняет настоящий prepared witness после успешной проверки.
	// Probe не получает caller proof: каждый вызов заново читает protected storage.
	_, err := r.admin.Exec(ctx, `CREATE FUNCTION kaname.test_binding_mirror_invocation_v4(p_fault text) RETURNS boolean
 LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $probe$
 DECLARE actual_proof jsonb;actual_metadata jsonb;
 BEGIN
  SELECT p.proof,p.metadata INTO STRICT actual_proof,actual_metadata FROM kaname._authority_binding_mirror_probe_v4() p;
  IF actual_proof IS NULL OR actual_metadata IS NULL
   OR actual_proof IS DISTINCT FROM kaname.authority_protocol_attestation()
   OR actual_metadata IS DISTINCT FROM kaname._authority_binding_mirror_store_v3() THEN
   RAISE EXCEPTION 'test requires actual paired mirror proof';END IF;
  CASE p_fault
   WHEN 'pair' THEN RETURN true;
   WHEN 'root' THEN UPDATE pg_temp.kaname_authority_attestation SET mode='global';
   WHEN 'account' THEN UPDATE pg_temp.kaname_authority_attestation SET accounts=accounts||ARRAY['mirror_invocation_missing'];
   WHEN 'consumer' THEN UPDATE pg_temp.kaname_authority_consumer SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
   WHEN 'mirror_nonce' THEN UPDATE pg_temp.kaname_binding_mirror_program SET nonce='00000000-0000-0000-0000-000000000000';
   WHEN 'clock' THEN UPDATE pg_temp.kaname_authority_attestation SET decision_at=decision_at+interval '1 second';
   WHEN 'population' THEN LOCK TABLE kaname.authority_producer_population_latch IN EXCLUSIVE MODE;
   ELSE RAISE EXCEPTION 'unknown mirror invocation fault';
  END CASE;
  RETURN kaname._authority_binding_mirror_before_write_v3('access_binding_target_members','INSERT',NULL,'{}'::jsonb);
 END $probe$;
 REVOKE ALL ON FUNCTION kaname.test_binding_mirror_invocation_v4(text) FROM PUBLIC`)
	require.NoError(t, err)
	_, err = r.admin.Exec(ctx, `GRANT EXECUTE ON FUNCTION kaname.test_binding_mirror_invocation_v4(text) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, e := r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_binding_mirror_invocation_v4(text)`)
		require.NoError(t, e)
	})
	kanamepg.BindingMirrorPreparedApplyForTest(t, ctx, r.repo, r.bundle, binding, other, r.a)
	var members int
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members WHERE binding_id=$1`, string(binding)).Scan(&members))
	require.Zero(t, members, "independent connection sees rolled-back actual apply")
	require.False(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id))
	require.NoError(t, bindingStageEngine(t, r, nil).ReconcileBinding(ctx, binding))
	require.True(t, ledgerHasTuple(t, ctx, r.runtime, binding, "user:"+uid, "v_get", "vpc_network:"+id))
	allow, err := (delegationNativeDoor{r}).Check(ctx, "user:"+uid, "v_get", "vpc_network:"+id)
	require.NoError(t, err)
	require.True(t, allow)
}

// Отдельный backend читает persisted состояние после actual COMMIT/rollback.
// Перед каждым сценарием новая база; outbox-фильтр не включает setup binding.
func mirrorProgramPersistedState(t *testing.T, r protocolRig, binding domain.AccessBindingID, object string) (string, int, int, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
	defer cancel()
	var state string
	var members, ledger, outboxes int
	err := r.runtime.QueryRow(ctx, `WITH m AS (
 SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) images FROM kaname.access_binding_target_members t WHERE binding_id=$1
), l AS (
 SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) images FROM kaname.access_binding_emitted_tuples t WHERE binding_id=$1
), f AS (
 SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) images FROM kaname.relation_fact t WHERE object_type='vpc_network' AND object_id=$2
), o AS (
 SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY t.id),'[]'::jsonb) images FROM kaname.fga_outbox t WHERE payload->>'object'='vpc_network:'||$2
) SELECT jsonb_build_object('members',m.images,'ledger',l.images,'facts',f.images,'outbox',o.images)::text,
 jsonb_array_length(m.images),jsonb_array_length(l.images),jsonb_array_length(o.images) FROM m,l,f,o`, string(binding), object).Scan(&state, &members, &ledger, &outboxes)
	require.NoError(t, err)
	return state, members, ledger, outboxes
}

func TestBindingMirrorPreparedProgramRequiresCompleteOrderedConsumption(t *testing.T) {
	for _, mutation := range []string{"complete", "omit_required_members", "replay_record", "record_before_members"} {
		t.Run(mutation, func(t *testing.T) {
			r, binding, id, uid := mirrorLocalityFixture(t)
			setup, cancelSetup := context.WithTimeout(r.ctx, 30*time.Second)
			prepared := r
			prepared.ctx = setup
			r.repo, _ = fullContractActivate(t, prepared)
			cancelSetup()
			before, memberBefore, ledgerBefore, outboxBefore := mirrorProgramPersistedState(t, r, binding, id)
			require.Zero(t, memberBefore)
			require.Zero(t, ledgerBefore)
			require.Zero(t, outboxBefore)
			ctx, cancel := context.WithTimeout(r.ctx, 30*time.Second)
			err := kanamepg.BindingMirrorProgramCommitForTest(t, ctx, r.repo, r.bundle, binding, r.a, mutation)
			cancel()
			// Читаем observer даже при неожиданном successful COMMIT на R1.
			after, members, ledger, outboxes := mirrorProgramPersistedState(t, r, binding, id)
			if mutation == "complete" {
				require.NoError(t, err)
				require.Positive(t, members)
				require.Positive(t, ledger)
				require.Positive(t, outboxes)
				check, stop := context.WithTimeout(r.ctx, 30*time.Second)
				defer stop()
				allow, checkErr := (delegationNativeDoor{r}).Check(check, "user:"+uid, "v_get", "vpc_network:"+id)
				require.NoError(t, checkErr)
				if !allow {
					mirrorLogPublicVGet(t, check, r, binding, uid, id, allow)
				}
				require.True(t, allow)
				return
			}
			if err == nil {
				t.Errorf("%s: actual COMMIT accepted incomplete/replayed/reordered owner program; persisted members=%d ledger=%d outboxes=%d", mutation, members, ledger, outboxes)
			} else {
				var pgerr *pgconn.PgError
				require.ErrorAs(t, err, &pgerr, "timeout/cancellation/transport failure не доказывает semantic refusal")
				require.Contains(t, []string{"42501", "P1036"}, pgerr.Code, "только закрытый authorization/completion отказ")
			}
			require.JSONEq(t, before, after, "member/ledger/fact/outbox должны полностью откатиться")
		})
	}
}

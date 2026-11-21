// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

const auditAdmissionID = "evt_00000000000000000001"
const auditAdmissionProbeID = "evt_00000000000000000002"

const auditAdmissionInsert = `INSERT INTO kaname.audit_outbox(id,event_type,event_payload)
 VALUES ('` + auditAdmissionID + `','iam.session.issued','{}'::jsonb)`

func auditAdmissionRootHeld(t *testing.T, r protocolRig, tx pgx.Tx) bool {
	t.Helper()
	var held bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
 WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569283::oid AND objid=0::oid AND objsubid=2
 AND mode IN ('ShareLock','ExclusiveLock') AND granted)`).Scan(&held))
	return held
}

// Настоящий первичный ApplyAll, включая audit в той же транзакции. Одного
// ручного INSERT audit недостаточно: regression возник именно на installation.
func TestAuditBootstrapCatalogInstallationWritesAudit(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	r = identityLifecycleSingle(t, r)
	var phase string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT phase FROM kaname.authority_semantic_identity WHERE singleton`).Scan(&phase))
	require.Equal(t, "uninitialized", phase)
	before := auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent)
	declared := []*manifest.Manifest{probeManifest(probeResource("bootstrapaudit", "get"))}
	_, err := applierOver(t, r.runtime).ApplyAll(r.ctx, declared)
	require.NoError(t, err, "законная первичная установка фиксирует каталог и audit")
	require.Equal(t, before+1, auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent))
	var rows int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.catalog_resource WHERE module=$1 AND resource='bootstrapaudit'`, applierProbeModule).Scan(&rows))
	require.Equal(t, 1, rows)
	_, err = applierOver(t, r.runtime).ApplyAll(r.ctx, declared)
	require.NoError(t, err, "пустая owner-квитанция после COMMIT допускает следующий canonical entry")
	require.Equal(t, before+1, auditRowsOfType(t, r.ctx, r.admin, moduleCatalogAppliedEvent), "неизменный каталог не пишет второй audit")
}

// Runtime может взять root и drain сам. Даже в точном initial state это
// не квитанция canonical entry; смена lifecycle также не открывает этот путь.
func TestAuditBootstrapLocksDoNotProveInstallationAdmission(t *testing.T) {
	for _, phase := range []string{"uninitialized", "prepared", "transition", "active", "strict"} {
		t.Run(phase, func(t *testing.T) {
			r, owner := writerProtocolRigBeforePreparation(t)
			if phase != "uninitialized" {
				require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
			}
			if phase == "transition" || phase == "active" {
				_, err := r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET phase=$1 WHERE singleton`, phase)
				require.NoError(t, err)
			}
			if phase == "strict" {
				r.strict(t)
			}
			conn, err := r.runtime.Acquire(r.ctx)
			require.NoError(t, err)
			defer conn.Release()
			_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
			require.NoError(t, err)
			tx, err := conn.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0); SELECT pg_advisory_xact_lock(1262569292,0)`)
			require.NoError(t, err)
			_, err = tx.Exec(r.ctx, auditAdmissionInsert)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, "42501", denied.Code)
			require.Error(t, tx.Commit(r.ctx))
			var count int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE id=$1`, auditAdmissionID).Scan(&count))
			require.Zero(t, count)
		})
	}
}

// Проверяется именно runtime LOGIN: чужая квитанция не принимается, а
// DISCARD/rollback/предыдущий COMMIT не превращают потерянный entry в ordinary.
func TestAuditBootstrapWitnessCannotBeForgedOrReused(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	_, err := r.admin.Exec(r.ctx, auditAdmissionInsert)
	require.NoError(t, err)
	for _, fault := range []string{"foreign-table", "foreign-view", "discard", "rollback-entry", "failed-entry", "pooled-empty"} {
		for _, operation := range []string{"insert", "update", "delete"} {
			t.Run(fault+"/"+operation, func(t *testing.T) {
				conn, err := r.runtime.Acquire(r.ctx)
				require.NoError(t, err)
				defer conn.Release()
				_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
				require.NoError(t, err)
				if fault == "pooled-empty" {
					previous, e := conn.Begin(r.ctx)
					require.NoError(t, e)
					defer attestationLocksetRollback(previous)
					_, e = previous.Exec(r.ctx, `SELECT kaname.authority_installation_enter_v2('catalog')`)
					require.NoError(t, e)
					require.NoError(t, previous.Commit(r.ctx))
					var present bool
					require.NoError(t, conn.QueryRow(r.ctx, `SELECT to_regclass('pg_temp.kaname_authority_installation') IS NOT NULL`).Scan(&present))
					require.True(t, present, "проверяется сохранённая owner-квитанция после COMMIT")
				}
				tx, err := conn.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				switch fault {
				case "foreign-table":
					_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_installation(singleton boolean)`)
				case "foreign-view":
					_, err = tx.Exec(r.ctx, `CREATE TEMP VIEW kaname_authority_installation AS SELECT true AS singleton WHERE false`)
				case "discard":
					_, err = tx.Exec(r.ctx, `SELECT kaname.authority_installation_enter_v2('catalog')`)
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `DISCARD TEMP; SELECT pg_advisory_unlock_all()`)
					require.NoError(t, err)
					require.True(t, auditAdmissionRootHeld(t, r, tx))
				case "rollback-entry", "failed-entry":
					_, err = tx.Exec(r.ctx, `SAVEPOINT before_entry`)
					require.NoError(t, err)
					kind := "catalog"
					if fault == "failed-entry" {
						kind = "not-an-installation-family"
					}
					_, err = tx.Exec(r.ctx, `SELECT kaname.authority_installation_enter_v2($1)`, kind)
					if fault == "failed-entry" {
						var refused *pgconn.PgError
						require.ErrorAs(t, err, &refused)
						require.Equal(t, "22023", refused.Code)
					} else {
						require.NoError(t, err)
					}
					_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT before_entry`)
					require.NoError(t, err)
					require.False(t, auditAdmissionRootHeld(t, r, tx), "откат отменил admission")
					// Законный близнец: после полного отката entry обычный audit
					// разрешён. Только последующая ручная подделка root+D откажет.
					_, err = tx.Exec(r.ctx, strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID))
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `DELETE FROM kaname.audit_outbox WHERE id=$1`, auditAdmissionProbeID)
					require.NoError(t, err)
				}
				require.NoError(t, err)
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0); SELECT pg_advisory_xact_lock(1262569292,0)`)
				require.NoError(t, err)
				statement := strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID)
				if operation == "update" {
					statement = `UPDATE kaname.audit_outbox SET attempts=attempts+1 WHERE id='` + auditAdmissionID + `'`
				} else if operation == "delete" {
					statement = `DELETE FROM kaname.audit_outbox WHERE id='` + auditAdmissionID + `'`
				}
				_, err = tx.Exec(r.ctx, statement)
				var denied *pgconn.PgError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, "42501", denied.Code)
				require.Error(t, tx.Commit(r.ctx))
				var count, attempts int
				queriedID := auditAdmissionID
				expected := 1
				if operation == "insert" {
					queriedID, expected = auditAdmissionProbeID, 0
				}
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),coalesce(sum(attempts),0) FROM kaname.audit_outbox WHERE id=$1`, queriedID).Scan(&count, &attempts))
				require.Equal(t, expected, count)
				require.Zero(t, attempts)
			})
		}
	}
}

// Один backend после настоящего signed COMMIT сохраняет пустые owner TEMP
// tables. И он, и чистый backend должны писать audit, пока ДРУГАЯ TX держит
// compatibility fence. INSERT проходит оба row guards; UPDATE/DELETE — statement.
func TestAuditOrdinaryWriterNeverAcquiresLateAuthorityFence(t *testing.T) {
	for _, strict := range []bool{false, true} {
		mode := "compatibility"
		if strict {
			mode = "strict"
		}
		for _, pooled := range []bool{false, true} {
			backend := "clean"
			if pooled {
				backend = "pooled_empty_owner_witness"
			}
			t.Run(mode+"/"+backend, func(t *testing.T) {
				r := writerProtocolRig(t)
				purpose := "transition"
				if strict {
					r.strict(t)
					purpose = "decision"
				}
				conn, err := r.runtime.Acquire(r.ctx)
				require.NoError(t, err)
				defer conn.Release()
				_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
				require.NoError(t, err)
				if pooled {
					previous, e := conn.Begin(r.ctx)
					require.NoError(t, e)
					defer attestationLocksetRollback(previous)
					r.enter(t, previous, r.intent(r.a), purpose)
					require.True(t, auditAdmissionRootHeld(t, r, previous))
					require.NoError(t, previous.Commit(r.ctx))
				}
				var present bool
				require.NoError(t, conn.QueryRow(r.ctx, `SELECT to_regclass('pg_temp.kaname_authority_attestation') IS NOT NULL`).Scan(&present))
				require.Equal(t, pooled, present, "проверяется именно сохранённая после COMMIT таблица")
				holder, err := r.admin.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(holder)
				_, err = holder.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569292,0)`)
				require.NoError(t, err)
				tx, err := conn.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				require.False(t, auditAdmissionRootHeld(t, r, tx), "root lock прошлого entry освобождён")
				_, err = tx.Exec(r.ctx, `SET LOCAL lock_timeout='500ms'`)
				require.NoError(t, err)
				for _, statement := range []string{
					auditAdmissionInsert,
					`UPDATE kaname.audit_outbox SET attempts=attempts+1 WHERE id='` + auditAdmissionID + `'`,
					`DELETE FROM kaname.audit_outbox WHERE id='` + auditAdmissionID + `'`,
				} {
					tag, e := tx.Exec(r.ctx, statement)
					require.NoError(t, e, "ordinary audit не ждёт authority fence")
					require.EqualValues(t, 1, tag.RowsAffected())
				}
				var admitted bool
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks
 WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569292::oid AND objid=0::oid AND objsubid=2)`).Scan(&admitted))
				require.False(t, admitted, "audit не приобрёл и не запросил compatibility fence")
				var reserved bool
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks
 WHERE pid=pg_backend_pid() AND database=(SELECT oid FROM pg_database WHERE datname=current_database())
 AND locktype='advisory' AND classid=1262569298::oid AND objid=(hashtext($1)::bigint & 4294967295)::oid
 AND objsubid=2 AND mode='ExclusiveLock' AND granted)`, auditAdmissionID).Scan(&reserved))
				require.True(t, reserved, "обычный audit по-прежнему резервирует собственный ID")
				require.NoError(t, tx.Commit(r.ctx))
			})
		}
	}
}

// DISCARD TEMP разрешён ordinary LOGIN и удаляет даже owner TEMP storage.
// Xact root lock остаётся: отсутствие таблиц не разрешает прежнему signed TX
// записать непроверенный audit. Foreign empty table/view также не ordinary.
func TestAuditOrdinaryFastPathRejectsMissingOrForgedAuthorityWitness(t *testing.T) {
	for _, strict := range []bool{false, true} {
		r := writerProtocolRig(t)
		_, err := r.admin.Exec(r.ctx, auditAdmissionInsert)
		require.NoError(t, err)
		// Owner-only GIVEN: compare source profile не становится писателем
		// аудита через новую ordinary ветку. Runtime не может создать owner row.
		_, err = r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_audit_local_compare() RETURNS void
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 BEGIN
  CREATE TEMP TABLE kaname_authority_compare ON COMMIT DROP AS
   SELECT pg_backend_pid() AS backend,pg_current_xact_id() AS transaction_id,
    (SELECT oid FROM pg_roles WHERE rolname=session_user) AS invoker_oid,
    gen_random_uuid()::text AS nonce,'accounts'::text AS mode;
  REVOKE ALL ON pg_temp.kaname_authority_compare FROM PUBLIC;
 END $$;
 REVOKE ALL ON FUNCTION kaname.test_audit_local_compare() FROM PUBLIC`)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, `GRANT EXECUTE ON FUNCTION kaname.test_audit_local_compare() TO `+pgx.Identifier{r.role}.Sanitize())
		require.NoError(t, err)
		var executable bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,
 'kaname._authority_audit_binding_store_v3()','EXECUTE')`).Scan(&executable))
		require.False(t, executable, "audit selector не становится runtime API")
		mode := "compatibility"
		purpose := "transition"
		if strict {
			mode = "strict"
			r.strict(t)
			purpose = "decision"
		}
		for _, fault := range []string{"foreign-attestation", "foreign-view", "foreign-compare", "foreign-mirror", "owner-local-compare", "discard-account-entry", "discard-global-entry"} {
			for _, operation := range []string{"insert", "update", "delete"} {
				t.Run(mode+"/"+fault+"/"+operation, func(t *testing.T) {
					conn, err := r.runtime.Acquire(r.ctx)
					require.NoError(t, err)
					defer conn.Release()
					_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
					require.NoError(t, err)
					tx, err := conn.Begin(r.ctx)
					require.NoError(t, err)
					defer attestationLocksetRollback(tx)
					switch fault {
					case "foreign-attestation":
						_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_attestation(singleton boolean)`)
					case "foreign-view":
						_, err = tx.Exec(r.ctx, `CREATE TEMP VIEW kaname_authority_attestation AS SELECT true AS singleton WHERE false`)
					case "foreign-compare":
						_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_compare(singleton boolean)`)
					case "foreign-mirror":
						_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_binding_mirror_program(singleton boolean)`)
					case "owner-local-compare":
						_, err = tx.Exec(r.ctx, `SELECT kaname.test_audit_local_compare()`)
					default:
						intent := r.intent(r.a)
						if fault == "discard-global-entry" {
							intent = r.intent()
							intent.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
						}
						r.enter(t, tx, intent, purpose)
						require.True(t, auditAdmissionRootHeld(t, r, tx))
						// Положительный близнец: та же подписанная TX до DISCARD
						// проходит canonical attestation; отказ не blanket для signed.
						_, err = tx.Exec(r.ctx, strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID))
						require.NoError(t, err)
						_, err = tx.Exec(r.ctx, `DELETE FROM kaname.audit_outbox WHERE id=$1`, auditAdmissionProbeID)
						require.NoError(t, err)
						_, err = tx.Exec(r.ctx, `DISCARD TEMP; SELECT pg_advisory_unlock_all()`)
						require.NoError(t, err)
						require.True(t, auditAdmissionRootHeld(t, r, tx), "DISCARD/session unlock не снимают xact root anchor")
					}
					require.NoError(t, err)
					statement := strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID)
					if operation == "update" {
						statement = `UPDATE kaname.audit_outbox SET attempts=attempts+1 WHERE id='` + auditAdmissionID + `'`
					} else if operation == "delete" {
						statement = `DELETE FROM kaname.audit_outbox WHERE id='` + auditAdmissionID + `'`
					}
					_, err = tx.Exec(r.ctx, statement)
					var denied *pgconn.PgError
					require.ErrorAs(t, err, &denied)
					require.Equal(t, "42501", denied.Code)
					require.Error(t, tx.Commit(r.ctx), "отказ нельзя зафиксировать вместе с audit")
					var count, attempts int
					queriedID := auditAdmissionID
					if operation == "insert" {
						queriedID = auditAdmissionProbeID
					}
					require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),coalesce(sum(attempts),0)
 FROM kaname.audit_outbox WHERE id=$1`, queriedID).Scan(&count, &attempts))
					expected := 1
					if operation == "insert" {
						expected = 0
					}
					require.Equal(t, expected, count)
					require.Zero(t, attempts)
				})
			}
		}
	}
}

// Нельзя сменить signed entry на unsigned после DISCARD TEMP. Даже session
// unlock сохраняет xact root; отказ entry не оставляет audit effects.
func TestAuditReconcileEntryCannotReplaceLostSignedWitness(t *testing.T) {
	for _, strict := range []bool{false, true} {
		r := writerProtocolRig(t)
		purpose := "transition"
		if strict {
			r.strict(t)
			purpose = "decision"
		}
		for _, mode := range []string{"accounts", "global"} {
			t.Run(purpose+"/"+mode, func(t *testing.T) {
				conn, err := r.runtime.Acquire(r.ctx)
				require.NoError(t, err)
				defer conn.Release()
				_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
				require.NoError(t, err)
				tx, err := conn.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				intent := r.intent(r.a)
				if mode == "global" {
					intent = r.intent()
					intent.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
				}
				r.enter(t, tx, intent, purpose)
				_, err = tx.Exec(r.ctx, auditAdmissionInsert)
				require.NoError(t, err, "signed близнец пишет audit до потери witness")
				_, err = tx.Exec(r.ctx, `DISCARD TEMP; SELECT pg_advisory_unlock_all()`)
				require.NoError(t, err)
				require.True(t, auditAdmissionRootHeld(t, r, tx))
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_reconcile_enter_v3()`)
				var denied *pgconn.PgError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, "25001", denied.Code)
				require.Error(t, tx.Commit(r.ctx))
				var count int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE id=$1`, auditAdmissionID).Scan(&count))
				require.Zero(t, count)
			})
		}
	}
}

// Даже законный executor не может войти после начала другого writer или
// подделать root перед entry; owner-квитанция не доступна runtime для записи.
func TestAuditReconcileEntryRequiresFreshTransaction(t *testing.T) {
	r := writerProtocolRig(t)
	for _, fault := range []string{"assigned-xid", "manual-root", "repeated-entry", "discard-entry", "witness-write"} {
		t.Run(fault, func(t *testing.T) {
			conn, err := r.runtime.Acquire(r.ctx)
			require.NoError(t, err)
			defer conn.Release()
			_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
			require.NoError(t, err)
			tx, err := conn.Begin(r.ctx)
			require.NoError(t, err)
			defer attestationLocksetRollback(tx)
			switch fault {
			case "assigned-xid":
				_, err = tx.Exec(r.ctx, `SELECT pg_current_xact_id()`)
			case "manual-root":
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock_shared(1262569283,0)`)
			default:
				_, err = tx.Exec(r.ctx, `SELECT kaname.authority_reconcile_enter_v3()`)
			}
			require.NoError(t, err)
			if fault == "discard-entry" {
				_, err = tx.Exec(r.ctx, `DISCARD TEMP; SELECT pg_advisory_unlock_all()`)
				require.NoError(t, err)
			}
			statement := `SELECT kaname.authority_reconcile_enter_v3()`
			want := "25001"
			if fault == "witness-write" {
				statement = `UPDATE pg_temp.kaname_authority_reconcile SET invoker_oid=0`
				want = "42501"
			}
			_, err = tx.Exec(r.ctx, statement)
			var denied *pgconn.PgError
			require.ErrorAs(t, err, &denied)
			require.Equal(t, want, denied.Code)
			require.Error(t, tx.Commit(r.ctx))
		})
	}
}

// Потерянная, чужая или завершённая reconcile-квитанция не разрешает audit.
func TestAuditReconcileWitnessCannotBeForgedOrReused(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	_, err := r.admin.Exec(r.ctx, auditAdmissionInsert)
	require.NoError(t, err)
	for _, fault := range []string{"foreign-table", "foreign-view", "discard", "rollback-entry", "pooled-empty", "manual-locks"} {
		for _, operation := range []string{"insert", "update", "delete"} {
			t.Run(fault+"/"+operation, func(t *testing.T) {
				conn, err := r.runtime.Acquire(r.ctx)
				require.NoError(t, err)
				defer conn.Release()
				_, err = conn.Exec(r.ctx, `DISCARD TEMP`)
				require.NoError(t, err)
				if fault == "pooled-empty" {
					previous, e := conn.Begin(r.ctx)
					require.NoError(t, e)
					defer attestationLocksetRollback(previous)
					_, e = previous.Exec(r.ctx, `SELECT kaname.authority_reconcile_enter_v3()`)
					require.NoError(t, e)
					require.NoError(t, previous.Commit(r.ctx))
					var present bool
					require.NoError(t, conn.QueryRow(r.ctx, `SELECT to_regclass('pg_temp.kaname_authority_reconcile') IS NOT NULL`).Scan(&present))
					require.True(t, present, "проверяется сохранённая owner-квитанция после COMMIT")
				}
				tx, err := conn.Begin(r.ctx)
				require.NoError(t, err)
				defer attestationLocksetRollback(tx)
				switch fault {
				case "foreign-table":
					_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_reconcile(singleton boolean)`)
				case "foreign-view":
					_, err = tx.Exec(r.ctx, `CREATE TEMP VIEW kaname_authority_reconcile AS SELECT true AS singleton WHERE false`)
				case "discard":
					_, err = tx.Exec(r.ctx, `SELECT kaname.authority_reconcile_enter_v3()`)
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `DISCARD TEMP; SELECT pg_advisory_unlock_all()`)
					require.NoError(t, err)
					require.True(t, auditAdmissionRootHeld(t, r, tx))
				case "rollback-entry":
					_, err = tx.Exec(r.ctx, `SAVEPOINT before_entry`)
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `SELECT kaname.authority_reconcile_enter_v3()`)
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT before_entry`)
					require.NoError(t, err)
					require.False(t, auditAdmissionRootHeld(t, r, tx), "откат отменил admission")
					// Законный близнец: после полного отката entry обычный audit
					// разрешён. Только последующая ручная подделка root+D откажет.
					_, err = tx.Exec(r.ctx, strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID))
					require.NoError(t, err)
					_, err = tx.Exec(r.ctx, `DELETE FROM kaname.audit_outbox WHERE id=$1`, auditAdmissionProbeID)
					require.NoError(t, err)
				}
				require.NoError(t, err)
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock_shared(1262569283,0); SELECT pg_advisory_xact_lock(1262569292,0)`)
				require.NoError(t, err)
				statement := strings.ReplaceAll(auditAdmissionInsert, auditAdmissionID, auditAdmissionProbeID)
				if operation == "update" {
					statement = `UPDATE kaname.audit_outbox SET attempts=attempts+1 WHERE id='` + auditAdmissionID + `'`
				} else if operation == "delete" {
					statement = `DELETE FROM kaname.audit_outbox WHERE id='` + auditAdmissionID + `'`
				}
				_, err = tx.Exec(r.ctx, statement)
				var denied *pgconn.PgError
				require.ErrorAs(t, err, &denied)
				require.Equal(t, "42501", denied.Code)
				require.Error(t, tx.Commit(r.ctx))
				var count, attempts int
				queriedID := auditAdmissionID
				expected := 1
				if operation == "insert" {
					queriedID, expected = auditAdmissionProbeID, 0
				}
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),coalesce(sum(attempts),0) FROM kaname.audit_outbox WHERE id=$1`, queriedID).Scan(&count, &attempts))
				require.Equal(t, expected, count)
				require.Zero(t, attempts)
			})
		}
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

type protocolRig struct {
	ctx            context.Context
	admin, runtime *pgxpool.Pool
	repo           *kanamepg.Repository
	bundle         *granteffect.Bundle
	role, a, b     string
}

func writerProtocolRig(t *testing.T) protocolRig {
	t.Helper()
	ctx, admin, owner := authorityTestDB(t)
	_, a := kac127SeedUserAndAccount(t, ctx, admin, "protocol-a")
	_, b := kac127SeedUserAndAccount(t, ctx, admin, "protocol-b")
	bundle := semanticBundleDB(t, ctx, admin)
	role := fmt.Sprintf("protocol_runtime_%s", strings.ReplaceAll(ids.NewID("rol"), "-", "_"))
	quoted := pgx.Identifier{role}.Sanitize()
	password := ids.NewID("pwd")
	_, err := admin.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = admin.Exec(cleanup, "DROP OWNED BY "+quoted)
		_, _ = admin.Exec(cleanup, "DROP ROLE "+quoted)
	})
	_, err = admin.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, role)
	require.NoError(t, err)
	config := admin.Config()
	config.ConnConfig.User = role
	config.ConnConfig.Password = password
	config.AfterConnect = nil
	runtime, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	var effective, session string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, role, effective)
	require.Equal(t, role, session, "нужна настоящая LOGIN connection, не SET ROLE поверх admin")
	var elevated bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole OR rolbypassrls OR has_schema_privilege(current_user,'kaname','CREATE') OR has_table_privilege(current_user,'kaname.groups','TRIGGER') FROM pg_roles WHERE rolname=current_user`).Scan(&elevated))
	require.False(t, elevated)
	rig := protocolRig{ctx, admin, runtime, kanamepg.New(runtime, nil), bundle, role, a, b}
	uninitialized, err := rig.repo.TransitionalAuthorityWriter(ctx, rig.intent(a))
	require.Error(t, err, "default identity не допускает даже transitional entry")
	require.Nil(t, uninitialized)
	authorityWaitReleased(t, runtime)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, bundle))
	return rig
}
func (r protocolRig) intent(accounts ...string) kaname.AuthorityWriteIntent {
	refs := make([]kaname.AuthorityOwnerRef, len(accounts))
	for i, id := range accounts {
		refs[i] = kaname.AuthorityOwnerRef{Kind: "account", ID: id}
	}
	return kaname.AuthorityWriteIntent{Plan: authorityAccounts(accounts...), Owners: refs, Kind: kaname.AuthorityGroup, Bundle: r.bundle}
}
func (r protocolRig) strict(t *testing.T) {
	t.Helper()
	// Синтетический strict fixture проверяет backstop; продуктового drain тут нет.
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET phase='active'; UPDATE kaname.authority_writer_protocol SET enforcement='strict'`)
	require.NoError(t, err)
}
func (r protocolRig) enter(t *testing.T, tx pgx.Tx, in kaname.AuthorityWriteIntent, purpose string) time.Time {
	t.Helper()
	at, err := protocolEnter(r.ctx, tx, in, purpose)
	require.NoError(t, err)
	return at
}
func protocolEnter(ctx context.Context, tx pgx.Tx, in kaname.AuthorityWriteIntent, purpose string) (time.Time, error) {
	refs, err := json.Marshal(append([]kaname.AuthorityOwnerRef{}, in.Owners...))
	if err != nil {
		return time.Time{}, err
	}
	accounts := make([]string, len(in.Plan.Accounts))
	for i, id := range in.Plan.Accounts {
		accounts[i] = string(id)
	}
	mode := "accounts"
	if in.Plan.Mode == kaname.AuthorityFenceGlobal {
		mode = "global"
	}
	id := in.Bundle.Identity()
	var at time.Time
	err = tx.QueryRow(ctx, `SELECT kaname.authority_protocol_enter($1,$2::text[],$3::jsonb,$4,$5,$6,$7,1,$8)`, mode, accounts, refs, string(in.Kind), id.ModelID, id.CatalogID, id.ProjectorVersion, purpose).Scan(&at)
	return at, err
}
func TestWriterProtocolStagesAdaptersWithoutSemanticDecision(t *testing.T) {
	r := writerProtocolRig(t)
	in := r.intent(r.a)
	decision, err := r.repo.CoordinatedAuthorityWriter(r.ctx, in)
	require.Error(t, err)
	require.Nil(t, decision)
	old, err := r.repo.SemanticAuthorityWriter(r.ctx, in.Plan, r.bundle)
	require.Error(t, err)
	require.Nil(t, old)
	transition, err := r.repo.TransitionalAuthorityWriter(r.ctx, in)
	require.NoError(t, err)
	_, semantic := transition.(kaname.SemanticAuthorityWriter)
	require.False(t, semantic, "compatibility writer не должен нести semantic decision API")
	_, err = transition.GroupsW().Insert(r.ctx, domain.Group{ID: "grp-protocol-stage", AccountID: domain.AccountID(r.a), Name: "protocol-stage"})
	require.NoError(t, err)
	require.NoError(t, transition.Commit(r.ctx))
	r.strict(t)
	transition, err = r.repo.TransitionalAuthorityWriter(r.ctx, in)
	require.Error(t, err)
	require.Nil(t, transition)
	decision, err = r.repo.CoordinatedAuthorityWriter(r.ctx, in)
	require.NoError(t, err)
	require.Same(t, r.bundle, decision.SemanticBundle())
	require.NoError(t, decision.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
func TestWriterProtocolOrdinaryRuntimeCannotForgeOrReplay(t *testing.T) {
	r := writerProtocolRig(t)
	r.strict(t)
	for _, mode := range []string{"no-entry", "fake-guc", "session-locks", "foreign-temp", "direct-state", "late-row-lock", "late-table-lock", "reentry", "private-write", "role-change"} {
		t.Run(mode, func(t *testing.T) {
			conn, err := r.runtime.Acquire(r.ctx)
			require.NoError(t, err)
			defer conn.Release()
			tx, err := conn.Begin(r.ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(context.Background()) }()
			switch mode {
			case "fake-guc":
				_, err = tx.Exec(r.ctx, `SET LOCAL kaname.authority_attestation='ready'; SET LOCAL kaname.authority_protocol='1'`)
				require.NoError(t, err)
			case "session-locks":
				_, err = tx.Exec(r.ctx, `SELECT pg_advisory_lock_shared(1262569283,0),pg_advisory_lock(1262569281,hashtext($1))`, r.a)
				require.NoError(t, err)
				defer func() {
					_ = tx.Rollback(context.Background())
					_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock_all()`)
				}()
			case "foreign-temp":
				_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_attestation(singleton boolean)`)
				require.NoError(t, err)
				require.NoError(t, tx.Commit(r.ctx))
				tx, err = conn.Begin(r.ctx)
				require.NoError(t, err)
				defer func() {
					_ = tx.Rollback(context.Background())
					_, _ = conn.Exec(context.Background(), `DROP TABLE pg_temp.kaname_authority_attestation`)
				}()
				_, err = protocolEnter(r.ctx, tx, r.intent(r.a), "decision")
				require.Error(t, err)
				return
			case "direct-state":
				_, err = tx.Exec(r.ctx, `UPDATE kaname.authority_writer_protocol SET enforcement='compatibility'`)
				require.Error(t, err)
				return
			case "late-row-lock", "late-table-lock":
				if mode == "late-table-lock" {
					_, err = tx.Exec(r.ctx, `LOCK TABLE kaname.groups IN EXCLUSIVE MODE`)
				} else {
					_, err = tx.Exec(r.ctx, `SELECT 1 FROM kaname.accounts WHERE id=$1 FOR UPDATE`, r.a)
				}
				require.NoError(t, err)
				_, err = protocolEnter(r.ctx, tx, r.intent(r.a), "decision")
				require.Error(t, err)
				return
			case "reentry", "private-write", "role-change":
				r.enter(t, tx, r.intent(r.a), "decision")
				if mode == "reentry" {
					_, err = protocolEnter(r.ctx, tx, r.intent(r.a, r.b), "decision")
					require.Error(t, err)
					return
				}
				if mode == "private-write" {
					_, err = tx.Exec(r.ctx, `UPDATE pg_temp.kaname_authority_attestation SET accounts=ARRAY[$1]`, r.b)
					require.Error(t, err)
					return
				}
				// Настоящий runtime LOGIN не может превратиться в migration owner.
				_, err = tx.Exec(r.ctx, "SET ROLE "+pgx.Identifier{r.admin.Config().ConnConfig.User}.Sanitize())
				require.Error(t, err)
				return
			}
			_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='forged' WHERE false`)
			require.Error(t, err, "BEFORE STATEMENT обязан отказать даже при нуле строк")
		})
	}
	attestationNonceObserver(t, r)
	// Та же физическая connection: COMMIT очищает temp rows, прежний nonce не живёт.
	conn, err := r.runtime.Acquire(r.ctx)
	require.NoError(t, err)
	defer conn.Release()
	var previous string
	for _, commit := range []bool{true, false, true} {
		tx, e := conn.Begin(r.ctx)
		require.NoError(t, e)
		defer attestationLocksetRollback(tx)
		r.enter(t, tx, r.intent(r.a), "decision")
		// Проверку выполняет настоящий guard; observer только показывает nonce.
		_, e = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='fresh-entry' WHERE false`)
		require.NoError(t, e)
		var nonce string
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_attestation_nonce()`).Scan(&nonce))
		require.NotEmpty(t, nonce)
		require.NotEqual(t, previous, nonce)
		previous = nonce
		if commit {
			require.NoError(t, tx.Commit(r.ctx))
		} else {
			require.NoError(t, tx.Rollback(r.ctx))
		}
		tx, e = conn.Begin(r.ctx)
		require.NoError(t, e)
		defer attestationLocksetRollback(tx)
		_, e = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='replay' WHERE false`)
		require.Error(t, e)
		require.NoError(t, tx.Rollback(r.ctx))
	}
}
func TestWriterProtocolChecksBothRowScopesAndGlobalTruncate(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-protocol-a',$1,'protocol-a'),('grp-protocol-b',$2,'protocol-b')`, r.a, r.b)
	require.NoError(t, err)
	r.strict(t)
	for _, mode := range []string{"old", "new", "truncate", "both"} {
		t.Run(mode, func(t *testing.T) {
			tx, e := r.runtime.Begin(r.ctx)
			require.NoError(t, e)
			defer tx.Rollback(context.Background())
			in := r.intent(r.a)
			if mode == "both" {
				in = r.intent(r.a, r.b)
			}
			r.enter(t, tx, in, "decision")
			switch mode {
			case "old":
				_, e = tx.Exec(r.ctx, `UPDATE kaname.groups SET account_id=$1 WHERE id='grp-protocol-b'`, r.a)
			case "new", "both":
				_, e = tx.Exec(r.ctx, `UPDATE kaname.groups SET account_id=$1 WHERE id='grp-protocol-a'`, r.b)
			case "truncate":
				_, e = tx.Exec(r.ctx, `TRUNCATE kaname.groups CASCADE`)
			}
			if mode == "both" {
				require.NoError(t, e)
			} else {
				require.Error(t, e)
			}
		})
	}
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	in := r.intent()
	in.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	r.enter(t, tx, in, "decision")
	_, err = tx.Exec(r.ctx, `TRUNCATE kaname.groups CASCADE`)
	require.NoError(t, err)
}
func TestWriterProtocolFreshOwnershipRestartsAndAccountsRemainParallel(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-protocol-move',$1,'protocol-move')`, r.a)
	require.NoError(t, err)
	first, err := r.repo.TransitionalAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	defer first.Rollback(context.Background())
	other, err := r.repo.TransitionalAuthorityWriter(r.ctx, r.intent(r.b))
	require.NoError(t, err)
	require.NoError(t, other.Rollback(r.ctx))
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	in := r.intent(r.a)
	in.Owners = []kaname.AuthorityOwnerRef{{Kind: "group", ID: "grp-protocol-move"}}
	type answer struct {
		w   kaname.AuthorityWriter
		err error
	}
	result := make(chan answer, 1)
	consumed := false
	defer func() {
		cancel()
		if consumed {
			return
		}
		cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case got := <-result:
			if got.w != nil {
				_ = got.w.Rollback(cleanup)
			}
		case <-cleanup.Done():
			t.Error("ожидающий writer не завершился при cleanup")
		}
	}()
	go func() { w, e := r.repo.TransitionalAuthorityWriter(ctx, in); result <- answer{w, e} }()
	authorityWaitLock(t, r.ctx, r.admin)
	// Ещё допустимый legacy writer меняет ownership, пока новый entry ждёт fence.
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.groups SET account_id=$1 WHERE id='grp-protocol-move'`, r.b)
	require.NoError(t, err)
	var afterWait time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&afterWait))
	require.NoError(t, first.Commit(r.ctx))
	select {
	case got := <-result:
		consumed = true
		if got.w != nil {
			defer got.w.Rollback(context.Background())
		}
		require.NoError(t, got.err)
		require.NotNil(t, got.w)
		require.Equal(t, []domain.AccountID{domain.AccountID(r.b)}, got.w.AuthorityFence().Accounts())
		require.False(t, got.w.AuthorityFence().DecisionAt().Before(afterWait))
		require.NoError(t, got.w.Rollback(r.ctx))
	case <-r.ctx.Done():
		t.Fatal("entry не завершился после освобождения fence")
	}
	authorityWaitReleased(t, r.runtime)
}

// kaname#1034: observer pgx меняет реальный ownership перед каждым entry.
// Это воспроизводит исчерпание restart без sleep и без production test hook.
type protocolChurnTracer struct {
	admin   *pgxpool.Pool
	a, b    string
	calls   atomic.Int32
	failure chan error
}

func (c *protocolChurnTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "SELECT kaname.authority_protocol_enter(") {
		c.calls.Add(1)
		_, err := c.admin.Exec(ctx, `UPDATE kaname.groups SET account_id=CASE account_id WHEN $1 THEN $2 ELSE $1 END WHERE id='grp-protocol-churn'`, c.a, c.b)
		if err != nil {
			select {
			case c.failure <- err:
			default:
			}
		}
	}
	return ctx
}
func (*protocolChurnTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestWriterProtocolBoundedRestartAndCancellationReleaseSlots(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-protocol-churn',$1,'protocol-churn')`, r.a)
	require.NoError(t, err)
	tracer := &protocolChurnTracer{admin: r.admin, a: r.a, b: r.b, failure: make(chan error, 3)}
	config := r.runtime.Config()
	config.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(r.ctx, config)
	require.NoError(t, err)
	defer pool.Close()
	in := r.intent(r.a)
	in.Owners = []kaname.AuthorityOwnerRef{{Kind: "group", ID: "grp-protocol-churn"}}
	out, err := kanamepg.New(pool, nil).TransitionalAuthorityWriter(r.ctx, in)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.Nil(t, out)
	require.Equal(t, int32(3), tracer.calls.Load())
	select {
	case e := <-tracer.failure:
		require.NoError(t, e)
	default:
	}
	authorityWaitReleased(t, pool)
	first, err := r.repo.TransitionalAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	defer first.Rollback(context.Background())
	ctx, cancel := context.WithCancel(r.ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		w, e := r.repo.TransitionalAuthorityWriter(ctx, r.intent(r.a))
		if w != nil {
			_ = w.Rollback(context.Background())
		}
		done <- e
	}()
	authorityWaitLock(t, r.ctx, r.admin)
	cancel()
	select {
	case e := <-done:
		require.ErrorIs(t, e, context.Canceled)
	case <-r.ctx.Done():
		t.Fatal("отменённый entry не завершился")
	}
	require.NoError(t, first.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
func TestWriterProtocolRejectsInvalidIntentBeforePool(t *testing.T) {
	r := writerProtocolRig(t)
	for _, mode := range []string{"kind", "global-kind", "missing-owners", "owner-kind", "empty-owner", "oversized", "nil-bundle"} {
		t.Run(mode, func(t *testing.T) {
			in := r.intent(r.a)
			switch mode {
			case "kind":
				in.Kind = "invented"
			case "global-kind":
				in.Kind = kaname.AuthorityIdentity
			case "missing-owners":
				in.Owners = nil
			case "owner-kind":
				in.Owners[0].Kind = "unknown"
			case "empty-owner":
				in.Owners[0].ID = ""
			case "oversized":
				in.Owners = make([]kaname.AuthorityOwnerRef, kaname.MaxAuthorityOwnershipRefs+1)
			case "nil-bundle":
				in.Bundle = nil
			}
			w, err := kanamepg.New(nil, nil).CoordinatedAuthorityWriter(context.Background(), in)
			require.Error(t, err)
			require.Nil(t, w)
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w, err := kanamepg.New(nil, nil).TransitionalAuthorityWriter(ctx, r.intent(r.a))
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, w)
}

// kaname#1034: cascades после удаления parent требуют заранее выбранного global.
// Это консервативная граница core, не обещание account-parallel Role.Delete.
func TestWriterProtocolRoleDeleteCascadeUsesGlobalIntent(t *testing.T) {
	r := writerProtocolRig(t)
	owner := kanamepg.New(r.admin, nil)
	role := seedCustomRole(t, r.ctx, owner, domain.AccountID(r.a), "protocol_cascade_owner")
	target := seedCustomRole(t, r.ctx, owner, domain.AccountID(r.b), "protocol_cascade_target")
	require.NoError(t, writeGrantProjection(t, r.ctx, owner, role.ID, []domain.GrantCapabilityRule{grantCreate("a"), grantBind("b", target.ID)}))
	before := grantProjectionRows(t, r.ctx, r.admin, role.ID)
	require.Len(t, before, 2)
	r.strict(t)
	in := r.intent(r.a)
	in.Kind = kaname.AuthorityRole
	in.Owners = []kaname.AuthorityOwnerRef{{Kind: "role", ID: string(role.ID)}}
	local, err := r.repo.CoordinatedAuthorityWriter(r.ctx, in)
	require.NoError(t, err)
	require.Error(t, local.RolesW().Delete(r.ctx, role.ID), "parent cascade требует global до row locks, scope не угадывается")
	require.NoError(t, local.Rollback(r.ctx))
	require.Equal(t, before, grantProjectionRows(t, r.ctx, r.admin, role.ID), "отказ откатывает parent и оба children")
	in.Plan = kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}
	global, err := r.repo.CoordinatedAuthorityWriter(r.ctx, in)
	require.NoError(t, err)
	defer global.Rollback(context.Background())
	require.NoError(t, global.RolesW().Delete(r.ctx, role.ID))
	require.NoError(t, global.Commit(r.ctx))
	require.Empty(t, grantProjectionRows(t, r.ctx, r.admin, role.ID))
	var count int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.roles WHERE id=$1`, string(role.ID)).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.roles WHERE id=$1`, string(target.ID)).Scan(&count))
	require.Equal(t, 1, count, "ссылка удалена каскадом; независимая target role сохранена")
	authorityWaitReleased(t, r.runtime)
}

// kaname#1034: полноценная forged witness и temp shadows не удостоверяют owner
// и fences. Проба вызывает raw mutation без entry под настоящим runtime LOGIN.
func TestWriterProtocolTempCatalogShadowCannotForgeAttestation(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-protocol-shadow',$1,'protocol-shadow')`, r.a)
	require.NoError(t, err)
	var ownerOID uint32
	var ownerName string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT c.relowner,r.rolname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_roles r ON r.oid=c.relowner WHERE c.oid='kaname.authority_writer_protocol'::regclass`).Scan(&ownerOID, &ownerName))
	r.strict(t)
	conn, err := r.runtime.Acquire(r.ctx)
	require.NoError(t, err)
	defer conn.Release()
	tx, err := conn.Begin(r.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	// Все поля proof соответствуют текущей TX/identity. Ложны только owner и lock.
	_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_attestation AS
 SELECT true AS singleton,pg_backend_pid() AS backend,pg_current_xact_id() AS transaction_id,
 (SELECT oid FROM pg_catalog.pg_roles WHERE rolname=current_user) AS invoker_oid,
 gen_random_uuid() AS nonce,protocol_version AS protocol,model_id,catalog_id,projector_version,
 'global'::text AS mode,ARRAY[]::text[] AS accounts,'group'::text AS kind,
 'decision'::text AS purpose,clock_timestamp() AS decision_at
 FROM kaname.authority_semantic_identity WHERE singleton;
 CREATE TEMP TABLE pg_class AS SELECT * FROM pg_catalog.pg_class WHERE oid='pg_temp.kaname_authority_attestation'::regclass;
 CREATE TEMP TABLE pg_locks AS SELECT * FROM pg_catalog.pg_locks WHERE false;
 CREATE TEMP TABLE pg_roles AS SELECT * FROM pg_catalog.pg_roles;
 CREATE TEMP TABLE pg_database AS SELECT * FROM pg_catalog.pg_database WHERE datname=current_database()`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `UPDATE pg_temp.pg_class SET relowner=$1`, ownerOID)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `INSERT INTO pg_temp.pg_locks(locktype,database,classid,objid,objsubid,pid,mode,granted)
 VALUES('advisory',(SELECT oid FROM pg_catalog.pg_database WHERE datname=current_database()),1262569283,0,2,pg_backend_pid(),'ExclusiveLock',true)`)
	require.NoError(t, err)
	// Не рассчитываем на superuser owner: definer получает SELECT на подделки.
	_, err = tx.Exec(r.ctx, "GRANT SELECT ON pg_temp.kaname_authority_attestation,pg_temp.pg_class,pg_temp.pg_locks,pg_temp.pg_roles,pg_temp.pg_database TO "+pgx.Identifier{ownerName}.Sanitize())
	require.NoError(t, err)
	var held int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory'`).Scan(&held))
	require.Zero(t, held, "настоящего fence нет; fake pg_locks объявляет обратное")
	var falseOwner uint32
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT relowner FROM pg_temp.pg_class`).Scan(&falseOwner))
	require.Equal(t, ownerOID, falseOwner)
	_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='forged' WHERE id='grp-protocol-shadow'`)
	require.ErrorContains(t, err, "untrusted authority attestation storage")
	require.NoError(t, tx.Rollback(r.ctx))
	// Rollback убирает shadows. Нормальный entry на той же connection работает.
	tx, err = conn.Begin(r.ctx)
	require.NoError(t, err)
	r.enter(t, tx, r.intent(r.a), "decision")
	_, err = tx.Exec(r.ctx, `UPDATE kaname.groups SET description='legitimate' WHERE id='grp-protocol-shadow'`)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(r.ctx))
	var description string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.groups WHERE id='grp-protocol-shadow'`).Scan(&description))
	require.Equal(t, "legitimate", description)
}

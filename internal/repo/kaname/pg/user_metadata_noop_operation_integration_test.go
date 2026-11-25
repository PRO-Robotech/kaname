// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto/toproto"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestUserMetadataNoopOperationCommit(t *testing.T) {
	var uid, actor string
	w := metadataFixture(t, false, func(r protocolRig) {
		uid = seedMemberUser(t, r.ctx, r.admin, r.a, "user-noop-target")
		actor = seedMemberUser(t, r.ctx, r.admin, r.a, "user-noop-admin")
		_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET labels='{"team":"blue"}' WHERE id=$1`, uid)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.memberships(id,user_id,account_id,state)
			VALUES(kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE')`, uid, r.b)
		require.NoError(t, err)
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		defer policyFixtureRollback(tx)
		_, created, err := kanamepg.NewClusterAdminGrantWriter(r.admin).Grant(r.ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(actor), bindingPublicOwner(t, r))
		require.NoError(t, err)
		require.True(t, created)
		facts := append(fgaTuplesGrantSystemAdmin(actor),
			service.RelationTuple{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:" + r.a},
			service.RelationTuple{User: "account:" + r.a, Relation: "account", Object: "iam_user:" + uid},
			service.RelationTuple{User: "cluster:" + domain.ClusterSingletonID, Relation: "cluster", Object: "account:" + r.b},
			service.RelationTuple{User: "account:" + r.b, Relation: "account", Object: "iam_user:" + uid})
		require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(r.ctx, tx, facts))
		require.NoError(t, tx.Commit(r.ctx))
	})
	r := w.r
	for _, sig := range []string{
		"_authority_metadata_user_noop_reserve_v1(text,timestamptz,bytea,text,text,text,text,integer,integer)",
		"_authority_metadata_user_noop_complete_v1(text,uuid,timestamptz,bytea)",
		"_authority_metadata_user_noop_transition_v1(text,jsonb,jsonb)",
		"_authority_metadata_user_noop_commit_v1()",
	} {
		var private bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT NOT has_function_privilege(current_user,p.oid,'EXECUTE')
			AND NOT EXISTS(SELECT FROM aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a WHERE a.grantee<>p.proowner)
			FROM pg_proc p WHERE p.oid=to_regprocedure($1)`, "kaname."+sig).Scan(&private))
		require.True(t, private, sig)
	}
	const shims = "kaname.test_user_noop_prepare(text,jsonb,jsonb,jsonb,text,text)," +
		"kaname.test_user_noop_reserve(text,timestamptz,bytea,text,text,text,text,integer,integer)," +
		"kaname.test_user_noop_complete(text,uuid,timestamptz,bytea)"
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_user_noop_prepare(uid text,image jsonb,members jsonb,patch jsonb,actor_type text,actor_id text)
		RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
		DECLARE proof jsonb; target jsonb;
		BEGIN
			proof:=kaname.authority_protocol_attestation();
			target:=kaname._authority_metadata_user_patch_target_v1(uid,image->>0,image->>1,image->2,members,patch,actor_type,actor_id,1024,128);
			PERFORM kaname._authority_metadata_access_label_stash_v1(jsonb_build_object('root',target,'discovery','{}'::jsonb,'plan',proof,'catalog_id',proof->'catalog_id'));
		END $$;
		CREATE FUNCTION kaname.test_user_noop_reserve(text,timestamptz,bytea,text,text,text,text,integer,integer) RETURNS jsonb
		LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
			SELECT kaname._authority_metadata_user_noop_reserve_v1($1,$2,$3,$4,$5,$6,$7,$8,$9) $$;
		CREATE FUNCTION kaname.test_user_noop_complete(text,uuid,timestamptz,bytea) RETURNS kaname.operations
		LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
			SELECT * FROM kaname._authority_metadata_user_noop_complete_v1($1,$2,$3,$4) $$;
		REVOKE ALL ON FUNCTION `+shims+` FROM PUBLIC;
		GRANT EXECUTE ON FUNCTION `+shims+` TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	create := func(subject string) operations.Operation {
		t.Helper()
		principal := operations.Principal{Type: "user", ID: subject, DisplayName: "operator"}
		op, err := operations.NewFromContext(operations.WithPrincipal(r.ctx, principal), domain.PrefixOperationIAM, "Update user "+uid,
			&iamv1.UpdateUserMetadata{UserId: uid, AccountId: r.a, ProtectedLabels: true})
		require.NoError(t, err)
		op.CreatedAt = time.Now().UTC().Truncate(time.Microsecond)
		_, err = r.admin.Exec(r.ctx, `SELECT kaname._authority_user_access_labels_operation_create_v1($1,$2,$3,$4,$5,$6,$7,$8)`,
			op.ID, op.CreatedAt, uid, r.a, op.Metadata.Value, principal.Type, subject, principal.DisplayName)
		require.NoError(t, err)
		return op
	}
	snapshot := func() string {
		t.Helper()
		var s string
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_array(u.xmin::text,u.ctid::text,to_jsonb(u),
			(SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='iam_user' AND resource_id=u.id),
			(SELECT count(*) FROM kaname.audit_outbox),(SELECT count(*) FROM kaname.resource_reconcile_outbox),
			(SELECT count(*) FROM kaname.authority_access_label_dirty_root),(SELECT count(*) FROM kaname.authority_access_label_dirty_fact),
			(SELECT revision FROM kaname.authority_policy_epoch WHERE key='user:'||u.id),
			(SELECT revision FROM kaname.authority_binding_epoch WHERE scope=''))::text FROM ONLY kaname.users u WHERE u.id=$1`, uid).Scan(&s))
		return s
	}
	before := snapshot()
	const patch = `{"access_labels":{},"labels":{"team":"blue"}}`
	pending := func(op operations.Operation) {
		t.Helper()
		var pristine bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT NOT done AND response_data IS NULL AND error_code IS NULL FROM ONLY kaname.operations WHERE id=$1`, op.ID).Scan(&pristine))
		require.True(t, pristine)
	}
	denied := create(w.outsider)
	_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, denied, uid, r.a, []byte(patch), nil, "commit")
	require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
	pending(denied)

	// Без owner-команды обычный MarkDone сохраняет Interrupted. Затем
	// нативный writer видит завершённую строку и пропускает terminal CAS.
	interrupted := create(actor)
	legacyResponse, err := anypb.New(&iamv1.User{Id: uid})
	require.NoError(t, err)
	require.ErrorIs(t, w.ops.MarkDone(r.ctx, interrupted.ID, legacyResponse), operations.ErrAlreadyDone)
	var interruptedCode int
	require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT error_code FROM kaname.operations WHERE id=$1 AND done AND response_data IS NULL", interrupted.ID).Scan(&interruptedCode))
	require.Equal(t, 13, interruptedCode)
	_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, interrupted, uid, r.a, []byte(patch), nil, "commit")
	assertSQLState(t, err, "40001")
	op := create(actor)
	for _, mode := range []string{"rollback", "replay", "omit", "wrong nonce", "wrong operation", "wrong clock"} {
		_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, op, uid, r.a, []byte(patch), nil, mode)
		if mode == "rollback" {
			require.NoError(t, err)
		} else {
			assertSQLState(t, err, "42501")
		}
		pending(op)
	}
	for _, changed := range []string{`{"access_labels":{"zone":"internal"}}`, `{"access_labels":{},"labels":{}}`} {
		_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, op, uid, r.a, []byte(changed), nil, "commit")
		assertSQLState(t, err, "42501")
		pending(op)
	}
	wrong := op
	wrong.Metadata = proto.Clone(op.Metadata).(*anypb.Any)
	wrong.Metadata.Value = append(wrong.Metadata.Value, 0)
	_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, wrong, uid, r.a, []byte(patch), nil, "commit")
	assertSQLState(t, err, "40001")
	pending(op)

	// Recovery первым запер строку. NOWAIT писателя сохраняет pending и его версию.
	other, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(other)
	_, err = other.Exec(r.ctx, `SELECT id FROM ONLY kaname.operations WHERE id=$1 FOR UPDATE`, op.ID)
	require.NoError(t, err)
	_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, op, uid, r.a, []byte(patch), nil, "commit")
	assertSQLState(t, err, "40001")
	require.NoError(t, other.Rollback(r.ctx))
	pending(op)

	// При обратном порядке competing terminal CAS упирается в лок writer.
	afterReserve := func(tx pgx.Tx, nonce string) error {
		other, e := r.admin.Begin(r.ctx)
		require.NoError(t, e)
		defer policyFixtureRollback(other)
		_, e = other.Exec(r.ctx, `SET LOCAL lock_timeout='150ms'`)
		require.NoError(t, e)
		_, e = other.Exec(r.ctx, `UPDATE ONLY kaname.operations SET done=true,error_code=13 WHERE id=$1 AND NOT done`, op.ID)
		assertSQLState(t, e, "55P03")
		probe, e := tx.Begin(r.ctx)
		require.NoError(t, e)
		_, e = probe.Exec(r.ctx, `SELECT * FROM kaname.test_user_noop_complete($1,$2,clock_timestamp(),'premature'::bytea)`, op.ID, nonce)
		assertSQLState(t, e, "42501")
		return probe.Rollback(r.ctx)
	}
	response, err := kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, op, uid, r.a, []byte(patch), afterReserve, "commit")
	require.NoError(t, err)
	saved, err := operations.NewRepo(r.runtime, "kaname").GetOwned(r.ctx, op.ID, operations.Owner{PrincipalType: "user", PrincipalID: actor})
	require.NoError(t, err)
	require.True(t, saved.Done)
	require.True(t, proto.Equal(op.Metadata, saved.Metadata))
	require.True(t, proto.Equal(response, saved.Response))
	rd, err := w.full.Reader(r.ctx)
	require.NoError(t, err)
	actual, err := rd.Users().Get(r.ctx, domain.UserID(uid))
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(r.ctx))
	want, err := toproto.MarshalUserOperationResponse(actual)
	require.NoError(t, err)
	var wantUser iamv1.User
	require.NoError(t, want.UnmarshalTo(&wantUser))
	var user iamv1.User
	require.NoError(t, saved.Response.UnmarshalTo(&user))
	require.True(t, proto.Equal(&wantUser, &user))
	require.Equal(t, uid, user.Id)
	require.Equal(t, map[string]string{"team": "blue"}, user.Labels)
	require.NotEmpty(t, user.Email)
	require.Equal(t, before, snapshot())
	_, err = kanamepg.ProbeUserMetadataNoop(r.ctx, w.factory, op, uid, r.a, []byte(patch), nil, "commit")
	assertSQLState(t, err, "40001")
	require.Equal(t, before, snapshot())
}

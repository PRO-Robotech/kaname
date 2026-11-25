// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const userMetadataCreateFacade = "kaname.authority_user_access_labels_operation_create_v1(text,timestamptz,text,text,bytea,text,text,text)"

func TestUserMetadataOperationCreateRespectsEffectiveInsertRole(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	uid := seedMemberUser(t, r.ctx, r.admin, r.a, "user-pending-enrollment")
	ordinary := r.role + "_pending"
	quoted := pgx.Identifier{ordinary}.Sanitize()
	_, err := r.admin.Exec(r.ctx, "CREATE ROLE "+quoted+" LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.admin.Exec(ctx, "DROP OWNED BY "+quoted)
		_, _ = r.admin.Exec(ctx, "DROP ROLE "+quoted)
	})
	enrolled := r
	enrolled.role = ordinary
	pool, executor, _ := roleActorFiniteLogin(t, enrolled)
	seat := pgx.Identifier{executor}.Sanitize()
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION "+userMetadataCreateFacade+" TO "+seat+","+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)

	const probe = `SELECT kaname.authority_user_access_labels_operation_create_v1(
		'',clock_timestamp(),'','',decode('01','hex'),'user','usr-probe','')`
	check := func(want string) {
		t.Helper()
		_, err := pool.Exec(r.ctx, probe)
		requireAccessDefinitionSQLState(t, err, want)
	}

	_, err = r.admin.Exec(r.ctx, `GRANT USAGE ON SCHEMA kaname TO `+quoted+`;
		GRANT SELECT ON kaname.users TO `+quoted+`;
		GRANT INSERT(id,description,created_at,created_by,modified_at,done,metadata_type,metadata_data,
			resource_id,account_id,principal_type,principal_id) ON kaname.operations TO `+quoted)
	require.NoError(t, err)
	check("42501")
	_, err = r.admin.Exec(r.ctx, "GRANT INSERT(principal_display_name) ON kaname.operations TO "+quoted)
	require.NoError(t, err)
	check("22023")
	_, err = r.admin.Exec(r.ctx, "REVOKE SELECT ON kaname.users FROM "+quoted)
	require.NoError(t, err)
	check("42501")
	_, err = r.admin.Exec(r.ctx, "GRANT SELECT ON kaname.users TO "+quoted)
	require.NoError(t, err)

	_, err = r.runtime.Exec(r.ctx, probe)
	requireAccessDefinitionSQLState(t, err, "42501")
	impersonation, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, impersonation)
	_, err = impersonation.Exec(r.ctx, "SET LOCAL ROLE "+seat)
	require.NoError(t, err)
	_, err = impersonation.Exec(r.ctx, probe)
	requireAccessDefinitionSQLState(t, err, "42501")
	require.NoError(t, impersonation.Rollback(r.ctx))

	var canWrite bool
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT has_any_column_privilege(current_user,'kaname.operations','INSERT')`).Scan(&canWrite))
	require.False(t, canWrite)
	const create = `SELECT kaname.authority_user_access_labels_operation_create_v1($1,clock_timestamp(),$2,$3,decode('01','hex'),'user',$2,'')`
	id := ids.NewID(domain.PrefixOperationIAM)
	lock, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, lock)
	_, err = lock.Exec(r.ctx, "SELECT FROM ONLY kaname.authority_role_actor_login WHERE singleton FOR UPDATE")
	require.NoError(t, err)
	_, err = pool.Exec(r.ctx, create, id, uid, r.a)
	requireAccessDefinitionSQLState(t, err, "55P03")
	require.NoError(t, lock.Rollback(r.ctx))
	var exists bool
	require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT EXISTS(SELECT FROM kaname.operations WHERE id=$1)", id).Scan(&exists))
	require.False(t, exists)
	_, err = pool.Exec(r.ctx, create, id, uid, r.a)
	require.NoError(t, err)
	require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT user_access_labels AND NOT done FROM kaname.operations WHERE id=$1", id).Scan(&exists))
	require.True(t, exists)
}

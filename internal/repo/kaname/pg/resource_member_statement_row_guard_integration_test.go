// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Синтаксическое UPDATE право текущего members UPSERT не даёт права
// менять чужую actual строку: row image остаётся отдельным обязательством.
func TestResourcePublicRunMemberStatementDoesNotAuthorizeForeignRow(t *testing.T) {
	const objectA = "public-row-guard-A"
	const objectB = "public-row-guard-B"
	f := newResourcePublicFixtureWithNames(t, 1, [2][]string{{objectA}, {objectB}})
	ctx, cancel := context.WithTimeout(f.ctx, 60*time.Second)
	defer cancel()

	var runtimeUser, sessionUser string
	require.NoError(t, f.r.runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&runtimeUser, &sessionUser))
	require.Equal(t, f.r.role, runtimeUser)
	require.Equal(t, runtimeUser, sessionUser)

	// B создаётся штатным Register и его postcommit Object materializer.
	require.NoError(t, f.uc.Register(ctx, f.request(1, objectB, time.Now().UTC())))
	f.native(t, 1, objectB, true)
	var count int
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members
WHERE binding_id=$1 AND object_type='vpc.network' AND object_id=$2 AND verification_status='ACTIVE'`, f.bindings[1], objectB).Scan(&count))
	require.Equal(t, 1, count, "инъектор обязан встретить настоящую чужую ACTIVE строку")
	var beforeB string
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT to_jsonb(m)::text FROM kaname.access_binding_target_members m
WHERE binding_id=$1 AND object_type='vpc.network' AND object_id=$2`, f.bindings[1], objectB).Scan(&beforeB))

	// Владелец только ставит инъектор. UPDATE исполняется SECURITY INVOKER
	// внутри той же genuine runtime TX, без дополнительных grants/manifest.
	_, err := f.r.admin.Exec(ctx, `CREATE FUNCTION kaname.resource_public_foreign_member_update()
RETURNS trigger LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.object_type='vpc.network' AND NEW.object_id='public-row-guard-A' THEN
  UPDATE kaname.access_binding_target_members SET verification_status='REJECTED'
   WHERE object_type='vpc.network' AND object_id='public-row-guard-B';
  IF NOT FOUND THEN RAISE EXCEPTION 'foreign member fault target missing'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION kaname.resource_public_foreign_member_update() FROM PUBLIC;
CREATE TRIGGER resource_public_foreign_member_update BEFORE INSERT ON kaname.access_binding_target_members
FOR EACH ROW EXECUTE FUNCTION kaname.resource_public_foreign_member_update()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, cleanupErr := f.r.admin.Exec(cleanupCtx, `DROP TRIGGER IF EXISTS resource_public_foreign_member_update ON kaname.access_binding_target_members;
DROP FUNCTION IF EXISTS kaname.resource_public_foreign_member_update()`)
		require.NoError(t, cleanupErr)
	})

	// Register может успешно commit и лишь залогировать postcommit отказ.
	// Поэтому проверяем отдельный публичный Object вызов и его raw причину.
	require.NoError(t, f.uc.Register(ctx, f.request(0, objectA, time.Now().UTC())))
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.access_binding_target_members
WHERE object_type='vpc.network' AND object_id=$1`, objectA).Scan(&count))
	require.Zero(t, count, "A должен оставаться fresh INSERT для явного Object вызова")
	before := resourcePublicSnapshot(t, f.r)
	err = f.engine.ReconcileObject(ctx, "vpc.network", objectA)
	require.Error(t, err)
	var pgerr *pgconn.PgError
	require.True(t, errors.As(err, &pgerr), "нужна raw SQL причина: %s", resourcePublicErrorDetails(err))
	require.Equal(t, "42501", pgerr.Code)
	require.Equal(t, "resource row absent from private manifest", pgerr.Message)
	require.Contains(t, pgerr.Where, "_authority_resource_before_write_v3")
	require.Contains(t, pgerr.Where, "authority_protocol_row_guard")
	require.Contains(t, pgerr.Where, "resource_public_foreign_member_update")
	authorityWaitReleased(t, f.r.runtime)
	require.Equal(t, before, resourcePublicSnapshot(t, f.r), "отказ откатывает все Object effects")
	var afterB string
	require.NoError(t, f.r.admin.QueryRow(ctx, `SELECT to_jsonb(m)::text FROM kaname.access_binding_target_members m
WHERE binding_id=$1 AND object_type='vpc.network' AND object_id=$2`, f.bindings[1], objectB).Scan(&afterB))
	require.Equal(t, beforeB, afterB, "полный образ B неизменен после обоих отказавших Object attempts")
	f.native(t, 1, objectB, true)
	// Register уже создал canonical scope; live grant arm проверяет роль и names,
	// не target_members. Отказ Object не отзывает эту законную выдачу A.
	f.native(t, 0, objectA, true)
}

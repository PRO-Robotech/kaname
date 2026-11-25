// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func seedWorkerGenerationGroup(t *testing.T, r protocolRig, account string) domain.Group {
	t.Helper()
	g := domain.Group{ID: domain.GroupID(ids.NewID(domain.PrefixGroup)), AccountID: domain.AccountID(account),
		Name: "generation-worker-group", Labels: domain.Labels{}}
	factory, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	w, err := factory.GroupLifecycleWriter(r.ctx, kaname.GroupCreate, g)
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	group, err := w.GroupsW().Insert(r.ctx, g)
	require.NoError(t, err)
	require.NoError(t, w.EmitFGARelationWrite(r.ctx, []service.RelationTuple{{
		User: "account:" + account, Relation: "account", Object: "iam_group:" + string(group.ID),
	}}))
	require.NoError(t, w.EmitReconcileEvent(r.ctx, shared.ReconcileEventUpsert, "iam.group", string(group.ID)))
	require.NoError(t, w.Commit(r.ctx))
	return group
}

// Поколение группы может обнаружиться при пересчёте её выхода в другом аккаунте.
// Штатный объектный worker обязан включить группу в граф даже в отсутствие
// собственного dirty fact по координате iam_group.
func TestResourceObjectWorkerRetiresExistingGroupGeneration(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	r := f.r
	group := seedWorkerGenerationGroup(t, r, f.scenes[0].Account)
	require.NotEqual(t, f.scenes[0].Account, f.scenes[1].Account)

	seedGeneration := func(t *testing.T, groupID, projectID, labels string) string {
		t.Helper()
		var generation string
		require.NoError(t, r.admin.QueryRow(r.ctx, `WITH root AS (
			INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
			VALUES ('iam.group',$1,gen_random_uuid(),$3::jsonb) RETURNING root_type,root_id,generation
		) INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
			SELECT root_type,root_id,generation,'project',$2,'viewer','user:group-generation' FROM root
			RETURNING generation::text`, groupID, projectID, labels).Scan(&generation))
		return generation
	}
	requireGeneration := func(t *testing.T, groupID, projectID, generation string, pending bool) {
		t.Helper()
		var root, fact bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
			EXISTS(SELECT FROM ONLY kaname.authority_access_label_dirty_root
				WHERE root_type='iam.group' AND root_id=$1 AND generation=$3::uuid),
			EXISTS(SELECT FROM ONLY kaname.authority_access_label_dirty_fact
				WHERE root_type='iam.group' AND root_id=$1 AND generation=$3::uuid AND object_type='project'
				AND object_id=$2 AND relation='viewer' AND subject='user:group-generation')`,
			groupID, projectID, generation).Scan(&root, &fact))
		require.Equal(t, pending, root)
		require.Equal(t, pending, fact)

		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		for _, ref := range [][2]string{{"iam_group", groupID}, {"project", projectID}} {
			var observed bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT pending FROM kaname.authority_resource_reconcile_pending_v1($1,$2,1,2)`,
				ref[0], ref[1]).Scan(&observed))
			require.Equal(t, pending, observed, "%s:%s", ref[0], ref[1])
		}
	}

	groupID, projectID := string(group.ID), f.scenes[1].Project
	generation := seedGeneration(t, groupID, projectID, "{}")
	requireGeneration(t, groupID, projectID, generation, true)
	resourcePublicRequireNoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", projectID))
	requireGeneration(t, groupID, projectID, generation, false)
	// Повтор уже обработанного события видит чистый снимок.
	resourcePublicRequireNoError(t, f.engine.ReconcileObject(r.ctx, "iam.project", projectID))

	t.Run("changed Group labels", func(t *testing.T) {
		generation := seedGeneration(t, groupID, projectID, `{"team":"previous"}`)
		err := f.engine.ReconcileObject(r.ctx, "iam.project", projectID)
		var pgErr *pgconn.PgError
		require.ErrorAs(t, err, &pgErr, "%s", resourcePublicErrorDetails(err))
		require.Equal(t, "42501", pgErr.Code)
		require.Contains(t, pgErr.Message, "group generation held account or labels differ")
		requireGeneration(t, groupID, projectID, generation, true)
	})
	t.Run("missing Group", func(t *testing.T) {
		missing, otherProject := ids.NewID(domain.PrefixGroup), f.scenes[0].Project
		generation := seedGeneration(t, missing, otherProject, "{}")
		require.Error(t, f.engine.ReconcileObject(r.ctx, "iam.project", otherProject))
		requireGeneration(t, missing, otherProject, generation, true)
	})
	authorityWaitReleased(t, r.runtime)
}

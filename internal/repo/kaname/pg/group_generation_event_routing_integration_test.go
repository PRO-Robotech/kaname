// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestFullBackgroundGroupEventRetiresOnlyExistingGroup(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	r := f.r
	g := seedWorkerGenerationGroup(t, r, f.scenes[0].Account)
	catalog := rolePolicyCatalog(t, r)
	background := reconcile.New(kanamepg.NewReconcileAdapter(r.runtime, catalog), slog.Default(), catalog)
	membership, err := kanamepg.NewGroupMembershipParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	groups, err := membership.NewGroupObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, background.WithObjectReconciler(f.engine))
	require.NoError(t, background.WithBackgroundGroupObjectReconciler(groups))

	// Направляем тот же тип и идентификатор, которые записал lifecycle writer.
	var typ, id string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT object_type,object_id FROM kaname.resource_reconcile_outbox
		WHERE object_type='iam.group' AND object_id=$1 ORDER BY id DESC LIMIT 1`, g.ID).Scan(&typ, &id))
	var generation string
	require.NoError(t, r.admin.QueryRow(r.ctx, `WITH root AS (
		INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
		VALUES ('iam.group',$1,gen_random_uuid(),'{}') RETURNING root_type,root_id,generation
	) INSERT INTO kaname.authority_access_label_dirty_fact(root_type,root_id,generation,object_type,object_id,relation,subject)
		SELECT root_type,root_id,generation,'project',$2,'viewer','user:direct-group-event' FROM root
		RETURNING generation::text`, id, f.scenes[1].Project).Scan(&generation))
	resourcePublicRequireNoError(t, background.ReconcileObject(r.ctx, typ, id))
	var remaining bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
		EXISTS(SELECT FROM kaname.authority_access_label_dirty_root WHERE generation=$1::uuid) OR
		EXISTS(SELECT FROM kaname.authority_access_label_dirty_fact WHERE generation=$1::uuid)`, generation).Scan(&remaining))
	require.False(t, remaining)
	// Повтор без поколения обслуживает обычный membership writer.
	resourcePublicRequireNoError(t, background.ReconcileObject(r.ctx, typ, id))

	missing := ids.NewID(domain.PrefixGroup)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root(root_type,root_id,generation,new_labels)
		VALUES ('iam.group',$1,gen_random_uuid(),'{}')`, missing)
	require.NoError(t, err)
	require.ErrorIs(t, background.ReconcileObject(r.ctx, "iam.group", missing), kaname.ErrAccessLabelReconcilePending)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT FROM kaname.authority_access_label_dirty_root
		WHERE root_type='iam.group' AND root_id=$1)`, missing).Scan(&remaining))
	require.True(t, remaining)
	authorityWaitReleased(t, r.runtime)
}

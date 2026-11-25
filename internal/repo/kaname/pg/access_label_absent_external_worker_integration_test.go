// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestResourceObjectAbsentExternalGeneration(t *testing.T) {
	f := newResourcePublicFixture(t, 1)
	r := f.r
	const root = "absent-generation-retired"
	const other = "absent-generation-unregistered"
	const noScope = "absent-generation-no-scope"
	version := time.Now().UTC().Truncate(time.Microsecond)

	// Штатное снятие удаляет зеркало и сохраняет область регистрации.
	// Отдельная запись retirement не является условием допуска воркера.
	retire := func(scene int, id string) {
		t.Helper()
		req := f.request(scene, id, version)
		require.NoError(t, f.uc.Register(f.ctx, req))
		require.NoError(t, f.uc.Unregister(f.ctx, &iamv1.UnregisterResourceRequest{
			SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object,
			SourceVersion: timestamppb.New(version.Add(time.Second)),
		}))
		var mirror, scope bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT FROM kaname.resource_mirror WHERE object_type='vpc.network' AND object_id=$1),
 EXISTS(SELECT FROM kaname.resource_registration_scope WHERE object_type='vpc_network' AND object_id=$1 AND project_id=$2 AND account_id=$3)`,
			id, f.scenes[scene].Project, f.scenes[scene].Account).Scan(&mirror, &scope))
		require.False(t, mirror)
		require.True(t, scope)
	}
	retire(0, root)
	// У чужого выхода есть собственная настоящая область: один K4
	// не превращает координату в исходный корень поколения.
	retire(1, other)

	// Владелец задаёт состояние поколения после удаления. Обработчик вызывается
	// через обычный ReconcileObject с отдельным runtime LOGIN.
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels)
 VALUES ('vpc.network',$1,gen_random_uuid(),'{}'),('vpc.network',$2,gen_random_uuid(),'{}')`, root, noScope)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact
 (root_type,root_id,generation,object_type,object_id,relation,subject)
 SELECT root_type,root_id,generation,'vpc_network',$2,'viewer','user:absent-generation'
 FROM kaname.authority_access_label_dirty_root WHERE root_type='vpc.network' AND root_id=$1`, root, other)
	require.NoError(t, err)
	counts := func(id string) (int, int) {
		t.Helper()
		var roots, facts int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.authority_access_label_dirty_root WHERE root_type='vpc.network' AND root_id=$1),
 (SELECT count(*) FROM kaname.authority_access_label_dirty_fact WHERE root_type='vpc.network' AND root_id=$1)`,
			id).Scan(&roots, &facts))
		return roots, facts
	}

	require.ErrorIs(t, f.engine.ReconcileObject(r.ctx, "vpc.network", noScope), kaname.ErrAccessLabelReconcilePending)
	require.ErrorIs(t, f.engine.ReconcileObject(r.ctx, "vpc.network", other), kaname.ErrAccessLabelReconcilePending)
	roots, facts := counts(root)
	require.Equal(t, 1, roots)
	require.Equal(t, 1, facts)

	resourcePublicRequireNoError(t, f.engine.ReconcileObject(r.ctx, "vpc.network", root))
	roots, facts = counts(root)
	require.Zero(t, roots)
	require.Zero(t, facts)
	roots, facts = counts(noScope)
	require.Equal(t, 1, roots)
	require.Zero(t, facts)
}

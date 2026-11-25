// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
	"github.com/stretchr/testify/require"
)

func seedNestedProjectEdge(t *testing.T, r protocolRig, project domain.ProjectID) {
	t.Helper()
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,labels)
		VALUES ('iam.project',$1,$2,'{"team":"blue"}')`, project, r.a)
	require.NoError(t, err)
	tag, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT p.object_type,$1,a.object_type,$2,1 FROM ONLY kaname.catalog_resource p CROSS JOIN ONLY kaname.catalog_resource a
		WHERE p.dotted='iam.project' AND p.live AND a.dotted='iam.account' AND a.live`, project, r.a)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}

// Полный проход ReconcileBinding получает обычную метку из зеркала, а защищённую
// из собственной строки, куда её записал штатный Project.Update.
func TestRoleSelectorMoveNestedProjectReadsProtectedNativePairs(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	project := seedMetadataActualProject(t, r, "nested-native-label")
	seedNestedProjectEdge(t, r, project.ID)
	// Ребро с тем же ребёнком не вправе заимствовать метку у чужого аккаунта.
	tag, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth)
		SELECT p.object_type,$1,a.object_type,$2,1 FROM ONLY kaname.catalog_resource p CROSS JOIN ONLY kaname.catalog_resource a
		WHERE p.dotted='iam.project' AND p.live AND a.dotted='iam.account' AND a.live`, project.ID, r.b)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	pendingSourceApplyProjectLabel(t, r, owner, actor, project.ID)
	var mirror, native string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT m.access_labels::text,p.access_labels::text
		FROM ONLY kaname.resource_mirror m JOIN ONLY kaname.projects p ON p.id=m.object_id
		WHERE p.id=$1 AND m.object_type='iam.project'`, project.ID).Scan(&mirror, &native))
	require.JSONEq(t, "{}", mirror)
	require.JSONEq(t, `{"team":"blue"}`, native)
	for _, accounts := range [][]string{{r.a}, {r.b}, {r.a, r.b}} {
		rows, err := resource_mirror.DescendantsOf(r.ctx, r.admin, []string{"iam.project"}, "iam.account", accounts)
		require.NoError(t, err)
		found := 0
		for _, row := range rows {
			if row.ObjectID != string(project.ID) {
				continue
			}
			found++
			require.Equal(t, "blue", row.Labels["team"])
			if accounts[0] == r.a {
				require.Equal(t, map[string]string{"team": "blue"}, row.AccessLabels)
			} else {
				require.Empty(t, row.AccessLabels)
			}
		}
		require.Equal(t, 1, found)
	}
}

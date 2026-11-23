// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestChildRegistrationStateFollowsParentIncarnation(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	for _, table := range []string{"kaname.authority_child_parent_state", "kaname.authority_child_creation"} {
		var accessible bool
		require.NoError(t, r.runtime.QueryRow(r.ctx,
			"SELECT has_table_privilege(current_user,$1,'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')",
			table).Scan(&accessible))
		require.False(t, accessible, "runtime не получает доступ к состоянию после выдачи штатного ACL")
	}
	const parentType = "registry.registries"
	const parentID = "child-registration-parent-state"
	const childID = parentID + "/one"
	createParent := func(version time.Time) {
		t.Helper()
		_, err := r.admin.Exec(r.ctx, "INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,source_version) VALUES($1,$2,$3,$4)",
			parentType, parentID, r.a, version)
		require.NoError(t, err)
	}
	firstVersion := time.Unix(1600, 0).UTC()
	createParent(firstVersion)
	var first, second string
	require.NoError(t, r.admin.QueryRow(r.ctx,
		"INSERT INTO kaname.authority_child_parent_state(object_type,object_id,closed_at) VALUES($1,$2,$3) RETURNING incarnation::text",
		parentType, parentID, firstVersion).Scan(&first))
	_, err := r.admin.Exec(r.ctx,
		"INSERT INTO kaname.authority_child_creation(child_type,child_id,source_version,parent_incarnation,created_at,user_id) VALUES('registry.repositories',$1,$2,$3::uuid,$2,'usr-creator')",
		childID, firstVersion, first)
	require.NoError(t, err)

	_, err = r.admin.Exec(r.ctx,
		"UPDATE kaname.resource_mirror SET source_version=$3,labels=jsonb_build_object('updated',true) WHERE object_type=$1 AND object_id=$2",
		parentType, parentID, firstVersion.Add(time.Second))
	require.NoError(t, err)
	var stillClosed bool
	require.NoError(t, r.admin.QueryRow(r.ctx,
		"SELECT closed_at IS NOT NULL AND incarnation::text=$3 FROM kaname.authority_child_parent_state WHERE object_type=$1 AND object_id=$2",
		parentType, parentID, first).Scan(&stillClosed))
	require.True(t, stillClosed)

	_, err = r.admin.Exec(r.ctx, "DELETE FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2", parentType, parentID)
	require.NoError(t, err)
	var stateGone, receiptPresent bool
	require.NoError(t, r.admin.QueryRow(r.ctx,
		"SELECT NOT EXISTS(SELECT 1 FROM kaname.authority_child_parent_state WHERE incarnation=$1::uuid), EXISTS(SELECT 1 FROM kaname.authority_child_creation WHERE parent_incarnation=$1::uuid AND child_id=$2)",
		first, childID).Scan(&stateGone, &receiptPresent))
	require.True(t, stateGone)
	require.True(t, receiptPresent, "снятие родителя не удаляет квитанцию успешного создания")

	createParent(firstVersion.Add(2 * time.Second))
	var open bool
	require.NoError(t, r.admin.QueryRow(r.ctx,
		"INSERT INTO kaname.authority_child_parent_state(object_type,object_id) VALUES($1,$2) RETURNING incarnation::text,closed_at IS NULL",
		parentType, parentID).Scan(&second, &open))
	require.True(t, open)
	require.NotEqual(t, first, second)
}

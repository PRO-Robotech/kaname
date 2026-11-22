// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

func TestUserChildBodyCommitsAtomicCreationAndReplaysWithoutEffects(t *testing.T) {
	r, owner, scene, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	fullContractActivate(t, r)
	conn, err := r.admin.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	input := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/candidate"}
	version := kanamepg.CommitUserChildBodyProbe(t, ctx, conn.Conn(), r.bundle, input, principal)
	require.False(t, version.IsZero())
	var mirrorVersion, factVersion, receiptVersion time.Time
	var project, account, subject, actor, user string
	var incarnation, parentIncarnation string
	require.NoError(t, conn.QueryRow(ctx, `SELECT source_version,parent_project_id,parent_account_id
 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, input.ResourceType, input.ResourceID).Scan(&mirrorVersion, &project, &account))
	require.True(t, version.Equal(mirrorVersion))
	require.Equal(t, scene.Project, project)
	require.Equal(t, scene.Account, account)
	var scopes int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_registration_scope
 WHERE object_type='childstage_child' AND object_id=$1 AND project_id=$2 AND account_id=$3`, input.ResourceID, scene.Project, scene.Account).Scan(&scopes))
	require.Equal(t, 1, scopes)
	require.NoError(t, conn.QueryRow(ctx, `SELECT subject,source_version FROM kaname.relation_fact
 WHERE object_type='childstage_child' AND object_id=$1 AND relation='parent'`, input.ResourceID).Scan(&subject, &factVersion))
	require.Equal(t, "childstage_container:container-one", subject)
	require.True(t, version.Equal(factVersion))
	require.NoError(t, conn.QueryRow(ctx, `SELECT source_version,user_id,parent_incarnation::text
 FROM kaname.authority_child_creation WHERE child_type=$1 AND child_id=$2`, input.ResourceType, input.ResourceID).Scan(&receiptVersion, &user, &incarnation))
	require.Equal(t, principal.ID, user)
	require.True(t, version.Equal(receiptVersion))
	require.NoError(t, conn.QueryRow(ctx, `SELECT incarnation::text FROM kaname.authority_child_parent_state
 WHERE object_type='childstage.container' AND object_id='container-one' AND closed_at IS NULL`).Scan(&parentIncarnation))
	require.Equal(t, parentIncarnation, incarnation)
	require.NoError(t, conn.QueryRow(ctx, `SELECT event_payload->>'actor' FROM kaname.audit_outbox
 WHERE event_payload#>>'{object,id}'=$1`, input.ResourceID).Scan(&actor))
	require.Equal(t, "user:"+principal.ID, actor)
	var fga int
	require.NoError(t, conn.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox
 WHERE event_type='fga.tuple.write' AND payload->>'object'='childstage_child:'||$1
 AND payload->>'relation'='parent' AND payload->>'user'='childstage_container:container-one'`, input.ResourceID).Scan(&fga))
	require.Equal(t, 1, fga)
	snapshot := func() string {
		var result string
		require.NoError(t, conn.QueryRow(ctx, `SELECT jsonb_build_object(
   'mirror',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.resource_mirror x WHERE object_type=$1 AND object_id=$2),
   'scope',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_scope x WHERE object_type='childstage_child' AND object_id=$2),
   'edges',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_parent_edge x WHERE object_type='childstage_child' AND object_id=$2),
   'facts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.relation_fact x WHERE object_type='childstage_child' AND object_id=$2),
   'receipts',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_child_creation x WHERE child_type=$1 AND child_id=$2),
   'parent_state',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_child_parent_state x WHERE object_type='childstage.container' AND object_id='container-one'),
   'fga',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.fga_outbox x WHERE payload->>'object'='childstage_child:'||$2),
   'audits',(SELECT jsonb_agg(to_jsonb(x) ORDER BY id) FROM kaname.audit_outbox x WHERE event_payload#>>'{object,id}'=$2),
   'reconcile',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_reconcile_outbox x)
  )::text`, input.ResourceType, input.ResourceID).Scan(&result))
		return result
	}
	before := snapshot()
	replay := kanamepg.CommitUserChildBodyProbe(t, ctx, conn.Conn(), r.bundle, input, principal)
	require.True(t, version.Equal(replay), "повтор возвращает первоначальную версию")
	require.JSONEq(t, before, snapshot(), "повтор не создаёт новых эффектов")
}

func TestUserChildBodyIncompleteCommitRollsBackEffects(t *testing.T) {
	r, owner, _, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	fullContractActivate(t, r)
	conn, err := r.admin.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()
	input := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/incomplete"}
	kanamepg.AbortIncompleteUserChildBodyProbe(t, ctx, conn.Conn(), r.bundle, input, principal)
	var mirror, receipt, audit, fga, parent bool
	require.NoError(t, conn.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2),
 EXISTS(SELECT 1 FROM kaname.authority_child_creation WHERE child_type=$1 AND child_id=$2),
 EXISTS(SELECT 1 FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$2),
 EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE payload->>'object'='childstage_child:'||$2),
 EXISTS(SELECT 1 FROM kaname.authority_child_parent_state WHERE object_type='childstage.container' AND object_id='container-one')`, input.ResourceType, input.ResourceID).Scan(&mirror, &receipt, &audit, &fga, &parent))
	require.False(t, mirror)
	require.False(t, receipt)
	require.False(t, audit)
	require.False(t, fga)
	require.False(t, parent)
}

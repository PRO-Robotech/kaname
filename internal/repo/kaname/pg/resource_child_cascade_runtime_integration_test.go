// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

// Снятие module-owned родителя идёт прежним public Unregister под FULL;
// ребёнок и его квитанция получены настоящим runtime child runner.
func TestUserChildRuntimeParentUnregisterCascadePrewaitAndReceiptRetention(t *testing.T) {
	r, owner, scene, principal := childStageFixture(t)
	roster, err := moduleidentity.Parse([]string{"modules/kacho-childstage=module-writer"})
	require.NoError(t, err)
	writer, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(writer)
	_, err = writer.ServiceAccountsW().Insert(r.ctx, domain.ServiceAccount{
		ID:        domain.ServiceAccountID(authzguard.ServiceAccountIDForService("childstage")),
		AccountID: domain.AccountID(r.a), Name: "kacho-childstage", Description: "child cascade module identity",
	})
	require.NoError(t, err)
	require.NoError(t, writer.Commit(r.ctx))
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
		seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "childstage-cascade", AccountID: scene.Account, Module: "childstage"}}}))
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	full, _ := fullContractActivate(t, r)
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(roster)
	moduleCtx := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-childstage", true)
	require.NoError(t, gate.AuthorizeAccount(moduleCtx, scene.Account), "installer дал account-scoped fga_writer настоящему module SA")
	runner, err := kanamepg.NewResourceDecisionRunner(moduleCtx, full, r.bundle, gate)
	require.NoError(t, err)
	child := kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/cascade-child"}
	childVersion, err := runner.RunUserChildRegistration(operations.WithPrincipal(r.ctx, principal), child, principal)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, childVersion.IsZero())

	var parentVersion time.Time
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT source_version FROM kaname.resource_mirror
 WHERE object_type='childstage.container' AND object_id='container-one'`).Scan(&parentVersion))
	receipt := func() json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT to_jsonb(c) FROM kaname.authority_child_creation c
 WHERE child_type=$1 AND child_id=$2 AND source_version=$3`, child.ResourceType, child.ResourceID, childVersion).Scan(&raw))
		return raw
	}
	immutable := receipt()
	active := func() json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'mirror',(SELECT jsonb_agg(to_jsonb(x) ORDER BY object_type,object_id) FROM kaname.resource_mirror x WHERE (object_type='childstage.container' AND object_id='container-one') OR (object_type=$1 AND object_id=$2)),
 'state',(SELECT jsonb_agg(to_jsonb(x)) FROM kaname.authority_child_parent_state x WHERE object_type='childstage.container' AND object_id='container-one'),
 'scopes',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_scope x WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2)),
 'edges',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_parent_edge x WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2)),
 'facts',(SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.relation_fact x WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2)))`, child.ResourceType, child.ResourceID).Scan(&raw))
		return raw
	}
	intent := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionUnregister,
		Tuple:  outboxtypes.RelationTuple{User: "project:" + scene.Project, Relation: "project", Object: "childstage_container:container-one"},
		Mirror: outboxtypes.ResourceMirrorRow{ObjectType: "childstage_container", ObjectID: "container-one", SourceVersion: parentVersion.Add(-time.Microsecond)}}
	before := active()
	stale, err := runner.RunResourceDecision(moduleCtx, intent)
	resourcePublicEntryCause(t, err)
	require.NoError(t, err)
	require.False(t, stale.Changed, "устаревшее снятие не удаляет новую регистрацию родителя")
	require.JSONEq(t, string(before), string(active()), "stale Unregister сохраняет родителя, потомка и активную инкарнацию")
	require.JSONEq(t, string(immutable), string(receipt()))

	// SHARE конфликтует ровно с ROW EXCLUSIVE parent-state admission. В
	// отличие от задержки по времени, pg_locks доказывает реальное ожидание.
	held := resourcePublicHold(t, r, `LOCK TABLE ONLY kaname.authority_child_parent_state IN SHARE MODE`)
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&intent.Mirror.SourceVersion))
	call := resourcePublicStart(t, moduleCtx, func(ctx context.Context) error {
		result, callErr := runner.RunResourceDecision(ctx, intent)
		if callErr == nil && !result.Changed {
			return kaname.ErrSourceUnconfirmed
		}
		return callErr
	})
	pid := resourcePublicWaitBlocked(t, r, held.Conn().PgConn().PID(), r.role, "authority_resource_prewait_v2")
	var waiting bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
 WHERE pid=$1 AND locktype='relation' AND relation='kaname.authority_child_parent_state'::regclass
 AND mode='RowExclusiveLock' AND NOT granted)`, pid).Scan(&waiting))
	require.True(t, waiting, "private lifecycle relation lock приобретается в prewait до finalize")
	require.JSONEq(t, string(before), string(active()), "ожидающий Unregister ещё не применил cascade")
	require.NoError(t, held.Rollback(r.ctx))
	callErr := resourcePublicAwait(t, call)
	resourcePublicEntryCause(t, callErr)
	require.NoError(t, callErr)
	var mirrors, states, scopes, edges, facts int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE (object_type='childstage.container' AND object_id='container-one') OR (object_type=$1 AND object_id=$2)),
 (SELECT count(*) FROM kaname.authority_child_parent_state WHERE object_type='childstage.container' AND object_id='container-one'),
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2)),
 (SELECT count(*) FROM kaname.resource_parent_edge WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2)),
 (SELECT count(*) FROM kaname.relation_fact WHERE (object_type='childstage_container' AND object_id='container-one') OR (object_type='childstage_child' AND object_id=$2))`, child.ResourceType, child.ResourceID).Scan(&mirrors, &states, &scopes, &edges, &facts))
	require.Zero(t, mirrors, "родитель и потомок сняты одним commit")
	require.Zero(t, states, "FK cascade удалил инкарнацию родителя")
	require.Zero(t, scopes)
	require.Zero(t, edges)
	require.Zero(t, facts)
	require.JSONEq(t, string(immutable), string(receipt()), "историческая квитанция создания неизменна после cascade")
	authorityWaitReleased(t, r.runtime)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Квитанция связывает точный типизированный план с байтами полного входа дочернего запуска.
func ridRegistrationStartupProof(t *testing.T, root string, raw []byte, plan *installruntime.RegistrationWriterPlan) {
	t.Helper()
	digest := sha256.Sum256(raw)
	rid08Write(t, root, "registration-startup-profile", map[string]any{"writerPlan": plan, "writerPlanSHA256": rid01RedactionHash(plan), "fullStartupConfigSHA256": fmt.Sprintf("%x", digest)})
}

// Свидетели только читают полный набор активных назначений и фактов аккаунтной
// записи. Лишний субъект или аккаунт не может исчезнуть за фильтром снимка.
func (f *installationNativeWorld) requireRegistrationWriterPlan(t *testing.T, plan *installruntime.RegistrationWriterPlan) {
	t.Helper()
	require.NotNil(t, plan, "lawful full startup carries its explicit typed plan")
	require.NotNil(t, plan.Assignments)
	var active, bindings, facts, clusterFacts int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.registration_account_writer_assignment WHERE removed_at IS NULL),
 (SELECT count(*) FROM kaname.access_bindings WHERE resource_type='account' AND granted_relation='fga_writer' AND status='ACTIVE'),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='account' AND relation='fga_writer'),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='cluster' AND relation='fga_writer')`).Scan(&active, &bindings, &facts, &clusterFacts))
	require.Equal(t, len(plan.Assignments), active, "no unintended active assignment")
	require.Equal(t, active, bindings, "exact visible account writer binding set")
	require.Equal(t, active, facts, "no extra account/subject authority")
	require.True(t, plan.RetireClusterWriter, "new-only fixture retires migration legacy authority")
	require.Zero(t, clusterFacts, "legacy group cannot supply blanket registration authority")
	var provenance bool
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT EXISTS(
 SELECT 1 FROM kaname.registration_legacy_cluster_writer_identity i
 JOIN kaname.groups g ON g.id=i.group_id AND g.account_id=i.account_id
 WHERE i.singleton AND i.original_seed_name='module-relation-writers'
 AND g.name=i.original_seed_name)`).Scan(&provenance))
	require.True(t, provenance, "retained legacy group has explicit migration provenance, not own-seed issuance")
	var retired bool
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT cluster_writer_retired_at IS NOT NULL FROM kaname.registration_account_writer_switch WHERE singleton`).Scan(&retired))
	require.True(t, retired)
	for _, assignment := range plan.Assignments {
		binding := "acb" + domain.DerivedIDSuffix("registration-account-writer:"+assignment.AssignmentID)
		subject := authzguard.ServiceAccountIDForService(assignment.Module)
		var exact bool
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT EXISTS(
 SELECT 1 FROM kaname.registration_account_writer_assignment a
 JOIN kaname.access_bindings b ON b.id=a.binding_id
 WHERE a.assignment_id=$1 AND a.account_id=$2 AND a.module=$3 AND a.binding_id=$4 AND a.removed_at IS NULL
 AND b.resource_type='account' AND b.resource_id=$2 AND b.subject_type='service_account' AND b.subject_id=$5
 AND b.status='ACTIVE' AND b.granted_relation='fga_writer' AND coalesce(b.role_id,'')='' AND b.is_system AND b.deletion_protection)`,
			assignment.AssignmentID, assignment.AccountID, assignment.Module, binding, subject).Scan(&exact))
		require.True(t, exact, "exact installation ledger and system binding")
		var subjects []string
		rows, err := f.given.pool.Query(f.given.ctx, `SELECT subject_type||':'||subject_id||':'||ordinal::text||':'||resource_type||':'||resource_id FROM kaname.access_binding_subjects WHERE binding_id=$1 ORDER BY ordinal`, binding)
		require.NoError(t, err)
		for rows.Next() {
			var value string
			require.NoError(t, rows.Scan(&value))
			subjects = append(subjects, value)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.Equal(t, []string{"service_account:" + subject + ":0:account:" + assignment.AccountID}, subjects)
		var ledger []string
		rows, err = f.given.pool.Query(f.given.ctx, `SELECT fga_user||'|'||relation||'|'||object||'|'||source FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 ORDER BY fga_user,relation,object,source`, binding)
		require.NoError(t, err)
		for rows.Next() {
			var value string
			require.NoError(t, rows.Scan(&value))
			ledger = append(ledger, value)
		}
		require.NoError(t, rows.Err())
		rows.Close()
		require.ElementsMatch(t, []string{
			"service_account:" + subject + "|fga_writer|account:" + assignment.AccountID + "|binding",
			"account:" + assignment.AccountID + "|account|iam_access_binding:" + binding + "|binding",
		}, ledger)
		var direct bool
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='account' AND object_id=$1 AND relation='fga_writer' AND subject=$2)`, assignment.AccountID, "service_account:"+subject).Scan(&direct))
		require.True(t, direct)
		var visible iamv1.AccessBinding
		f.publicRead(t, "/iam/v1/accessBindings/"+binding, &visible)
		require.Equal(t, binding, visible.Id)
		require.Equal(t, "fga_writer", visible.GrantedRelation)
		require.Empty(t, visible.RoleId)
		require.Equal(t, iamv1.AccessBinding_ACTIVE, visible.Status)
	}
	rid08Write(t, f.session.Root, "registration-writer-plan-"+rid01RedactionHash(plan), map[string]any{"plan": plan, "activeAssignments": active, "visibleBindings": bindings, "accountFacts": facts, "clusterFacts": clusterFacts, "migrationGroupProvenance": provenance})
}

// Отдельный нативный мир сохраняет все существующие фазы и снимки RID.
// Изменения идут через полный запуск или публичный API; SQL выше только наблюдает.
func ridRegistrationWriterAuthorityTwins(t *testing.T) {
	w := newRIDLifecycleWorld(t, "S1", false)
	f := w.f
	plan := installruntime.CloneRegistrationWriterPlan(w.delivery.RegistrationWriters)
	require.Len(t, plan.Assignments, 1)
	originalID := plan.Assignments[0].AssignmentID
	// Отрицательный wildcard проходит настоящий полный запуск и не меняет
	// ни одну строку ранее выданных регистрационных полномочий.
	writerSnapshot := func() string {
		var raw string
		require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT jsonb_build_object(
 'assignments',COALESCE((SELECT jsonb_agg(to_jsonb(a) ORDER BY assignment_id) FROM kaname.registration_account_writer_assignment a),'[]'::jsonb),
 'bindings',COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY id) FROM kaname.access_bindings b WHERE granted_relation='fga_writer'),'[]'::jsonb),
 'subjects',COALESCE((SELECT jsonb_agg(to_jsonb(s) ORDER BY s.binding_id,s.ordinal) FROM kaname.access_binding_subjects s JOIN kaname.access_bindings b ON b.id=s.binding_id WHERE b.granted_relation='fga_writer'),'[]'::jsonb),
 'ledger',COALESCE((SELECT jsonb_agg(to_jsonb(e) ORDER BY e.binding_id,e.fga_user,e.relation,e.object,e.source) FROM kaname.access_binding_emitted_tuples e JOIN kaname.access_bindings b ON b.id=e.binding_id WHERE b.granted_relation='fga_writer'),'[]'::jsonb),
 'facts',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY object_type,object_id,relation,subject) FROM kaname.relation_fact r WHERE relation='fga_writer'),'[]'::jsonb))::text`).Scan(&raw))
		return raw
	}
	beforeWildcard := writerSnapshot()
	stopWildcard, cancelWildcard := context.WithTimeout(f.given.ctx, 20*time.Second)
	require.NoError(t, f.session.Stop(stopWildcard))
	cancelWildcard()
	invalid := w.delivery
	invalid.RegistrationWriters = installruntime.CloneRegistrationWriterPlan(plan)
	invalid.RegistrationWriters.Assignments[0].AccountID = "*"
	refused, err := f.session.StartDelivery(f.given.ctx, invalid)
	require.NoError(t, err)
	refusal, cancelRefusal := context.WithTimeout(f.given.ctx, 90*time.Second)
	require.Error(t, refused.Wait(refusal), "wildcard account plan must refuse full startup")
	require.NoError(t, refusal.Err(), "refusal is actual exit, not a timeout")
	cancelRefusal()
	require.NoError(t, refused.CheckSecretAbsence(f.secrets...))
	clearRefused, cancelClear := context.WithTimeout(f.given.ctx, 20*time.Second)
	require.Error(t, f.session.Stop(clearRefused), "retain actual rejected process status")
	cancelClear()
	require.JSONEq(t, beforeWildcard, writerSnapshot(), "invalid whole plan grants no partial authority")
	f.apply(t, w.delivery)
	require.Equal(t, originalID, f.writerPlan.Assignments[0].AssignmentID)
	// Дополнительный известный аккаунт — отрицательный вход без назначения.
	other := ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/accounts", f.operator.Bearer(), map[string]any{"name": "rid-writer-unassigned"}, 0))
	otherProject := ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/projects", f.operator.Bearer(), map[string]any{"accountId": other, "name": "rid-writer-unassigned-project"}, 0))
	check := func(account, project, object string, allowed bool) {
		t.Helper()
		conn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
		require.NoError(t, err)
		defer conn.Close()
		module := iamv1.NewInternalIAMServiceClient(conn)
		_, err = module.RegisterResource(f.given.ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + project, Relation: "project", Object: "registry_registry:" + object, ParentProjectId: project, ParentAccountId: account, ParentChain: []string{"project:" + project, "account:" + account}, SourceVersion: timestamppb.Now()})
		if !allowed {
			require.Equal(t, codes.PermissionDenied, status.Code(err))
			var count int
			require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type='registry.registries' AND object_id=$1) +
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_registry' AND object_id=$1) +
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='registry_registry' AND object_id=$1)`, object).Scan(&count))
			require.Zero(t, count, "denied registration creates no mirror, fact or saved authority scope")
			return
		}
		require.NoError(t, err)
		published, err := module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: "project:" + project, Relation: "project", Object: "registry_registry:" + object, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, err)
		require.True(t, published.Allowed, "lawful pointer is published")
		_, err = module.UnregisterResource(f.given.ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + project, Relation: "project", Object: "registry_registry:" + object, SourceVersion: timestamppb.Now()})
		require.NoError(t, err)
		published, err = module.Check(f.given.ctx, &iamv1.CheckRequest{SubjectId: "project:" + project, Relation: "project", Object: "registry_registry:" + object, Consistency: iamv1.CheckRequest_HIGHER_CONSISTENCY})
		require.NoError(t, err)
		require.False(t, published.Allowed, "lawful withdrawal removes publication")
	}
	check(other, otherProject, "rid-writer-other-account-denied", false)
	check(f.tenantID, w.project, "rid-writer-lawful-twin", true)
	// Удаление из настоящего явного плана отзывает назначение навсегда.
	revoked := w.delivery
	revoked.RegistrationWriters = installruntime.EmptyRegistrationWriterPlan()
	f.apply(t, revoked)
	check(f.tenantID, w.project, "rid-writer-no-assignment-denied", false)
	replayed := w.delivery
	replayed.RegistrationWriters = plan
	// Повтор выведенного ID не должен считаться активным обычным свидетелем apply.
	stop, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	require.NoError(t, f.session.Stop(stop))
	cancel()
	p, err := f.session.StartDelivery(f.given.ctx, replayed)
	require.NoError(t, err)
	ready, cancelReady := context.WithTimeout(f.given.ctx, 90*time.Second)
	require.NoError(t, p.AwaitReady(ready, f.wire.ProductionReady))
	cancelReady()
	check(f.tenantID, w.project, "rid-writer-revoked-id-denied", false)
	var removed bool
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT removed_at IS NOT NULL FROM kaname.registration_account_writer_assignment WHERE assignment_id=$1`, originalID).Scan(&removed))
	require.True(t, removed)
	// Явно НОВОЕ назначение оператора — положительный близнец восстановления.
	replacement := installruntime.CloneRegistrationWriterPlan(plan)
	replacement.Assignments[0].AssignmentID = originalID + "-explicit-replacement"
	replayed.RegistrationWriters = replacement
	f.apply(t, replayed)
	check(f.tenantID, w.project, "rid-writer-explicit-replacement-twin", true)
	var before, after []byte
	before, err = json.Marshal(replacement)
	require.NoError(t, err)
	f.apply(t, replayed)
	after, err = json.Marshal(f.writerPlan)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "repeat preserves exact explicit assignment ID")
}

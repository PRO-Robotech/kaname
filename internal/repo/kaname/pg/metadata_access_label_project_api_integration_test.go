// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Одинаковый ключ объявлен в двух проектах одного аккаунта. Apply в первом
// проекте не разрешает запись во втором, даже владельцу всего аккаунта.
func TestMetadataAccessLabelsActualProjectUpdateUsesExactScope(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	first := seedMetadataActualProject(t, r, "protected-first")
	second := seedMetadataActualProject(t, r, "protected-second")
	firstDefinition := seedMetadataActualProjectDefinition(t, r, first.ID)
	secondDefinition := seedMetadataActualProjectDefinition(t, r, second.ID)
	require.NotEqual(t, firstDefinition, secondDefinition)
	seedMetadataActualApplySourceInScope(t, r, actor,
		domain.ScopeAnchor{Type: "project", ID: string(first.ID)}, firstDefinition)
	// Как в metadataFixtureMode: ordinary method требует реальный binding,
	// selectors и role_verb; право владельца само по себе не заменяет v_update.
	editor := groupLifecycleBinding(t, r, r.a, actor, "metadata_project_update", domain.Rule{
		Module: "iam", Resources: []string{"project"}, Verbs: []string{"update"},
	})
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, editor))
	var ordinaryProjects []string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT coalesce(array_agg(DISTINCT object ORDER BY object),'{}'::text[])
 FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND fga_user=$2 AND relation='v_update'`,
		string(editor), "user:"+actor).Scan(&ordinaryProjects))
	require.ElementsMatch(t, []string{"project:" + string(first.ID), "project:" + string(second.ID)}, ordinaryProjects)
	cfg := r.runtime.Config()
	cfg.ConnConfig.Tracer = metadataActualQueryTrace{test: t}
	traced, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(traced.Close)
	r.runtime, r.repo = traced, kanamepg.New(traced, nil)
	factory, err := kanamepg.NewStagedMetadataMutationWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	ports, err := factory.WithInstalledAccessLabels(r.ctx)
	require.NoError(t, err)
	_, protected := ports.(kaname.ProjectAccessLabelsWriterFactory)
	require.True(t, protected, "use the installed project writer, without a test SQL export")
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	ops := operations.NewRepo(r.runtime, "kaname")
	update := projectapp.NewUpdateProjectUseCase(r.repo, ops).
		WithRelationStore(door, nil).WithProjectMetadataWriter(ports)
	ctx := declarerCtx(r.ctx, actor)
	for _, id := range []domain.ProjectID{first.ID, second.ID} {
		allowed, err := door.Check(ctx, "user:"+actor, "v_update", "project:"+string(id))
		require.NoError(t, err)
		require.True(t, allowed, "ordinary update authority exists in both projects")
	}
	reader := metadataActualReadbackLogin(t, r)
	var original json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(p) FROM kaname.projects p WHERE id=$1`, first.ID).Scan(&original))
	run := func(id domain.ProjectID, want codes.Code) {
		t.Helper()
		op, err := update.Execute(ctx, projectapp.UpdateProjectInput{
			ID: id, AccessLabels: domain.Labels{"classification": "internal"}, UpdateMask: []string{"access_labels"},
		})
		require.NoError(t, err)
		result := awaitOperation(t, r.ctx, ops, op.ID)
		if want == codes.OK {
			require.Nil(t, result.Error)
		} else {
			require.NotNil(t, result.Error)
			require.Equal(t, int32(want), result.Error.Code, result.Error.Message)
		}
	}
	run(first.ID, codes.OK)
	var exact bool
	var audits, journals int
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT
 to_jsonb(p)=($2::jsonb||'{"access_labels":{"classification":"internal"}}'::jsonb),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.project.updated'
  AND event_payload->>'resource_id'=$1 AND event_payload->>'actor'=$3
  AND event_payload->'changed_fields'='["access_labels"]'::jsonb),
 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='project' AND resource_id=$1 AND event_type='UPDATED')
 FROM kaname.projects p WHERE p.id=$1`, first.ID, original, actor).Scan(&exact, &audits, &journals))
	require.True(t, exact, "another LOGIN sees exactly the approved committed project row")
	require.Equal(t, 1, audits)
	require.Equal(t, 1, journals)
	beforeDenied := metadataActualProjectSnapshot(t, r, []string{string(first.ID), string(second.ID)})
	run(second.ID, codes.PermissionDenied)
	require.JSONEq(t, beforeDenied, metadataActualProjectSnapshot(t, r, []string{string(first.ID), string(second.ID)}),
		"a grant in project A cannot mutate project B or leave audit/journal/freshness effects")
	var secondLabels json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT access_labels FROM kaname.projects WHERE id=$1`, second.ID).Scan(&secondLabels))
	require.JSONEq(t, `{}`, string(secondLabels))
}

func seedMetadataActualProject(t *testing.T, r protocolRig, name string) domain.Project {
	t.Helper()
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	project, err := seed.ProjectsW().Insert(r.ctx, domain.Project{
		ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: domain.AccountID(r.a),
		Name: domain.ProjectName(name), Description: "project access label integration", Labels: domain.Labels{},
	})
	require.NoError(t, err)
	var structural []service.RelationTuple
	for _, fact := range project.StructuralFacts() {
		structural = append(structural, service.RelationTuple{User: fact.User, Relation: fact.Relation, Object: fact.Object})
	}
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, structural))
	require.NoError(t, seed.Commit(r.ctx))
	return project
}

func seedMetadataActualProjectDefinition(t *testing.T, r protocolRig, id domain.ProjectID) string {
	t.Helper()
	var definition string
	require.NoError(t, r.admin.QueryRow(r.ctx, `INSERT INTO kaname.authority_access_label_definition
 (scope_kind,scope_id,module,resource,label_key) VALUES('project',$1,'iam','project','classification') RETURNING id::text`, id).Scan(&definition))
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value(definition_id,label_value) VALUES($1::uuid,'internal')`, definition)
	require.NoError(t, err)
	return definition
}

func metadataActualProjectSnapshot(t *testing.T, r protocolRig, projects []string) string {
	t.Helper()
	var value string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'roots',(SELECT jsonb_agg(jsonb_build_array(xmin::text,ctid::text,to_jsonb(p)) ORDER BY id) FROM kaname.projects p WHERE id=ANY($1::text[])),
 'generations',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY root_id),'[]') FROM kaname.authority_access_label_dirty_root d WHERE root_type='iam.project' AND root_id=ANY($1::text[])),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY root_id,object_type,object_id,relation,subject),'[]') FROM kaname.authority_access_label_dirty_fact d WHERE root_type='iam.project' AND root_id=ANY($1::text[])),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(a) ORDER BY id),'[]') FROM kaname.audit_outbox a WHERE event_type='iam.project.updated' AND event_payload->>'resource_id'=ANY($1::text[])),
 'journal',(SELECT coalesce(jsonb_agg(to_jsonb(j) ORDER BY sequence_no),'[]') FROM kaname.resource_journal j WHERE resource_kind='project' AND resource_id=ANY($1::text[]) AND event_type='UPDATED'))::text`, projects).Scan(&value))
	return value
}

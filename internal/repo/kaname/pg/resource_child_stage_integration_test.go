// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func childStageFixture(t *testing.T) (protocolRig, *kanamepg.Repository, registrationscene.Scene, operations.Principal) {
	t.Helper()
	return childStageFixtureWithPolicy(t, catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60}, "container-one")
}

func childStageFixtureWithPolicy(t *testing.T, rule catalog.ChildRegistrationRule, parentIDs ...string) (protocolRig, *kanamepg.Repository, registrationscene.Scene, operations.Principal) {
	t.Helper()
	require.Equal(t, "registerchild", rule.Verb)
	require.EqualValues(t, 1, rule.ParentSegments)
	require.NotEmpty(t, parentIDs)
	r, owner := writerProtocolRigBeforePreparation(t)
	declaration := fmt.Sprintf(`apiVersion: iam/v1
module: childstage
resources:
  - name: container
    objectType: childstage_container
    parents: [project]
    producer: authored
    verbs: [get]
    relations:
      - {name: child_registrar, definition: "[user]"}
  - name: child
    objectType: childstage_child
    parents:
      - {name: parent, type: childstage_container}
    producer: authored
    verbs: [get]
    containerVerbs:
      - {name: registerChild, parent: parent, relation: child_registrar}
    childRegistration: {verb: registerChild, parentSegments: 1, maxChildren: %d, maxCreates: %d, windowSeconds: %d}
`, rule.MaxChildren, rule.MaxCreates, rule.WindowSeconds)
	m, err := manifest.LoadWithReferent([]byte(declaration), manifest.ReferentCanon)
	require.NoError(t, err)
	model, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.admin).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		if _, err := w.UpsertModule(ctx, "childstage"); err != nil {
			return err
		}
		for _, row := range []catalog.ResourceRow{
			{Module: "childstage", Resource: "container", ObjectType: "childstage_container", ParentNames: []string{"project"}, ParentTypes: []string{"project"}},
			{Module: "childstage", Resource: "child", ObjectType: "childstage_child", ParentNames: []string{"parent"}, ParentTypes: []string{"childstage_container"}, ChildRegistration: &rule},
		} {
			if _, err := w.UpsertResource(ctx, row); err != nil {
				return err
			}
		}
		for _, row := range []catalog.VerbRow{
			{Module: "childstage", Resource: "container", Verb: "get", PerObject: true},
			{Module: "childstage", Resource: "child", Verb: "get", PerObject: true},
			{Module: "childstage", Resource: "child", Verb: "registerchild", ContainerParent: "childstage_container", ContainerRelation: "child_registrar"},
		} {
			if _, err := w.UpsertVerb(ctx, row); err != nil {
				return err
			}
		}
		return nil
	}))
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	r.bundle, err = granteffect.NewBundle(r.ctx, model, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	scene := registrationscene.Seed(t, r.ctx, r.admin)
	version := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	for _, parentID := range parentIDs {
		_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,parent_project_id,source_version)
 VALUES('childstage.container',$1,$2,$3,$4)`, parentID, scene.Account, scene.Project, version)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 VALUES('childstage_container',$1,$2,$3)`, parentID, scene.Project, scene.Account)
		require.NoError(t, err)
		_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 VALUES('childstage_container',$1,'project','project:'||$2::text,$3)`, parentID, scene.Project, version)
		require.NoError(t, err)
	}
	actor := seedMemberUser(t, r.ctx, r.admin, scene.Account, "child-stage-registrar")
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	// Право выводит штатный role producer по выбранному родителю. Потомок
	// отсутствует; тест не подменяет источник разрешения вручную записанным фактом.
	binding := groupLifecycleBinding(t, r, scene.Account, actor, "child_stage_registrar", domain.Rule{
		Module: "childstage", Resources: []string{"container"}, Verbs: []string{"get"},
		Children: []domain.Rule{{Resources: []string{"child"}, Verbs: []string{"registerChild"}}},
	})
	source := catalog.Fixed{F: facts}
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	for _, parentID := range parentIDs {
		var holders int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples
 WHERE binding_id=$1 AND member_object_type='childstage.container' AND member_object_id=$2
 AND fga_user=$3 AND relation='child_registrar' AND object=$4`, binding, parentID, "user:"+actor, "childstage_container:"+parentID).Scan(&holders))
		require.Positive(t, holders, "предпосылка: настоящий producer подтвердил право на модульном родителе")
	}

	return r, owner, scene, operations.Principal{Type: "user", ID: actor}
}

func TestUserChildStageRRCapturesAuthorizedModuleParentAndAbsentChild(t *testing.T) {
	const parentID, childID = "container-one", "container-one/candidate"
	r, _, scene, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	tx, err := r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() { require.NoError(t, tx.Rollback(context.WithoutCancel(ctx))) }()
	probe, err := kanamepg.ProbeUserChildStage(ctx, tx, r.bundle,
		kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: childID}, principal)
	require.NoError(t, err)
	require.True(t, probe.SameLifetime)
	require.False(t, probe.SourceSealed)
	require.True(t, probe.ParentRegistered)
	require.False(t, probe.ChildRegistered)
	require.Equal(t, "childstage_container:"+parentID, probe.Target.ParentObject)
	require.Equal(t, "child_registrar", probe.Target.ParentAction)
	require.Equal(t, []domain.ParentHierarchy{{Links: []string{"childstage_container:" + parentID, "project:" + scene.Project, "account:" + scene.Account}, ProjectID: scene.Project, AccountID: scene.Account}}, probe.Hierarchies)
	require.Empty(t, probe.OldScopes)
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: scene.Project, AccountID: scene.Account}}, probe.NewScopes)
	// Для типа произвольного модуля читатель прав пока выбирает общий
	// барьер. Фактическую область родителя сохраняем в самом запросе.
	require.Equal(t, kaname.AuthorityFenceGlobal, probe.Plan.Mode)
	require.Empty(t, probe.Plan.Accounts)
	var envelope struct {
		Actor        string                     `json:"actor"`
		NativeGuards []string                   `json:"native_guards"`
		NativeEpochs map[string]json.RawMessage `json:"native_epochs"`
		Registration []domain.AccountID         `json:"registration_accounts"`
		Objects      []domain.ResourceRef       `json:"objects"`
		Sources      []struct {
			Kind   int      `json:"kind"`
			Type   string   `json:"type"`
			ID     string   `json:"id"`
			States []string `json:"states"`
		} `json:"sources"`
		Catalogs []struct {
			Input  string   `json:"input"`
			States []string `json:"states"`
		} `json:"catalogs"`
	}
	require.NoError(t, json.Unmarshal(probe.Envelope, &envelope))
	require.Equal(t, principal.ID, envelope.Actor)
	require.Contains(t, envelope.NativeGuards, "*")
	require.Contains(t, envelope.NativeEpochs, "*")
	require.Equal(t, []domain.AccountID{domain.AccountID(scene.Account)}, envelope.Registration)
	require.Contains(t, envelope.Objects, domain.ResourceRef{Type: "childstage.child", ID: childID})
	for _, kind := range []int{2, 3, 4, 5, 6, 25, 26, 28} {
		typ := "childstage_child"
		if kind == 2 {
			typ = "childstage.child"
		}
		found := false
		for _, capture := range envelope.Sources {
			if capture.Kind == kind && capture.Type == typ && capture.ID == childID {
				found = true
				require.Empty(t, capture.States, "predicate %d должен подтверждать отсутствие потомка", kind)
			}
		}
		require.True(t, found, "отсутствует обязательный exact predicate %d", kind)
	}
	var physical string
	require.NoError(t, tx.QueryRow(ctx, `SELECT jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c))::text
 FROM kaname.catalog_resource c WHERE c.dotted='childstage.child' AND c.live`).Scan(&physical))
	bound := false
	for _, captured := range envelope.Catalogs {
		if captured.Input == "childstage.child" {
			bound = true
			require.Equal(t, []string{physical}, captured.States)
		}
	}
	require.True(t, bound, "stage должен сохранить физический каталог кандидата для recheck")
	for _, query := range probe.Queries {
		require.False(t, strings.Contains(query, "authority_child_creation") || strings.Contains(query, "authority_child_parent_state"), "private quota sources принадлежат owner capture")
	}
}

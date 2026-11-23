// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationRecheckRequiresSignedParentFenceAndFreshCapture(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	const declaration = `apiVersion: iam/v1
module: recheck
resources:
  - name: container
    objectType: recheck_container
    parents: [project]
    producer: authored
    verbs: [get]
    relations:
      - {name: child_registrar, definition: "[user]"}
  - name: child
    objectType: recheck_child
    parents:
      - {name: parent, type: recheck_container}
    producer: authored
    verbs: [get]
    containerVerbs:
      - {name: registerChild, parent: parent, relation: child_registrar}
    childRegistration: {verb: registerChild, parentSegments: 1, maxChildren: 24, maxCreates: 4, windowSeconds: 60}
`
	m, err := manifest.LoadWithReferent([]byte(declaration), manifest.ReferentCanon)
	require.NoError(t, err)
	source, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	resources := []catalog.ResourceRow{
		{Module: "recheck", Resource: "container", ObjectType: "recheck_container", ParentNames: []string{"project"}, ParentTypes: []string{"project"}},
		{Module: "recheck", Resource: "child", ObjectType: "recheck_child", ParentNames: []string{"parent"}, ParentTypes: []string{"recheck_container"},
			ChildRegistration: &catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60}},
	}
	verbs := []catalog.VerbRow{
		{Module: "recheck", Resource: "container", Verb: "get", PerObject: true},
		{Module: "recheck", Resource: "child", Verb: "get", PerObject: true},
		{Module: "recheck", Resource: "child", Verb: "registerchild", ContainerParent: "recheck_container", ContainerRelation: "child_registrar"},
	}
	require.NoError(t, kanamepg.NewCatalogWriteRepo(r.admin).RunInWriteTx(r.ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		if _, err := w.UpsertModule(ctx, "recheck"); err != nil {
			return err
		}
		for _, row := range resources {
			if _, err := w.UpsertResource(ctx, row); err != nil {
				return err
			}
		}
		for _, row := range verbs {
			if _, err := w.UpsertVerb(ctx, row); err != nil {
				return err
			}
		}
		return nil
	}))
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	r.bundle, err = granteffect.NewBundle(r.ctx, source, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	scene := registrationscene.Seed(t, r.ctx, r.admin)
	const parent, child = "recheck-parent", "recheck-parent/candidate"
	version := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,parent_project_id,source_version)
 VALUES('recheck.container',$1,$2,$3,$4)`, parent, scene.Account, scene.Project, version)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_child_parent_state(object_type,object_id) VALUES('recheck.container',$1)`, parent)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 VALUES('recheck_container',$1,$2,$3)`, parent, scene.Project, scene.Account)
	require.NoError(t, err)

	// Индекс содержит настоящие сохранённые области родителя и строку проекта.
	// xmin/ctid берутся из БД, а не из синтетического доказательства.
	var index []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_resource_capture_index_v2(jsonb_build_array(
 jsonb_build_object('kind',4,'type','recheck_container','id',$1::text,'projection','','states',
  (SELECT jsonb_agg(jsonb_build_array(s.xmin::text,s.ctid::text,to_jsonb(s))::text) FROM kaname.resource_registration_scope s WHERE s.object_type='recheck_container' AND s.object_id=$1)),
 jsonb_build_object('kind',1,'type','project','id',$2::text,'projection','','states',
  (SELECT jsonb_agg(jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p))::text) FROM kaname.projects p WHERE p.id=$2))
 ),100000)`, parent, scene.Project).Scan(&index))
	var before []byte
	var capturedRows, capturedReads int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT witness,logical_rows,logical_reads
 FROM kaname._authority_child_registration_capture_v1('recheck.child',$1,64,64)`, child).Scan(&before, &capturedRows, &capturedReads))
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	fullContractActivate(t, r)
	identity := r.bundle.Identity()

	open := func(account string, signed bool) pgx.Tx {
		t.Helper()
		tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		if signed {
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_enter_v3('accounts',ARRAY[$1::text],
 jsonb_build_array(jsonb_build_object('kind','account','id',$1::text)),$2,$3,$4)`, account, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
			require.NoError(t, err, "настоящий FULL вход подписывает ожидающего resource participant")
		}
		return tx
	}
	recheck := func(tx pgx.Tx, requestedChild string) ([]byte, int, int, error) {
		var got []byte
		var rows, reads int
		err := tx.QueryRow(r.ctx, `SELECT witness,logical_rows,logical_reads
 FROM kaname._authority_child_registration_recheck_v1('recheck.child',$1,$2::jsonb,$3::jsonb,$4::jsonb,64,64)`, requestedChild, before, index, r.bundle.CanonicalCatalog()).Scan(&got, &rows, &reads)
		return got, rows, reads, err
	}
	refuses := func(t *testing.T, tx pgx.Tx, requestedChild, code string) {
		t.Helper()
		_, _, _, err := recheck(tx, requestedChild)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, code, pe.Code)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	t.Run("held parent accepts equal fresh witness", func(t *testing.T) {
		tx := open(scene.Account, true)
		got, rows, reads, err := recheck(tx, child)
		require.NoError(t, err)
		require.JSONEq(t, string(before), string(got))
		require.Equal(t, capturedRows+2, rows, "в бюджет входят область регистрации и проект")
		require.Equal(t, capturedReads+2, reads)
		require.NoError(t, tx.Rollback(r.ctx))
	})
	t.Run("other account cannot substitute parent fence", func(t *testing.T) {
		refuses(t, open(r.b, true), child, "42501")
	})
	t.Run("owner connection without attestation refuses", func(t *testing.T) {
		refuses(t, open(scene.Account, false), child, "42501")
	})
	t.Run("snapshot belongs only to the requested child", func(t *testing.T) {
		refuses(t, open(scene.Account, true), parent+"/other", "42501")
	})
	// Изменение выполняется между двумя RC попытками, после освобождения ограждения.
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_child_parent_state SET closed_at=$2 WHERE object_type='recheck.container' AND object_id=$1`, parent, version.Add(time.Minute))
	require.NoError(t, err)
	t.Run("changed parent invalidates old capture", func(t *testing.T) {
		refuses(t, open(scene.Account, true), child, "P1034")
	})
}

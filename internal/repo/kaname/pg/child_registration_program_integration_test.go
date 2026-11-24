// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationProgramCompilesParentAndExplicitHumanActor(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
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

	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 VALUES('recheck_container',$1,'project','project:'||$2::text,$3)`, parent, scene.Project, version)
	require.NoError(t, err)
	var userID string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, scene.Account).Scan(&userID))

	// Снимок содержит реальные строки родителя и явно прочитанную пустоту по кандидату.
	var index, witness, catalogRows []byte
	require.NoError(t, r.admin.QueryRow(r.ctx, `WITH captures AS (
 SELECT jsonb_build_object('kind',1,'type','project','id',$2::text,'projection','','states',
  (SELECT jsonb_agg(jsonb_build_array(p.xmin::text,p.ctid::text,to_jsonb(p))::text) FROM kaname.projects p WHERE p.id=$2)) AS c
 UNION ALL SELECT jsonb_build_object('kind',2,'type','recheck.container','id',$1::text,'projection','','states',
  (SELECT jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m))::text) FROM kaname.resource_mirror m WHERE m.object_type='recheck.container' AND m.object_id=$1))
 UNION ALL SELECT jsonb_build_object('kind',6,'type','recheck_container','id',$1::text,'projection','','states',
  (SELECT jsonb_agg(jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f))::text) FROM kaname.relation_fact f WHERE f.object_type='recheck_container' AND f.object_id=$1))
 UNION ALL SELECT jsonb_build_object('kind',kind,'type',CASE WHEN kind=2 THEN 'recheck.child' ELSE 'recheck_child' END,
  'id',$3::text,'projection','','states','[]'::jsonb) FROM unnest(ARRAY[2,3,4,5,6,25,26,28]) kind
 ) SELECT kaname._authority_resource_capture_index_v2(jsonb_agg(c),100000) FROM captures`, parent, scene.Project, child).Scan(&index))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT witness FROM kaname._authority_child_registration_capture_v1('recheck.child',$1,64,64)`, child).Scan(&witness))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_agg(jsonb_build_object('state',jsonb_build_array(c.xmin::text,c.ctid::text,to_jsonb(c))::text))
 FROM kaname.catalog_resource c WHERE c.dotted='recheck.child' AND c.live`).Scan(&catalogRows))
	decisionAt := version.Add(time.Hour)
	transactionAt := decisionAt.Add(-time.Second)
	const auditID = "evt_0123456789ABCDEFGHJKMN"
	compile := func(w, i, rows []byte) (map[string]json.RawMessage, error) {
		var result []byte
		err := r.admin.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_program_v1(
 $1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb,$5,$6,$7,$8)`,
			w, i, r.bundle.CanonicalCatalog(), rows, userID, auditID, decisionAt, transactionAt).Scan(&result)
		if err != nil {
			return nil, err
		}
		var value map[string]json.RawMessage
		err = json.Unmarshal(result, &value)
		return value, err
	}
	t.Run("prepare sources before choosing a version", func(t *testing.T) {
		var raw []byte
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_sources_v1(
 $1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb)`, witness, index, r.bundle.CanonicalCatalog(), catalogRows).Scan(&raw))
		var prepared struct {
			Certificate struct {
				Command map[string]json.RawMessage `json:"command"`
			} `json:"certificate"`
			Sources struct {
				Required map[string]bool `json:"required"`
			} `json:"sources"`
		}
		require.NoError(t, json.Unmarshal(raw, &prepared))
		require.NotContains(t, prepared.Certificate.Command, "source_version")
		require.Contains(t, prepared.Certificate.Command, "parent_chain")
		require.NotEmpty(t, prepared.Sources.Required)
	})
	t.Run("create derives parent program without an owner tuple", func(t *testing.T) {
		body, err := compile(witness, index, catalogRows)
		require.NoError(t, err)
		require.JSONEq(t, `"create"`, string(body["outcome"]))
		var sourceVersion time.Time
		require.NoError(t, json.Unmarshal(body["source_version"], &sourceVersion))
		require.True(t, decisionAt.Equal(sourceVersion))
		var certificate struct {
			Tuple   struct{ User, Relation, Object string } `json:"tuple"`
			Command struct {
				ParentProjectID string   `json:"parent_project_id"`
				ParentAccountID string   `json:"parent_account_id"`
				ParentChain     []string `json:"parent_chain"`
			} `json:"command"`
			NewScopes []struct {
				Registered           bool
				ProjectID, AccountID string
			} `json:"new_scopes"`
		}
		require.NoError(t, json.Unmarshal(body["certificate"], &certificate))
		require.Equal(t, "recheck_container:"+parent, certificate.Tuple.User)
		require.Equal(t, "parent", certificate.Tuple.Relation)
		require.Equal(t, "recheck_child:"+child, certificate.Tuple.Object)
		require.Equal(t, scene.Project, certificate.Command.ParentProjectID)
		require.Equal(t, scene.Account, certificate.Command.ParentAccountID)
		require.Equal(t, []string{"recheck_container:" + parent, "project:" + scene.Project, "account:" + scene.Account}, certificate.Command.ParentChain)
		require.Len(t, certificate.NewScopes, 1)
		require.True(t, certificate.NewScopes[0].Registered)
		require.Equal(t, scene.Project, certificate.NewScopes[0].ProjectID)
		require.Equal(t, scene.Account, certificate.NewScopes[0].AccountID)
		var program struct {
			Changed bool `json:"changed"`
			Steps   []struct {
				Kind string `json:"kind"`
			} `json:"steps"`
			Receipts []json.RawMessage `json:"receipts"`
			Pointers []json.RawMessage `json:"pointers"`
		}
		require.NoError(t, json.Unmarshal(body["program"], &program))
		require.True(t, program.Changed)
		require.NotEmpty(t, program.Steps)
		require.Empty(t, program.Receipts, "parent registration must not create registration_owner receipts")
		require.Empty(t, program.Pointers, "parent is a relation fact, not a named pointer receipt")
		var parentWrite struct {
			Fact struct {
				ObjectType    string    `json:"object_type"`
				ObjectID      string    `json:"object_id"`
				Relation      string    `json:"relation"`
				Subject       string    `json:"subject"`
				SourceVersion time.Time `json:"source_version"`
			} `json:"fact"`
		}
		require.NoError(t, json.Unmarshal(body["parent_write"], &parentWrite))
		require.Equal(t, "recheck_child", parentWrite.Fact.ObjectType)
		require.Equal(t, child, parentWrite.Fact.ObjectID)
		require.Equal(t, "parent", parentWrite.Fact.Relation)
		require.Equal(t, "recheck_container:"+parent, parentWrite.Fact.Subject)
		require.True(t, decisionAt.Equal(parentWrite.Fact.SourceVersion))
		var receipt struct {
			UserID string `json:"user_id"`
		}
		require.NoError(t, json.Unmarshal(body["receipt"], &receipt))
		require.Equal(t, userID, receipt.UserID)
		var audit struct {
			EventPayload struct {
				Actor string `json:"actor"`
			} `json:"event_payload"`
		}
		require.NoError(t, json.Unmarshal(body["audit"], &audit))
		require.Equal(t, "user:"+userID, audit.EventPayload.Actor)
		var mirrorCount, receiptCount int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type='recheck.child' AND object_id=$1),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='recheck.child' AND child_id=$1)`, child).Scan(&mirrorCount, &receiptCount))
		require.Zero(t, mirrorCount, "the compiler does not persist the proposed mirror")
		require.Zero(t, receiptCount, "the compiler does not persist the proposed receipt")
	})
	t.Run("closed parent branches before requiring a direct census", func(t *testing.T) {
		var closed map[string]any
		require.NoError(t, json.Unmarshal(witness, &closed))
		closed["closed_at"] = version
		delete(closed, "live_children")
		delete(closed, "recent_creations")
		encoded, err := json.Marshal(closed)
		require.NoError(t, err)
		body, err := compile(encoded, []byte(`{}`), []byte(`[]`))
		require.NoError(t, err)
		require.JSONEq(t, `"parent_closed"`, string(body["outcome"]))
		require.Empty(t, body["program"])
	})
	t.Run("new parent incarnation uses the caller reserved UUID", func(t *testing.T) {
		var uninitialized map[string]any
		require.NoError(t, json.Unmarshal(witness, &uninitialized))
		uninitialized["parent_incarnation"] = nil
		encoded, err := json.Marshal(uninitialized)
		require.NoError(t, err)
		const reserved = "de305d54-75b4-431b-adb2-eb6b9e546014"
		var result []byte
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_program_v1(
 $1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb,$5,$6,$7,$8,$9::uuid)`,
			encoded, index, r.bundle.CanonicalCatalog(), catalogRows, userID, auditID, decisionAt, transactionAt, reserved).Scan(&result))
		var body struct {
			Outcome     string `json:"outcome"`
			ParentState struct {
				Incarnation string `json:"incarnation"`
			} `json:"parent_state"`
			Receipt struct {
				ParentIncarnation string `json:"parent_incarnation"`
			} `json:"receipt"`
		}
		require.NoError(t, json.Unmarshal(result, &body))
		require.Equal(t, "create", body.Outcome)
		require.Equal(t, reserved, body.ParentState.Incarnation)
		require.Equal(t, reserved, body.Receipt.ParentIncarnation)
	})
	t.Run("runtime cannot invoke the owner private compiler", func(t *testing.T) {
		_, err := r.runtime.Exec(r.ctx, `SELECT kaname._authority_child_registration_program_v1(
 $1::jsonb,$2::jsonb,$3::jsonb,$4::jsonb,$5,$6,$7,$8)`,
			witness, index, r.bundle.CanonicalCatalog(), catalogRows, userID, auditID, decisionAt, transactionAt)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "42501", pe.Code)
	})
}

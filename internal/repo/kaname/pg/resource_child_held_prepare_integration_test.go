// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"log/slog"
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
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Фикстура использует тот же production RR stage и reconciler права, что
// TestUserChildStageRRCapturesAuthorizedModuleParentAndAbsentChild. Подготовка
// FULL выполняется после установочных записей; owner proof создаётся отдельно
// в каждой RC попытке, а не подставляется в JSON.
func childHeldPreparationFixture(t *testing.T) (protocolRig, json.RawMessage) {
	t.Helper()
	r, owner := writerProtocolRigBeforePreparation(t)
	const declaration = `apiVersion: iam/v1
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
    childRegistration: {verb: registerChild, parentSegments: 1, maxChildren: 24, maxCreates: 4, windowSeconds: 60}
`
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
			{Module: "childstage", Resource: "child", ObjectType: "childstage_child", ParentNames: []string{"parent"}, ParentTypes: []string{"childstage_container"}, ChildRegistration: &catalog.ChildRegistrationRule{Verb: "registerchild", ParentSegments: 1, MaxChildren: 24, MaxCreates: 4, WindowSeconds: 60}},
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
	const parentID, childID = "container-one", "container-one/candidate"
	version := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id,parent_project_id,source_version)
 VALUES('childstage.container',$1,$2,$3,$4)`, parentID, scene.Account, scene.Project, version)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_registration_scope(object_type,object_id,project_id,account_id)
 VALUES('childstage_container',$1,$2,$3)`, parentID, scene.Project, scene.Account)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject,source_version)
 VALUES('childstage_container',$1,'project','project:'||$2::text,$3)`, parentID, scene.Project, version)
	require.NoError(t, err)
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
	var holders int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples
 WHERE binding_id=$1 AND member_object_type='childstage.container' AND member_object_id=$2
 AND fga_user=$3 AND relation='child_registrar' AND object=$4`, binding, parentID, "user:"+actor, "childstage_container:"+parentID).Scan(&holders))
	require.Positive(t, holders, "предпосылка: настоящий producer подтвердил право на модульном родителе")

	principal := operations.Principal{Type: "user", ID: actor}
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	fullContractActivate(t, r)
	tx, err := r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	probe, err := kanamepg.ProbeUserChildStage(ctx, tx, r.bundle,
		kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: childID}, principal)
	require.NoError(t, err)
	require.True(t, probe.SameLifetime)
	require.NotEmpty(t, probe.Envelope)
	require.NoError(t, tx.Rollback(context.WithoutCancel(ctx)))
	return r, probe.Envelope
}

func TestUserChildHeldPreparationRequiresSignedOwnerAndEqualRRSources(t *testing.T) {
	r, envelope := childHeldPreparationFixture(t)
	identity := r.bundle.Identity()
	open := func(t *testing.T, profile string) pgx.Tx {
		t.Helper()
		tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		switch profile {
		case "resource_source_pending":
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_source_enter_v3(
 'global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		case "resource_pending":
			_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_enter_v3(
 'global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
		case "":
		default:
			t.Fatalf("unexpected fixture profile %q", profile)
		}
		require.NoError(t, err)
		if profile != "" {
			var proof struct {
				Contract  int    `json:"writer_contract"`
				Profile   string `json:"consumer_profile"`
				Finalized bool   `json:"consumer_finalized"`
			}
			var raw []byte
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_protocol_attestation()`).Scan(&raw))
			require.NoError(t, json.Unmarshal(raw, &proof))
			require.Equal(t, 2, proof.Contract)
			require.Equal(t, profile, proof.Profile)
			require.False(t, proof.Finalized)
		}
		return tx
	}
	hold := func(tx pgx.Tx, payload json.RawMessage) (json.RawMessage, int, int, error) {
		var prepared json.RawMessage
		var rows, reads int
		err := tx.QueryRow(r.ctx, `SELECT prepared,logical_rows,logical_reads
 FROM kaname._authority_child_registration_hold_v1($1::jsonb,100000,4096)`, payload).Scan(&prepared, &rows, &reads)
		return prepared, rows, reads, err
	}
	refuses := func(t *testing.T, profile string, payload json.RawMessage, code string) {
		t.Helper()
		tx := open(t, profile)
		_, _, _, err := hold(tx, payload)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, code, pe.Code)
		require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
	}
	mutate := func(t *testing.T, change func(map[string]any)) json.RawMessage {
		t.Helper()
		var value map[string]any
		require.NoError(t, json.Unmarshal(envelope, &value))
		change(value)
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		return raw
	}
	t.Run("owner without signed entry is refused", func(t *testing.T) {
		refuses(t, "", envelope, "42501")
	})
	t.Run("ordinary resource profile cannot substitute source profile", func(t *testing.T) {
		refuses(t, "resource_pending", envelope, "42501")
	})
	t.Run("other intent kind is refused", func(t *testing.T) {
		payload := mutate(t, func(value map[string]any) {
			value["intent"].(map[string]any)["kind"] = "resource_registration"
		})
		refuses(t, "resource_source_pending", payload, "42501")
	})
	t.Run("parent mirror must equal its captured RR state", func(t *testing.T) {
		payload := mutate(t, func(value map[string]any) {
			found := false
			for _, raw := range value["sources"].([]any) {
				capture := raw.(map[string]any)
				if capture["kind"] == float64(2) && capture["type"] == "childstage.container" && capture["id"] == "container-one" {
					require.NotEmpty(t, capture["states"], "предпосылка: stage прочитал реальный parent mirror")
					capture["states"] = []any{}
					found = true
				}
			}
			require.True(t, found)
		})
		refuses(t, "resource_source_pending", payload, "P1034")
	})
	t.Run("signed source owner preserves fresh private witness", func(t *testing.T) {
		tx := open(t, "resource_source_pending")
		prepared, rows, reads, err := hold(tx, envelope)
		require.NoError(t, err)
		require.Positive(t, rows)
		require.Positive(t, reads)
		require.LessOrEqual(t, rows, 100000)
		require.LessOrEqual(t, reads, 4096)
		var state struct {
			Witness       json.RawMessage `json:"witness"`
			Intent        json.RawMessage `json:"intent"`
			Backend       json.RawMessage `json:"backend"`
			TransactionID json.RawMessage `json:"transaction_id"`
			Nonce         json.RawMessage `json:"nonce"`
			NativeEpochs  json.RawMessage `json:"native_epochs"`
		}
		require.NoError(t, json.Unmarshal(prepared, &state))
		require.NotEmpty(t, state.Witness)
		var proposed struct {
			Intent       json.RawMessage `json:"intent"`
			NativeEpochs json.RawMessage `json:"native_epochs"`
		}
		require.NoError(t, json.Unmarshal(envelope, &proposed))
		require.JSONEq(t, string(proposed.Intent), string(state.Intent))
		require.JSONEq(t, string(proposed.NativeEpochs), string(state.NativeEpochs))
		var signed map[string]json.RawMessage
		var attestation []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_protocol_attestation()`).Scan(&attestation))
		require.NoError(t, json.Unmarshal(attestation, &signed))
		for key, captured := range map[string]json.RawMessage{
			"backend": state.Backend, "transaction_id": state.TransactionID, "nonce": state.Nonce,
		} {
			require.NotEmpty(t, captured, key)
			require.NotEqual(t, "null", string(captured), key)
			require.JSONEq(t, string(signed[key]), string(captured), "prepared должен принадлежать тому же signed owner: %s", key)
		}
		var current []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT witness FROM kaname._authority_child_registration_capture_v1(
 'childstage.child','container-one/candidate',100000,4096)`).Scan(&current))
		require.JSONEq(t, string(current), string(state.Witness), "закрытый снимок равен настоящим источникам под тем же ограждением")
		var witness struct {
			ChildType     string     `json:"child_type"`
			ChildID       string     `json:"child_id"`
			ParentType    string     `json:"parent_type"`
			ParentID      string     `json:"parent_id"`
			ParentAction  string     `json:"parent_action"`
			ParentVersion time.Time  `json:"parent_version"`
			ChildVersion  *time.Time `json:"child_version"`
		}
		require.NoError(t, json.Unmarshal(state.Witness, &witness))
		require.Equal(t, "childstage.child", witness.ChildType)
		require.Equal(t, "container-one/candidate", witness.ChildID)
		require.Equal(t, "childstage.container", witness.ParentType)
		require.Equal(t, "container-one", witness.ParentID)
		require.Equal(t, "child_registrar", witness.ParentAction)
		require.Equal(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), witness.ParentVersion)
		require.Nil(t, witness.ChildVersion)
		var childExists bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type='childstage.child' AND object_id='container-one/candidate')`).Scan(&childExists))
		require.False(t, childExists, "hold готовит источники, но ещё не исполняет создание")
		require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
	})
}

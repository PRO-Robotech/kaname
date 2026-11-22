// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func childHeldPreparationFixture(t *testing.T) (protocolRig, json.RawMessage) {
	t.Helper()
	r, owner, _, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
	fullContractActivate(t, r)
	tx, err := r.runtime.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	probe, err := kanamepg.ProbeUserChildStage(ctx, tx, r.bundle,
		kaname.UserChildRegistrationInput{ResourceType: "childstage.child", ResourceID: "container-one/candidate"}, principal)
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
		require.Equal(t, time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC), witness.ParentVersion.UTC())
		require.Nil(t, witness.ChildVersion)
		var childExists bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type='childstage.child' AND object_id='container-one/candidate')`).Scan(&childExists))
		require.False(t, childExists, "hold готовит источники, но ещё не исполняет создание")
		require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
	})
}

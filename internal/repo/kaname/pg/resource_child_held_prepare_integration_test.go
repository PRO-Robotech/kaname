// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func childHeldPreparationFixture(t *testing.T, closed bool) (protocolRig, json.RawMessage) {
	t.Helper()
	r, owner, _, principal := childStageFixture(t)
	ctx := operations.WithPrincipal(r.ctx, principal)
	if closed {
		_, err := r.admin.Exec(ctx, `INSERT INTO kaname.authority_child_parent_state(object_type,object_id,closed_at)
 VALUES('childstage.container','container-one',clock_timestamp())`)
		require.NoError(t, err)
	}
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
	r, envelope := childHeldPreparationFixture(t, false)
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
	t.Run("omitting captured output holder census is refused", func(t *testing.T) {
		payload := mutate(t, func(value map[string]any) {
			captures := value["sources"].([]any)
			kept := make([]any, 0, len(captures))
			removed := 0
			for _, raw := range captures {
				capture := raw.(map[string]any)
				// kind 35 — все ledger holders, именующие объект; пустота
				// тоже обязательный источник полного OUTPUT-графа.
				if capture["kind"] == float64(35) && capture["type"] == "childstage_child" && capture["id"] == "container-one/candidate" {
					require.Empty(t, capture["states"], "проверяется отсутствие нового потомка")
					removed++
					continue
				}
				kept = append(kept, raw)
			}
			require.Equal(t, 1, removed, "удаляем настоящий exact RR predicate, а не добавленный тестом ключ")
			value["sources"] = kept
		})
		refuses(t, "resource_source_pending", payload, "42501")
	})
	t.Run("select rejects changed private witness without binding a slot", func(t *testing.T) {
		tx := open(t, "resource_source_pending")
		prepared, _, _, err := hold(tx, envelope)
		require.NoError(t, err)
		var changed map[string]any
		require.NoError(t, json.Unmarshal(prepared, &changed))
		witness := changed["witness"].(map[string]any)
		liveChildren, ok := witness["live_children"].(float64)
		require.True(t, ok)
		witness["live_children"] = liveChildren + 1
		tampered, err := json.Marshal(changed)
		require.NoError(t, err)
		var before []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&before))
		var decisionAt time.Time
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&decisionAt))
		_, err = tx.Exec(r.ctx, `SAVEPOINT child_select_tamper`)
		require.NoError(t, err)
		var result []byte
		err = tx.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_select_v1($1::jsonb,$2)`, tampered, decisionAt).Scan(&result)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "42501", pe.Code)
		_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT child_select_tamper`)
		require.NoError(t, err)
		var after []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&after))
		require.JSONEq(t, string(before), string(after), "подменённый prepared не меняет зарезервированную программу")
		var sequence struct {
			Selected json.RawMessage `json:"selected"`
		}
		require.NoError(t, json.Unmarshal(after, &sequence))
		require.JSONEq(t, "null", string(sequence.Selected))
		require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
	})
	t.Run("signed source owner preserves fresh private witness", func(t *testing.T) {
		tx := open(t, "resource_source_pending")
		prepared, rows, reads, err := hold(tx, envelope)
		require.NoError(t, err)
		require.Positive(t, rows)
		require.Positive(t, reads)
		require.LessOrEqual(t, rows, 100000)
		require.LessOrEqual(t, reads, 4096)
		type relationLock struct {
			OID  uint32 `json:"oid,string"`
			Mode string `json:"mode"`
		}
		var state struct {
			Witness       json.RawMessage `json:"witness"`
			Intent        json.RawMessage `json:"intent"`
			Backend       json.RawMessage `json:"backend"`
			TransactionID json.RawMessage `json:"transaction_id"`
			Nonce         json.RawMessage `json:"nonce"`
			NativeEpochs  json.RawMessage `json:"native_epochs"`
			Maximum       struct {
				PolicyEpochs  map[string]string   `json:"policy_epochs"`
				BindingEpochs map[string]string   `json:"binding_epochs"`
				Operations    map[string][]string `json:"operations"`
			} `json:"maximum"`
			EpochWitness struct {
				PolicyBefore map[string]json.RawMessage `json:"policy_before"`
				PolicyAfter  map[string]json.RawMessage `json:"policy_after"`
				BindingAfter map[string]json.RawMessage `json:"binding_after"`
			} `json:"epoch_witness"`
			Required     map[string]bool `json:"required"`
			Reservations struct {
				AuditID      string  `json:"audit_id"`
				ReconcileIDs []int64 `json:"reconcile_ids"`
				FGASlot      int     `json:"fga_slot"`
			} `json:"reservations"`
			HeldRelations []relationLock `json:"held_relations"`
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
		var intent struct {
			AuditID string `json:"audit_id"`
			Actor   string `json:"actor"`
		}
		require.NoError(t, json.Unmarshal(proposed.Intent, &intent))
		require.NotEmpty(t, intent.AuditID)
		require.Equal(t, intent.AuditID, state.Reservations.AuditID)
		require.Len(t, state.Reservations.ReconcileIDs, 1)
		require.Positive(t, state.Reservations.ReconcileIDs[0])
		require.Equal(t, 1, state.Reservations.FGASlot)
		var programRaw []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&programRaw))
		var sequence struct {
			Family   string          `json:"family"`
			Selected json.RawMessage `json:"selected"`
			Frozen   struct {
				Kind   string          `json:"kind"`
				Intent json.RawMessage `json:"intent"`
			} `json:"frozen"`
			Maximum []struct {
				Table      string          `json:"table"`
				Ordinal    int             `json:"ordinal"`
				ReservedID int64           `json:"reserved_id"`
				Row        json.RawMessage `json:"row"`
			} `json:"maximum"`
		}
		require.NoError(t, json.Unmarshal(programRaw, &sequence))
		require.Equal(t, "resource", sequence.Family)
		require.JSONEq(t, "null", string(sequence.Selected))
		require.Equal(t, "child_registration", sequence.Frozen.Kind)
		require.JSONEq(t, string(proposed.Intent), string(sequence.Frozen.Intent))
		require.Len(t, sequence.Maximum, 1)
		fga := sequence.Maximum[0]
		require.Equal(t, "fga_outbox", fga.Table)
		require.Equal(t, state.Reservations.FGASlot, fga.Ordinal)
		require.Positive(t, fga.ReservedID)
		require.JSONEq(t, "{}", string(fga.Row))
		for _, relation := range state.HeldRelations {
			var held bool
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='relation'
 AND relation=$1 AND mode=$2 AND granted)`, relation.OID, relation.Mode).Scan(&held))
			require.True(t, held, "зарезервированное отношение %d должно оставаться под %s", relation.OID, relation.Mode)
		}
		for _, name := range []string{"authority_child_parent_state", "authority_child_creation", "fga_outbox", "audit_outbox", "resource_reconcile_outbox"} {
			var oid uint32
			require.NoError(t, tx.QueryRow(r.ctx, `SELECT $1::text::regclass::oid`, "kaname."+name).Scan(&oid))
			require.Contains(t, state.HeldRelations, relationLock{OID: oid, Mode: "RowExclusiveLock"})
		}
		var auditExists, reconcileExists, fgaExists bool
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.audit_outbox WHERE id=$1),
 EXISTS(SELECT 1 FROM kaname.resource_reconcile_outbox WHERE id=$2),
 EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE id=$3)`,
			intent.AuditID, state.Reservations.ReconcileIDs[0], fga.ReservedID).Scan(&auditExists, &reconcileExists, &fgaExists))
		require.False(t, auditExists)
		require.False(t, reconcileExists)
		require.False(t, fgaExists)
		// После подготовки точные OUTPUT epoch keys удерживаются для записи.
		// Scope берём из того же реального родителя, который проверил hold.
		var account, project, childEpoch string
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT parent_account_id,parent_project_id,
 'object:'||jsonb_build_array('childstage.child','container-one/candidate')::text
 FROM kaname.resource_mirror WHERE object_type='childstage.container' AND object_id='container-one'`).Scan(&account, &project, &childEpoch))
		require.NotEmpty(t, account)
		require.NotEmpty(t, project)
		require.Equal(t, "write", state.Maximum.PolicyEpochs[childEpoch])
		require.Equal(t, "write", state.Maximum.PolicyEpochs["scope:account:"+account])
		require.Equal(t, "write", state.Maximum.BindingEpochs[account])
		for table, operations := range map[string][]string{
			"resource_mirror":         {"INSERT", "UPDATE"},
			"fga_outbox":              {"INSERT"},
			"producer_source_receipt": {"UPDATE"},
			"audit_outbox":            {"INSERT"},
		} {
			for _, operation := range operations {
				require.Contains(t, state.Maximum.Operations[table], operation, "maximum обязан покрывать %s %s", table, operation)
			}
		}
		// RR сравнивается с policy_before по исходным native keys. Полный
		// policy_after отдельно содержит созданные/удержанные OUTPUT epochs.
		var nativeBefore map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(proposed.NativeEpochs, &nativeBefore))
		require.NotEmpty(t, nativeBefore)
		for key, value := range nativeBefore {
			require.Contains(t, state.EpochWitness.PolicyBefore, key)
			require.JSONEq(t, string(value), string(state.EpochWitness.PolicyBefore[key]))
		}
		for _, key := range []string{childEpoch, "scope:account:" + account} {
			require.Contains(t, state.EpochWitness.PolicyAfter, key)
			require.NotEqual(t, "null", string(state.EpochWitness.PolicyAfter[key]))
		}
		require.Contains(t, state.EpochWitness.BindingAfter, account)
		require.NotEqual(t, "null", string(state.EpochWitness.BindingAfter[account]))
		// JSON-ключи декодируются, чтобы проверка не зависела от пробелов
		// PostgreSQL. 21/22 — object members/ledger; 35 — fact ledger holders.
		type sourceKey struct {
			Kind                 int
			Type, ID, Projection string
		}
		required := make(map[sourceKey]bool, len(state.Required))
		for key, enabled := range state.Required {
			var parts []json.RawMessage
			require.NoError(t, json.Unmarshal([]byte(key), &parts))
			require.Len(t, parts, 4)
			var decoded sourceKey
			require.NoError(t, json.Unmarshal(parts[0], &decoded.Kind))
			require.NoError(t, json.Unmarshal(parts[1], &decoded.Type))
			require.NoError(t, json.Unmarshal(parts[2], &decoded.ID))
			require.NoError(t, json.Unmarshal(parts[3], &decoded.Projection))
			required[decoded] = enabled
		}
		for _, key := range []sourceKey{
			{Kind: 4, Type: "childstage_container", ID: "container-one"},
			{Kind: 1, Type: "project", ID: project},
			{Kind: 21, Type: "childstage.child", ID: "container-one/candidate"},
			{Kind: 22, Type: "childstage.child", ID: "container-one/candidate"},
			{Kind: 35, Type: "childstage_child", ID: "container-one/candidate"},
		} {
			require.True(t, required[key], "required обязан включать scope и полный OUTPUT census: %+v", key)
		}
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
		// Единственное время решения берём у PostgreSQL после всех проверок
		// hold. Выбор программы связывает уже зарезервированный journal slot.
		var decisionAt time.Time
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&decisionAt))
		var resultRaw []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_select_v1($1::jsonb,$2)`, prepared, decisionAt).Scan(&resultRaw))
		var result struct {
			Outcome       string    `json:"outcome"`
			SourceVersion time.Time `json:"source_version"`
			Receipt       struct {
				UserID        string    `json:"user_id"`
				CreatedAt     time.Time `json:"created_at"`
				SourceVersion time.Time `json:"source_version"`
			} `json:"receipt"`
			Audit struct {
				ID      string `json:"id"`
				Payload struct {
					Actor string `json:"actor"`
				} `json:"event_payload"`
			} `json:"audit"`
			ParentWrite struct {
				Journal json.RawMessage `json:"journal"`
			} `json:"parent_write"`
			RegistrationBody json.RawMessage `json:"registration_body"`
		}
		require.NoError(t, json.Unmarshal(resultRaw, &result))
		require.Equal(t, "create", result.Outcome)
		require.True(t, decisionAt.Equal(result.SourceVersion), "новая версия этого ключа равна точному DecisionAt")
		require.Equal(t, intent.Actor, result.Receipt.UserID)
		require.True(t, decisionAt.Equal(result.Receipt.CreatedAt))
		require.True(t, result.SourceVersion.Equal(result.Receipt.SourceVersion))
		require.Equal(t, intent.AuditID, result.Audit.ID)
		require.Equal(t, "user:"+intent.Actor, result.Audit.Payload.Actor)
		require.NotEmpty(t, result.ParentWrite.Journal)
		require.NotEqual(t, "null", string(result.ParentWrite.Journal))
		type packedEntry struct {
			Command int             `json:"command"`
			Row     json.RawMessage `json:"row"`
		}
		type packedCommand struct {
			Kind    string          `json:"kind"`
			Row     json.RawMessage `json:"row"`
			Journal json.RawMessage `json:"journal"`
		}
		var packed struct {
			Physical struct {
				Commands  []packedCommand `json:"commands"`
				Audits    []packedEntry   `json:"audits"`
				Outboxes  []packedEntry   `json:"outboxes"`
				Reconcile []packedEntry   `json:"reconcile"`
			} `json:"physical"`
			StepObligations map[string]struct {
				Audits    []string `json:"audits"`
				Reconcile []int64  `json:"reconcile"`
			} `json:"step_obligations"`
			Writes  []json.RawMessage `json:"writes"`
			Program struct {
				Commands []packedCommand `json:"commands"`
			} `json:"program"`
			Result struct {
				Outcome       string    `json:"outcome"`
				SourceVersion time.Time `json:"source_version"`
			} `json:"result"`
		}
		require.NoError(t, json.Unmarshal(result.RegistrationBody, &packed))
		require.NotEmpty(t, packed.Writes)
		require.Equal(t, packed.Physical.Commands, packed.Program.Commands)
		require.Equal(t, "create", packed.Result.Outcome)
		require.True(t, result.SourceVersion.Equal(packed.Result.SourceVersion))
		require.Len(t, packed.Physical.Audits, 1)
		audit := packed.Physical.Audits[0]
		require.Positive(t, audit.Command)
		require.LessOrEqual(t, audit.Command, len(packed.Physical.Commands))
		var auditRow struct {
			ID      string `json:"id"`
			Payload struct {
				Actor string `json:"actor"`
			} `json:"event_payload"`
		}
		require.NoError(t, json.Unmarshal(audit.Row, &auditRow))
		require.Equal(t, state.Reservations.AuditID, auditRow.ID)
		require.Equal(t, "user:"+intent.Actor, auditRow.Payload.Actor)
		require.Equal(t, "registration_audit", packed.Physical.Commands[audit.Command-1].Kind)
		require.JSONEq(t, string(audit.Row), string(packed.Physical.Commands[audit.Command-1].Row))
		require.Equal(t, []string{state.Reservations.AuditID}, packed.StepObligations[strconv.Itoa(audit.Command)].Audits)
		auditCommands := 0
		for _, command := range packed.Physical.Commands {
			if command.Kind == "registration_audit" {
				auditCommands++
			}
		}
		require.Equal(t, 1, auditCommands, "дополнительного модульного аудита в программе нет")
		require.Len(t, packed.Physical.Outboxes, 1)
		outbox := packed.Physical.Outboxes[0]
		require.Positive(t, outbox.Command)
		require.LessOrEqual(t, outbox.Command, len(packed.Physical.Commands))
		require.JSONEq(t, string(result.ParentWrite.Journal), string(outbox.Row))
		require.Equal(t, "registration_journal", packed.Physical.Commands[outbox.Command-1].Kind)
		require.JSONEq(t, string(outbox.Row), string(packed.Physical.Commands[outbox.Command-1].Journal))
		require.Len(t, packed.Physical.Reconcile, 1)
		reconcile := packed.Physical.Reconcile[0]
		var reconcileRow struct {
			ID int64 `json:"id"`
		}
		require.NoError(t, json.Unmarshal(reconcile.Row, &reconcileRow))
		require.Equal(t, state.Reservations.ReconcileIDs[0], reconcileRow.ID)
		require.Equal(t, []int64{reconcileRow.ID}, packed.StepObligations[strconv.Itoa(reconcile.Command)].Reconcile)
		var selectedRaw []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&selectedRaw))
		var bound struct {
			Selected []struct {
				Table      string          `json:"table"`
				Ordinal    int             `json:"ordinal"`
				ReservedID int64           `json:"reserved_id"`
				Row        json.RawMessage `json:"row"`
				Origin     struct {
					Command int `json:"command"`
				} `json:"origin"`
			} `json:"selected"`
		}
		require.NoError(t, json.Unmarshal(selectedRaw, &bound))
		require.Len(t, bound.Selected, 1)
		require.Equal(t, "fga_outbox", bound.Selected[0].Table)
		require.Equal(t, fga.Ordinal, bound.Selected[0].Ordinal)
		require.Equal(t, fga.ReservedID, bound.Selected[0].ReservedID, "выбор сохраняет ранее зарезервированный ID")
		require.JSONEq(t, string(result.ParentWrite.Journal), string(bound.Selected[0].Row))
		require.Equal(t, outbox.Command, bound.Selected[0].Origin.Command, "sequence origin связан с фактической физической командой журнала")
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE id=$1)`, fga.ReservedID).Scan(&fgaExists))
		require.False(t, fgaExists, "select связывает программу; dispatcher ещё не записывал journal")
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.audit_outbox WHERE id=$1),
 EXISTS(SELECT 1 FROM kaname.resource_reconcile_outbox WHERE id=$2),
 EXISTS(SELECT 1 FROM kaname.resource_mirror WHERE object_type='childstage.child' AND object_id='container-one/candidate')`,
			state.Reservations.AuditID, state.Reservations.ReconcileIDs[0]).Scan(&auditExists, &reconcileExists, &childExists))
		require.False(t, auditExists)
		require.False(t, reconcileExists)
		require.False(t, childExists, "упаковка физических команд ещё не исполняет DML")
		require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
	})
}

// Закрытый родитель остаётся зарегистрированным и имеет действующее право
// пользователя. Отказ следует из owner-held состояния, а не из подмены RR.
func TestUserChildHeldSelectionClosedParentHasNoCreationSlots(t *testing.T) {
	r, envelope := childHeldPreparationFixture(t, true)
	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_source_enter_v3(
 'global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	var prepared []byte
	var rows, reads int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT prepared,logical_rows,logical_reads
 FROM kaname._authority_child_registration_hold_v1($1::jsonb,100000,4096)`, envelope).Scan(&prepared, &rows, &reads))
	require.Positive(t, rows)
	require.Positive(t, reads)
	require.LessOrEqual(t, rows, 100000)
	require.LessOrEqual(t, reads, 4096)
	var state struct {
		Intent struct {
			AuditID string `json:"audit_id"`
		} `json:"intent"`
		Witness struct {
			ClosedAt *time.Time `json:"closed_at"`
		} `json:"witness"`
		Reservations struct {
			AuditID string `json:"audit_id"`
		} `json:"reservations"`
	}
	require.NoError(t, json.Unmarshal(prepared, &state))
	require.NotNil(t, state.Witness.ClosedAt)
	require.NotEmpty(t, state.Reservations.AuditID)
	require.Equal(t, state.Intent.AuditID, state.Reservations.AuditID)
	var auditHeld bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_catalog.pg_locks
 WHERE pid=pg_backend_pid() AND locktype='relation' AND relation='kaname.audit_outbox'::regclass
 AND mode='RowExclusiveLock' AND granted)`).Scan(&auditHeld))
	require.True(t, auditHeld)
	var before []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&before))
	var sequence struct {
		MaximumCount int             `json:"maximum_count"`
		Maximum      json.RawMessage `json:"maximum"`
		Selected     json.RawMessage `json:"selected"`
	}
	require.NoError(t, json.Unmarshal(before, &sequence))
	require.Zero(t, sequence.MaximumCount)
	require.JSONEq(t, "[]", string(sequence.Maximum))
	require.JSONEq(t, "null", string(sequence.Selected))
	var decisionAt time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&decisionAt))
	var resultRaw []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_child_registration_select_v1($1::jsonb,$2)`, prepared, decisionAt).Scan(&resultRaw))
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(resultRaw, &result))
	require.JSONEq(t, `"parent_closed"`, string(result["outcome"]))
	require.JSONEq(t, "null", string(result["source_version"]))
	require.NotContains(t, result, "receipt")
	require.NotContains(t, result, "parent_write")
	var after []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&after))
	require.NoError(t, json.Unmarshal(after, &sequence))
	require.Zero(t, sequence.MaximumCount)
	require.JSONEq(t, "[]", string(sequence.Maximum))
	require.JSONEq(t, "[]", string(sequence.Selected))
	var fgaExists, receiptExists, auditExists bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT
 EXISTS(SELECT 1 FROM kaname.fga_outbox WHERE payload->>'object'='childstage_child:container-one/candidate'),
 EXISTS(SELECT 1 FROM kaname.authority_child_creation WHERE child_type='childstage.child' AND child_id='container-one/candidate'),
 EXISTS(SELECT 1 FROM kaname.audit_outbox WHERE id=$1)`, state.Reservations.AuditID).Scan(&fgaExists, &receiptExists, &auditExists))
	require.False(t, fgaExists)
	require.False(t, receiptExists)
	require.False(t, auditExists, "аудит пока только зарезервирован; dispatcher не исполнялся")
	require.NoError(t, tx.Rollback(context.WithoutCancel(r.ctx)))
}

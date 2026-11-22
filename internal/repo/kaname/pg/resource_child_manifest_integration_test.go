// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Подготовка и единственное время решения принадлежат owner. Финальный
// manifest пока не открывает body и не разрешает незавершённый COMMIT.
func TestUserChildPrivateManifestFinalizesOnceWithoutOpeningBody(t *testing.T) {
	r, envelope := childHeldPreparationFixture(t, false)
	var proposal struct {
		Intent json.RawMessage `json:"intent"`
	}
	require.NoError(t, json.Unmarshal(envelope, &proposal))
	denied := func(t *testing.T, err error) {
		t.Helper()
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "42501", pe.Code)
	}
	for _, function := range []string{"_authority_child_registration_prepare_v1", "_authority_child_registration_finalize_v1"} {
		t.Run("runtime cannot execute "+function, func(t *testing.T) {
			var allowed bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, "kaname."+function+"(jsonb,integer,integer)").Scan(&allowed))
			require.False(t, allowed)
			payload := envelope
			if function == "_authority_child_registration_finalize_v1" {
				payload = proposal.Intent
			}
			_, err := r.runtime.Exec(r.ctx, "SELECT * FROM kaname."+function+"($1::jsonb,100000,4096)", payload)
			denied(t, err)
		})
	}

	tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	identity := r.bundle.Identity()
	_, err = tx.Exec(r.ctx, `SELECT kaname.authority_resource_source_enter_v3(
 'global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, identity.ModelID, identity.CatalogID, identity.ProjectorVersion)
	require.NoError(t, err)
	var rows, reads int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT logical_rows,logical_reads
 FROM kaname._authority_child_registration_prepare_v1($1::jsonb,100000,4096)`, envelope).Scan(&rows, &reads))
	require.Positive(t, rows)
	require.Positive(t, reads)
	require.LessOrEqual(t, rows, 100000)
	require.LessOrEqual(t, reads, 4096)
	type manifestState struct {
		State      string          `json:"state"`
		Intent     json.RawMessage `json:"intent"`
		DecisionAt *time.Time      `json:"decision_at"`
		Writes     json.RawMessage `json:"writes"`
		Body       struct {
			Prepared json.RawMessage `json:"prepared"`
			Selected json.RawMessage `json:"selected"`
		} `json:"registration_body"`
	}
	readManifest := func() manifestState {
		t.Helper()
		var raw []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT to_jsonb(m) FROM pg_temp.kaname_authority_resource_manifest m`).Scan(&raw))
		var manifest manifestState
		require.NoError(t, json.Unmarshal(raw, &manifest))
		return manifest
	}
	type proofState struct {
		Finalized  bool      `json:"consumer_finalized"`
		DecisionAt time.Time `json:"decision_at"`
	}
	readProof := func() proofState {
		t.Helper()
		var raw []byte
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_protocol_attestation()`).Scan(&raw))
		var proof proofState
		require.NoError(t, json.Unmarshal(raw, &proof))
		return proof
	}
	before := readManifest()
	require.Equal(t, "prepared", before.State)
	require.JSONEq(t, string(proposal.Intent), string(before.Intent))
	require.Nil(t, before.DecisionAt)
	require.JSONEq(t, "[]", string(before.Writes))
	require.NotEmpty(t, before.Body.Prepared)
	require.NotEqual(t, "null", string(before.Body.Prepared))
	require.JSONEq(t, "null", string(before.Body.Selected))
	require.False(t, readProof().Finalized)

	var lower, decisionAt, upper time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&lower))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT decision_at,logical_rows,logical_reads
 FROM kaname._authority_child_registration_finalize_v1($1::jsonb,100000,4096)`, proposal.Intent).Scan(&decisionAt, &rows, &reads))
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT clock_timestamp()`).Scan(&upper))
	require.False(t, decisionAt.Before(lower))
	require.False(t, decisionAt.After(upper))
	require.GreaterOrEqual(t, rows, 0)
	require.GreaterOrEqual(t, reads, 0)
	require.LessOrEqual(t, rows, 100000)
	require.LessOrEqual(t, reads, 4096)
	after := readManifest()
	require.Equal(t, "final", after.State)
	require.NotNil(t, after.DecisionAt)
	require.True(t, decisionAt.Equal(*after.DecisionAt))
	require.JSONEq(t, string(before.Intent), string(after.Intent))
	require.JSONEq(t, string(before.Body.Prepared), string(after.Body.Prepared))
	require.JSONEq(t, "[]", string(after.Writes), "выбор программы не даёт обычному body право записи")
	proof := readProof()
	require.True(t, proof.Finalized)
	require.True(t, decisionAt.Equal(proof.DecisionAt))
	var selected struct {
		Outcome       string    `json:"outcome"`
		DecisionAt    time.Time `json:"decision_at"`
		SourceVersion time.Time `json:"source_version"`
		Receipt       struct {
			CreatedAt time.Time `json:"created_at"`
		} `json:"receipt"`
		RegistrationBody json.RawMessage `json:"registration_body"`
	}
	require.NoError(t, json.Unmarshal(after.Body.Selected, &selected))
	require.Equal(t, "create", selected.Outcome)
	require.True(t, decisionAt.Equal(selected.DecisionAt))
	require.True(t, decisionAt.Equal(selected.SourceVersion))
	require.True(t, decisionAt.Equal(selected.Receipt.CreatedAt))
	require.NotEmpty(t, selected.RegistrationBody)
	require.NotEqual(t, "null", string(selected.RegistrationBody))
	var sequenceRaw []byte
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname._authority_sequence_store_v3()`).Scan(&sequenceRaw))
	var sequence struct {
		Selected []json.RawMessage `json:"selected"`
	}
	require.NoError(t, json.Unmarshal(sequenceRaw, &sequence))
	require.Len(t, sequence.Selected, 1)
	var childExists bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.resource_mirror
 WHERE object_type='childstage.child' AND object_id='container-one/candidate')`).Scan(&childExists))
	require.False(t, childExists)

	// SAVEPOINT позволяет проверить каждый отказ на том же финальном
	// manifest, не подменяя его и не открывая новую попытку.
	for _, query := range []string{
		`SELECT * FROM kaname._authority_child_registration_finalize_v1($1::jsonb,100000,4096)`,
		`SELECT kaname.authority_resource_assert_body_v2($1::jsonb)`,
	} {
		_, err = tx.Exec(r.ctx, `SAVEPOINT child_manifest_refusal`)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, query, proposal.Intent)
		denied(t, err)
		_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT child_manifest_refusal`)
		require.NoError(t, err)
		require.Equal(t, "final", readManifest().State)
	}
	_, err = tx.Exec(r.ctx, `SAVEPOINT child_manifest_completion`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SET CONSTRAINTS ALL IMMEDIATE`)
	denied(t, err)
	_, err = tx.Exec(r.ctx, `ROLLBACK TO SAVEPOINT child_manifest_completion`)
	require.NoError(t, err)
	denied(t, tx.Commit(context.WithoutCancel(r.ctx)))
}

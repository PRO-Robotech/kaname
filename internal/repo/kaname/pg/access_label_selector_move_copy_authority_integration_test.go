// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestRoleMoveCopyAuthorityChecksOnlyFinalKeysFromHeldRoots(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	actor := bindingPublicOwner(t, r)
	ready := seedAccessDefinition(t, r, "account", r.a, "stage", "ready")
	seedAccessDefinition(t, r, "account", r.a, "extra", "local")
	seedMetadataActualApplySource(t, r, actor, ready.id)

	var old json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `UPDATE ONLY kaname.accounts a SET labels='{"stage":"ready","extra":"local"}'
		WHERE id=$1 RETURNING jsonb_build_array(xmin::text,ctid::text,to_jsonb(a))`, r.a).Scan(&old))
	const holdSQL = `SELECT kaname._authority_role_move_copy_requirements_hold_v1($1::jsonb,'user',$2,1000,100)`
	const requireSQL = `SELECT kaname._authority_role_move_copy_requirements_require_v1($1::jsonb,$2::jsonb,'user',$3,$4,1000,100)`
	type finalCopy struct {
		Type   string            `json:"root_type"`
		ID     string            `json:"root_id"`
		Labels map[string]string `json:"new_access_labels"`
	}
	all := map[string]string{"stage": "ready", "extra": "local"}
	plan, err := json.Marshal([]map[string]any{{
		"root_type": "iam.account", "root_id": r.a, "physical": old, "new_access_labels": all,
	}})
	require.NoError(t, err)

	for _, tc := range []struct {
		name, id, actor string
		labels          map[string]string
		duplicate       bool
		wantDenied      bool
	}{
		{"непроверенный ключ выпал до финальных часов", r.a, actor, map[string]string{"stage": "ready"}, false, false},
		{"оставшийся неразрешённый ключ", r.a, actor, all, false, true},
		{"подменённое значение", r.a, actor, map[string]string{"stage": "other"}, false, true},
		{"чужой объект", r.b, actor, map[string]string{"stage": "ready"}, false, true},
		{"чужой актёр", r.a, "usr-other", map[string]string{"stage": "ready"}, false, true},
		{"повтор того же объекта", r.a, actor, map[string]string{"stage": "ready"}, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx, err := r.admin.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			var held json.RawMessage
			require.NoError(t, tx.QueryRow(r.ctx, holdSQL, plan, actor).Scan(&held))
			copies := []finalCopy{{Type: "iam.account", ID: tc.id, Labels: tc.labels}}
			if tc.duplicate {
				copies = append(copies, copies[0])
			}
			final, err := json.Marshal(copies)
			require.NoError(t, err)
			var at time.Time
			require.NoError(t, tx.QueryRow(r.ctx, "SELECT clock_timestamp()").Scan(&at))
			var decision struct {
				Commands json.RawMessage `json:"commands"`
			}
			err = tx.QueryRow(r.ctx, requireSQL, held, final, tc.actor, at).Scan(&decision)
			if tc.wantDenied {
				requireAccessDefinitionSQLState(t, err, "42501")
			} else {
				require.NoError(t, err)
				want, err := json.Marshal([]map[string]any{{
					"root_type": "iam.account", "root_id": r.a, "table": "accounts",
					"physical": old, "access_labels": tc.labels,
				}})
				require.NoError(t, err)
				require.JSONEq(t, string(want), string(decision.Commands))
				var unchanged json.RawMessage
				require.NoError(t, tx.QueryRow(r.ctx, `SELECT jsonb_build_array(xmin::text,ctid::text,to_jsonb(a))
					FROM ONLY kaname.accounts a WHERE id=$1`, r.a).Scan(&unchanged))
				require.JSONEq(t, string(old), string(unchanged))
			}
		})
	}
	t.Run("наследуемый реестр допустимых значений", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, `CREATE TABLE kaname.copy_probe_inherited_value ()
		    INHERITS (kaname.authority_access_label_value)`)
		require.NoError(t, err)
		_, err = tx.Exec(r.ctx, holdSQL, plan, actor)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("часы до удержания ключей", func(t *testing.T) {
		tx, err := r.admin.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		var before time.Time
		require.NoError(t, tx.QueryRow(r.ctx, "SELECT clock_timestamp()").Scan(&before))
		var held json.RawMessage
		require.NoError(t, tx.QueryRow(r.ctx, holdSQL, plan, actor).Scan(&held))
		_, err = tx.Exec(r.ctx, requireSQL, held, `[]`, actor, before)
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	t.Run("квитанция из завершившейся транзакции", func(t *testing.T) {
		var held json.RawMessage
		require.NoError(t, r.admin.QueryRow(r.ctx, holdSQL, plan, actor).Scan(&held))
		_, err := r.admin.Exec(r.ctx, requireSQL, held, `[]`, actor, time.Now().UTC())
		requireAccessDefinitionSQLState(t, err, "42501")
	})
	_, err = r.runtime.Exec(r.ctx, holdSQL, plan, actor)
	requireAccessDefinitionSQLState(t, err, "42501")
}

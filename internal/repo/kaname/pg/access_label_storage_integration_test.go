// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelStorageRejectsRawChangesInEveryProfile(t *testing.T) {
	for _, phase := range []string{"uninitialized", "prepared", "transition", "active", "full"} {
		t.Run(phase, func(t *testing.T) {
			r, owner := writerProtocolRigBeforePreparation(t)
			var uid string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&uid))
			project := kac127SeedProject(t, r.ctx, r.admin, r.a, "access-label-storage")
			sa := seedSA(t, r.ctx, owner, domain.AccountID(r.a), "access-label-storage")
			binding := groupLifecycleBinding(t, r, r.a, uid, "access_label_storage", domain.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"get"}})
			var role string
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT role_id FROM kaname.access_bindings WHERE id=$1`, string(binding)).Scan(&role))
			_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-access-storage',$1,'access-storage')`, r.a)
			require.NoError(t, err)
			_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.resource_mirror(object_type,object_id,parent_account_id) VALUES('compute.instance','access-storage',$1)`, r.a)
			require.NoError(t, err)
			if phase == "full" {
				_, _ = fullContractActivate(t, r)
			} else if phase != "uninitialized" {
				require.NoError(t, owner.StageAuthorityBundle(r.ctx, r.bundle))
				if phase == "active" {
					require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
				} else if phase == "transition" {
					require.NoError(t, owner.CloseAuthorityBundle(r.ctx))
				}
			}
			for _, row := range []struct{ table, key, id string }{
				{"accounts", "id", r.a}, {"projects", "id", project}, {"users", "id", uid},
				{"service_accounts", "id", string(sa.ID)}, {"groups", "id", "grp-access-storage"},
				{"roles", "id", role}, {"access_bindings", "id", string(binding)},
				{"resource_mirror", "object_id", "access-storage"},
			} {
				t.Run(row.table, func(t *testing.T) {
					// Имена таблиц/ключей принадлежат закрытой переписи, не caller input.
					update := fmt.Sprintf(`UPDATE kaname.%s SET access_labels='{"trust":"yes"}' WHERE %s=$1`, row.table, row.key)
					insert := fmt.Sprintf(`INSERT INTO kaname.%s(access_labels) SELECT '{"trust":"yes"}'::jsonb WHERE $1::text<>''`, row.table)
					insertArgs := []any{row.id}
					if row.table == "access_bindings" {
						// Старый триггер первым проверяет, что роль можно выдать в этой области.
						insert = `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,scope,status,access_labels)
						 SELECT $2,subject_type,subject_id,role_id,resource_type,resource_id,scope,'PENDING','{"trust":"yes"}'::jsonb
						 FROM kaname.access_bindings WHERE id=$1`
						insertArgs = append(insertArgs, ids.NewID("acb"))
					}
					for _, check := range []struct {
						op, sql string
						args    []any
					}{
						{"UPDATE", update, []any{row.id}},
						{"INSERT", insert, insertArgs},
					} {
						_, err := r.runtime.Exec(r.ctx, check.sql, check.args...)
						var denied *pgconn.PgError
						require.ErrorAs(t, err, &denied, check.op)
						require.Equal(t, "42501", denied.Code, "%s: %s", check.op, denied.Message)
						if phase != "active" && phase != "full" {
							require.Contains(t, denied.Message, "access label mutation requires a protected writer")
						}
					}
					var labels string
					require.NoError(t, r.runtime.QueryRow(r.ctx, fmt.Sprintf(`SELECT access_labels::text FROM kaname.%s WHERE %s=$1`, row.table, row.key), row.id).Scan(&labels))
					require.JSONEq(t, `{}`, labels)
				})
			}
			var valid bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
			require.True(t, valid)
		})
	}
}

func TestAccessLabelStorageKeepsOrdinaryEmptyCRUDAndRejectsOwnerBypass(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	_, err := r.runtime.Exec(r.ctx, `INSERT INTO kaname.groups(id,account_id,name) VALUES('grp-empty-access',$1,'empty-access')`, r.a)
	require.NoError(t, err)
	_, err = r.runtime.Exec(r.ctx, `UPDATE kaname.groups SET description='ordinary update',access_labels=access_labels WHERE id='grp-empty-access'`)
	require.NoError(t, err)
	var description, labels string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT description,access_labels::text FROM kaname.groups WHERE id='grp-empty-access'`).Scan(&description, &labels))
	require.Equal(t, "ordinary update", description)
	require.JSONEq(t, `{}`, labels)
	// Даже прямой owner UPDATE не получает принимающий путь из current_user.
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.groups SET access_labels='{"trust":"yes"}' WHERE id='grp-empty-access'`)
	var denied *pgconn.PgError
	require.ErrorAs(t, err, &denied)
	require.Equal(t, "42501", denied.Code)
	require.Contains(t, denied.Message, "access label mutation requires a protected writer")
	result, err := r.runtime.Exec(r.ctx, `DELETE FROM kaname.groups WHERE id='grp-empty-access'`)
	require.NoError(t, err)
	require.EqualValues(t, 1, result.RowsAffected())
	var publicGuard, privateControl, protected bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
	 has_function_privilege(current_user,'kaname.access_labels_immutable_v1()','EXECUTE'),
	 has_function_privilege(current_user,'kaname.authority_protocol_attestation()','EXECUTE'),
	 kaname.authority_access_label_storage_valid_v1()`).Scan(&publicGuard, &privateControl, &protected))
	require.False(t, publicGuard)
	require.False(t, privateControl)
	require.True(t, protected)
}

func TestAccessLabelStorageValidatesTypesAndByteBoundaries(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	encode := func(value any) string {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		return string(raw)
	}
	entries := map[string]string{}
	for i := 0; i < 64; i++ {
		entries[fmt.Sprintf("key%d", i)] = ""
	}
	sixtyFour := encode(entries)
	entries["overflow"] = ""
	for _, tc := range []struct {
		name, raw string
		valid     bool
	}{
		{"empty", `{}`, true}, {"null", `null`, false}, {"array", `[]`, false},
		{"number-value", `{"key":1}`, false}, {"null-value", `{"key":null}`, false},
		{"object-value", `{"key":{}}`, false}, {"boolean-value", `{"key":true}`, false},
		{"empty-key", `{"":"value"}`, false}, {"uppercase-key", `{"Key":"value"}`, false},
		{"valid-key-alphabet", `{"a-b_c.d/e@f":""}`, true},
		{"key-63", encode(map[string]string{strings.Repeat("k", 63): ""}), true},
		{"key-64", encode(map[string]string{strings.Repeat("k", 64): ""}), false},
		{"value-63", encode(map[string]string{"key": strings.Repeat("v", 63)}), true},
		{"value-64", encode(map[string]string{"key": strings.Repeat("v", 64)}), false},
		{"unicode-62-bytes", encode(map[string]string{"key": strings.Repeat("я", 31)}), true},
		{"unicode-64-bytes", encode(map[string]string{"key": strings.Repeat("я", 32)}), false},
		{"entries-64", sixtyFour, true}, {"entries-65", encode(entries), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var valid bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.access_labels_valid_v1($1::jsonb)`, tc.raw).Scan(&valid))
			require.Equal(t, tc.valid, valid)
		})
	}
	var valid bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.access_labels_valid_v1(NULL)`).Scan(&valid))
	require.False(t, valid)
}

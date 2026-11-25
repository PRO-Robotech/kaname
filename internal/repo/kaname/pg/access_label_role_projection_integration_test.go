// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const accessRoleProjectionMigration = "20261124010000_access_label_role_projection_stays_private.sql"
const accessRoleProjectionInsert = `INSERT INTO kaname.authority_role_access_label_rule(role_id,rule_fp,definition_id) VALUES($1,$2,$3::uuid)`

func TestAccessLabelRoleProjectionPrivateAfterRuntimeRegrant(t *testing.T) {
	for _, phase := range []string{"uninitialized", "prepared", "transition", "active", "full"} {
		t.Run(phase, func(t *testing.T) {
			r, owner := writerProtocolRigBeforePreparation(t)
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
			for pass := 0; pass < 2; pass++ {
				_, err := r.admin.Exec(r.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, r.role)
				require.NoError(t, err)
				var exposed bool
				require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_role_access_label_rule','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
				 OR has_function_privilege(current_user,'kaname.authority_role_access_label_rule_closed_v1()','EXECUTE')`).Scan(&exposed))
				require.False(t, exposed)
				for _, sql := range []string{
					`SELECT * FROM kaname.authority_role_access_label_rule`,
					`INSERT INTO kaname.authority_role_access_label_rule VALUES('rol-denied',repeat('a',64),'00000000-0000-0000-0000-000000000001')`,
					`UPDATE kaname.authority_role_access_label_rule SET rule_fp=rule_fp`,
					`DELETE FROM kaname.authority_role_access_label_rule`,
					`TRUNCATE kaname.authority_role_access_label_rule`,
				} {
					_, err = r.runtime.Exec(r.ctx, sql)
					requireAccessDefinitionSQLState(t, err, "42501")
				}
			}
			// Отказ owner исходит от собственного guard даже в compatibility,
			// а не от runtime ACL, strict attestation или отсутствующей FK-строки.
			for _, sql := range []string{
				`INSERT INTO kaname.authority_role_access_label_rule SELECT 'rol-denied',repeat('a',64),'00000000-0000-0000-0000-000000000001'::uuid WHERE false`,
				`UPDATE kaname.authority_role_access_label_rule SET rule_fp=rule_fp`,
				`DELETE FROM kaname.authority_role_access_label_rule`,
				`TRUNCATE kaname.authority_role_access_label_rule`,
			} {
				_, err := r.admin.Exec(r.ctx, sql)
				requireAccessDefinitionSQLState(t, err, "42501")
				require.Contains(t, err.Error(), "access label role projection requires a protected writer")
			}
			var count int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_role_access_label_rule`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

// Только проверка физических constraints/Down: owner DDL временно снимает
// guard внутри откатываемой фикстуры. Это не принимающий продуктовый writer.
func accessRoleProjectionPhysicalFixture(t *testing.T, r protocolRig) (pgx.Tx, string, string) {
	t.Helper()
	role := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "access_projection")
	definition := seedAccessDefinition(t, r, "account", r.a, "projection")
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, accessRoleProjectionInsert, string(role), strings.Repeat("a", 64), definition.id)
	require.NoError(t, err)
	return tx, string(role), definition.id
}

func TestAccessLabelRoleProjectionExactShapeAndReferences(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	// Пустая новая проекция не препятствует прежнему удалению роли.
	unreferenced := seedAccountRole(t, r.ctx, r.admin, domain.AccountID(r.a), "access_unreferenced")
	_, err := r.runtime.Exec(r.ctx, `DELETE FROM kaname.roles WHERE id=$1`, string(unreferenced))
	require.NoError(t, err)
	other := seedAccessDefinition(t, r, "account", r.b, "projection")
	tx, role, definition := accessRoleProjectionPhysicalFixture(t, r)
	for _, check := range []struct {
		name, sql, state string
		args             []any
	}{
		{"duplicate", accessRoleProjectionInsert, "23505", []any{role, strings.Repeat("a", 64), definition}},
		{"fingerprint", accessRoleProjectionInsert, "23514", []any{role, "*", definition}},
		{"missing-role", accessRoleProjectionInsert, "23503", []any{"rol-missing-projection", strings.Repeat("b", 64), definition}},
		{"missing-definition", accessRoleProjectionInsert, "23503", []any{role, strings.Repeat("b", 64), "00000000-0000-0000-0000-000000000001"}},
		{"delete-definition", `DELETE FROM kaname.authority_access_label_definition WHERE id=$1::uuid`, "23503", []any{definition}},
		{"delete-role", `DELETE FROM kaname.roles WHERE id=$1`, "23503", []any{role}},
	} {
		t.Run(check.name, func(t *testing.T) {
			attempt, err := tx.Begin(r.ctx)
			require.NoError(t, err)
			_, err = attempt.Exec(r.ctx, check.sql, check.args...)
			requireAccessDefinitionSQLState(t, err, check.state)
			require.NoError(t, attempt.Rollback(r.ctx))
		})
	}
	// Один definition может иметь несколько явных rule origins; PK включает FP.
	_, err = tx.Exec(r.ctx, accessRoleProjectionInsert, role, strings.Repeat("b", 64), definition)
	require.NoError(t, err)
	// Другой UUID того же ключа в другой области остаётся отдельной целью.
	_, err = tx.Exec(r.ctx, accessRoleProjectionInsert, role, strings.Repeat("a", 64), other.id)
	require.NoError(t, err)
	var indexed, private bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT EXISTS(
	 SELECT 1 FROM pg_index i JOIN pg_attribute a ON a.attrelid=i.indrelid AND a.attname='definition_id'
	 WHERE i.indrelid='kaname.authority_role_access_label_rule'::regclass
	 AND i.indexrelid='kaname.authority_role_access_label_rule_definition_idx'::regclass
	 AND i.indisvalid AND i.indnkeyatts=1 AND i.indkey[0]=a.attnum AND i.indpred IS NULL),
	 NOT EXISTS(SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) a
	 WHERE c.oid='kaname.authority_role_access_label_rule'::regclass AND a.grantee<>c.relowner)`).Scan(&indexed, &private))
	require.True(t, indexed)
	require.True(t, private)
	_, err = tx.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	for _, sql := range []string{
		`INSERT INTO kaname.authority_role_access_label_rule SELECT * FROM kaname.authority_role_access_label_rule`,
		`UPDATE kaname.authority_role_access_label_rule SET rule_fp=rule_fp`,
		`DELETE FROM kaname.authority_role_access_label_rule`,
		`TRUNCATE kaname.authority_role_access_label_rule`,
	} {
		attempt, err := tx.Begin(r.ctx)
		require.NoError(t, err)
		_, err = attempt.Exec(r.ctx, sql)
		requireAccessDefinitionSQLState(t, err, "42501")
		require.NoError(t, attempt.Rollback(r.ctx))
	}
	var count int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_role_access_label_rule`).Scan(&count))
	require.Equal(t, 3, count)
	require.NoError(t, tx.Rollback(r.ctx))
}

func TestAccessLabelRoleProjectionDownPreservesRowsAndEmptyRoundTrip(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	restore := accessLabelSuspendMigrations(t, r, accessLabelFreshnessMigration, accessLabelSelectorSourceMigration, accessLabelSelectorCanonicalMigration, accessLabelRoleAtomicProjectionMigration, accessLabelRoleSourceReceiptsMigration, accessLabelRoleOwnerCensusMigration, accessLabelRoleNativeReadMigration, accessLabelRoleNativeSourceMigration, accessLabelRoleQuestionReceiptMigration, accessLabelBindingDefinitionCustodyMigration, accessLabelDefinitionCustodyMigration, accessLabelRoleCheckpointReadMigration, accessLabelNativeSourceMigration, accessLabelRoleProjectionWriteMigration)
	up, down := accessLabelMigrationParts(t, accessRoleProjectionMigration)
	tx, _, _ := accessRoleProjectionPhysicalFixture(t, r)
	_, err := tx.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	attempt, err := tx.Begin(r.ctx)
	require.NoError(t, err)
	_, err = attempt.Exec(r.ctx, down)
	requireAccessDefinitionSQLState(t, err, "55000")
	require.NoError(t, attempt.Rollback(r.ctx))
	var count int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_role_access_label_rule`).Scan(&count))
	require.Equal(t, 1, count)
	require.NoError(t, tx.Rollback(r.ctx))

	tx, err = r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	_, err = tx.Exec(r.ctx, down)
	require.NoError(t, err)
	var absent, valid bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT to_regclass('kaname.authority_role_access_label_rule') IS NULL,
	 kaname._authority_full_contract_storage_v3()`).Scan(&absent, &valid))
	require.True(t, absent)
	require.True(t, valid)
	// Проверяем Up также при нежелательных owner default ACL. Все DDL и
	// default privileges остаются в этой откатываемой транзакции.
	quoted := pgx.Identifier{r.role}.Sanitize()
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT ALL ON TABLES TO `+quoted)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `ALTER DEFAULT PRIVILEGES IN SCHEMA kaname GRANT EXECUTE ON FUNCTIONS TO `+quoted)
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, up)
	require.NoError(t, err)
	var exposed bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT has_table_privilege($1,'kaname.authority_role_access_label_rule','SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')
	 OR has_function_privilege($1,'kaname.authority_role_access_label_rule_closed_v1()','EXECUTE')`, r.role).Scan(&exposed))
	require.False(t, exposed)
	_, err = tx.Exec(r.ctx, `TRUNCATE kaname.authority_role_access_label_rule`)
	requireAccessDefinitionSQLState(t, err, "42501")
	require.NoError(t, tx.Rollback(r.ctx))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()`).Scan(&valid))
	require.True(t, valid, "старый physical authority closure не меняется")
	restore()
}

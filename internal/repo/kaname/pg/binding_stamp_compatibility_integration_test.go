// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/require"
)

// Реальный compare entry, без подмены attestation или выдачи private ACL.
// Discovery выполняется до нового RC TX; здесь проверяется только SQL adapter,
// а полный Go same-writer union остаётся в semantic_normalizer integration test.
func bindingStampCompareTx(t *testing.T, r protocolRig, mode string) pgx.Tx {
	t.Helper()
	var epochs, population []byte
	var expectedRows int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname.authority_compare_epoch_read_v2(ARRAY['*']::text[]),
 jsonb_build_object('generation',p.generation,'count',p.row_count,'revision',p.revision_sum),p.row_count
 FROM kaname.authority_policy_population_read(100000) p`).Scan(&epochs, &population, &expectedRows))
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	accounts := []string{}
	if mode == "accounts" {
		accounts = []string{r.a}
	}
	identity := r.bundle.Identity()
	var at time.Time
	var rows int
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT decision_at,population_rows FROM kaname.authority_compare_full_v2($1,$2::text[],$3,$4,$5,$6::jsonb,$7::jsonb,$8)`, mode, accounts, identity.ModelID, identity.CatalogID, identity.ProjectorVersion, epochs, population, 100000).Scan(&at, &rows))
	require.False(t, at.IsZero())
	require.Equal(t, expectedRows, rows)
	return tx
}

func bindingStampMissingRows(t *testing.T, r protocolRig, id string) {
	t.Helper()
	var parents, subjects int
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.access_bindings WHERE id=$1),
 (SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id=$1)`, id).Scan(&parents, &subjects))
	require.Zero(t, parents)
	require.Zero(t, subjects)
}

func TestBindingInsertStampUnsignedGlobalCompareRollback(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	uid := bindingPublicOwner(t, r)
	rid := seedAccountRulesRole(t, r.ctx, r.admin, owner, domain.AccountID(r.a), "stamp_global", domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}})
	r.bundle = semanticBundleDB(t, r.ctx, r.admin)
	// Active identity служит только compare component; strict не включается.
	semanticFixtureIdentity(t, r.ctx, r.admin, r.bundle)
	tx := bindingStampCompareTx(t, r, "global")
	id := ids.NewID(domain.PrefixAccessBinding)
	var stamp pgtype.Timestamptz
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_insert_stamp_v3($1)`, id).Scan(&stamp))
	require.False(t, stamp.Valid, "unsigned GLOBAL compare не имеет prepared timestamp")
	// NULL наблюдается через экспортированный stamp; private ACL проверяется без вызова функции.
	var canInspectAttestation bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_catalog.has_function_privilege(current_user, 'kaname.authority_protocol_attestation()', 'EXECUTE')`).Scan(&canInspectAttestation))
	require.False(t, canInspectAttestation, "runtime LOGIN не получает EXECUTE private attestation")
	// Те же parent -> capability -> subjects DML, что у capability port/helper.
	_, err := tx.Exec(r.ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status)
 VALUES($1,'user',$2,$3,'account',$4,'ACTIVE')`, id, uid, string(rid), r.a)
	require.NoError(t, err)
	tag, err := tx.Exec(r.ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1 AND grant_capability_version=0`, id)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	_, err = tx.Exec(r.ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES($1,'user',$2)`, id, uid)
	require.NoError(t, err)
	var version, subjects int
	var created time.Time
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT b.grant_capability_version,b.created_at,
 (SELECT count(*) FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id AND s.subject_type='user' AND s.subject_id=$2)
 FROM kaname.access_bindings b WHERE b.id=$1`, id, uid).Scan(&version, &created, &subjects))
	require.Equal(t, 1, version)
	require.False(t, created.IsZero())
	require.Equal(t, 1, subjects)
	bindingStampMissingRows(t, r, id)
	require.NoError(t, tx.Rollback(r.ctx))
	bindingStampMissingRows(t, r, id)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingInsertStampRawCompatibilityNull(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	id := ids.NewID(domain.PrefixAccessBinding)
	var stamp pgtype.Timestamptz
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_insert_stamp_v3($1)`, id).Scan(&stamp))
	require.False(t, stamp.Valid, "raw compatibility NULL не является compare или D1 proof")
	// NULL наблюдается через экспортированный stamp; private ACL проверяется без вызова функции.
	var canInspectAttestation bool
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT pg_catalog.has_function_privilege(current_user, 'kaname.authority_protocol_attestation()', 'EXECUTE')`).Scan(&canInspectAttestation))
	require.False(t, canInspectAttestation, "runtime LOGIN не получает EXECUTE private attestation")
	require.NoError(t, tx.Rollback(r.ctx))
	bindingStampMissingRows(t, r, id)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingInsertStampScopedCompareRefuses(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	semanticFixtureIdentity(t, r.ctx, r.admin, r.bundle)
	tx := bindingStampCompareTx(t, r, "accounts")
	id := ids.NewID(domain.PrefixAccessBinding)
	var stamp pgtype.Timestamptz
	err := tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_insert_stamp_v3($1)`, id).Scan(&stamp)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Equal(t, "compare source reader cannot become a local writer", pe.Message)
	require.NoError(t, tx.Rollback(r.ctx))
	bindingStampMissingRows(t, r, id)
	authorityWaitReleased(t, r.runtime)
}

func TestBindingInsertStampStrictUnsignedRefuses(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	id := ids.NewID(domain.PrefixAccessBinding)
	var stamp pgtype.Timestamptz
	err = tx.QueryRow(r.ctx, `SELECT kaname.authority_binding_insert_stamp_v3($1)`, id).Scan(&stamp)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Equal(t, "authority transaction attestation required", pe.Message)
	require.NoError(t, tx.Rollback(r.ctx))
	bindingStampMissingRows(t, r, id)
	authorityWaitReleased(t, r.runtime)
}

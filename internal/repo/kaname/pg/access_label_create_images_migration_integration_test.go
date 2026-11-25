// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAccessLabelCreateImagesMigrationRestoresSignedClosure(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	// Более поздняя миграция закрепляет новые SHA тех же compiler/census.
	// Проверяем 040000 на её настоящем predecessor, затем возвращаем latest.
	restore := accessLabelSuspendMigrations(t, r, accessLabelFreshnessMigration, accessLabelSelectorSourceMigration, accessLabelSelectorCanonicalMigration, accessLabelRoleAtomicProjectionMigration, accessLabelRoleSourceReceiptsMigration, accessLabelRoleOwnerCensusMigration, accessLabelRoleNativeReadMigration, accessLabelRoleNativeSourceMigration, accessLabelRoleQuestionReceiptMigration, accessLabelBindingDefinitionCustodyMigration, accessLabelDefinitionCustodyMigration, accessLabelRoleCheckpointReadMigration, accessLabelNativeSourceMigration, accessLabelRoleProjectionWriteMigration)
	sequenceUp, sequenceDown := accessLabelMigrationParts(t, accessLabelRoleSequenceMigration)
	_, err := r.admin.Exec(r.ctx, sequenceDown)
	require.NoError(t, err)
	up, down := accessLabelMigrationParts(t, "20261124040000_exact_create_images_include_access_labels.sql")
	signatures := []string{
		"_authority_crud_domain_images_v3(jsonb,jsonb,jsonb,timestamptz)",
		"authority_binding_sequence_prepare_v3(text,jsonb)",
		"authority_role_sequence_prepare_v3(jsonb,integer,integer)",
		"_authority_resource_registration_mirror_images_v2(jsonb,jsonb,jsonb,jsonb,jsonb,timestamptz)",
		"_authority_crud_storage_v3()",
		"_authority_full_contract_storage_v3()",
	}
	type snapshot struct {
		metadata string
		digests  []string
	}
	inspect := func() snapshot {
		t.Helper()
		var valid bool
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()
		AND kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
		require.True(t, valid)
		var out snapshot
		var count int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*),
		 jsonb_agg(jsonb_build_array(p.oid,p.proowner,p.proacl,p.prosecdef,p.provolatile,p.proconfig) ORDER BY s.ordinal)::text,
		 array_agg(encode(sha256(convert_to(p.prosrc,'UTF8')),'hex') ORDER BY s.ordinal)
		 FROM unnest($1::text[]) WITH ORDINALITY s(signature,ordinal)
		 JOIN pg_catalog.pg_proc p ON p.oid=to_regprocedure('kaname.'||s.signature)`, signatures).
			Scan(&count, &out.metadata, &out.digests))
		require.Equal(t, len(signatures), count)
		return out
	}
	// Каждый шаг Goose выполняется в новой транзакции. Тестовая БД выделена отдельно.
	installed := inspect()
	_, err = r.admin.Exec(r.ctx, down)
	require.NoError(t, err)
	previous := inspect()
	require.Equal(t, installed.metadata, previous.metadata)
	for i, signature := range signatures {
		require.NotEqual(t, installed.digests[i], previous.digests[i], signature)
	}
	_, err = r.admin.Exec(r.ctx, up)
	require.NoError(t, err)
	require.Equal(t, installed, inspect())
	_, err = r.admin.Exec(r.ctx, sequenceUp)
	require.NoError(t, err)
	restore()
	var valid bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT kaname._authority_full_contract_storage_v3()
	 AND kaname.authority_access_label_storage_valid_v1()`).Scan(&valid))
	require.True(t, valid)
}

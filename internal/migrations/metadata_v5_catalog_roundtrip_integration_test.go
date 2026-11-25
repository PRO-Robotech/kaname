// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestMetadataV5PreservesPublishedCatalogAndChildRegistrationOnRoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен PostgreSQL")
	}
	db := openP2(t).db
	own, before := versionsOf(t, "20261123150000_metadata_labels_hold_binding_candidate_root.sql")
	staged, beforeStaged := versionsOf(t, "20261123200000_staged_metadata_keeps_signed_effect_proof.sql")
	require.Equal(t, own, beforeStaged)
	require.NoError(t, goose.UpTo(db, ".", before))

	type storedFunction struct {
		definition string
		owner      uint32
		acl        string
	}
	snapshot := func(signatures []string) map[string]storedFunction {
		t.Helper()
		out := make(map[string]storedFunction, len(signatures))
		for _, signature := range signatures {
			var fn storedFunction
			require.NoError(t, db.QueryRow(`
                SELECT pg_catalog.pg_get_functiondef(p.oid), p.proowner, coalesce(p.proacl::text, '')
                FROM pg_catalog.pg_proc p WHERE p.oid=pg_catalog.to_regprocedure($1)
            `, signature).Scan(&fn.definition, &fn.owner, &fn.acl), signature)
			out[signature] = fn
		}
		return out
	}
	inherited := []string{
		"kaname.authority_protocol_statement_guard()",
		"kaname._authority_child_runtime_storage_v1()",
		"kaname.authority_child_registration_begin_body_v1(jsonb)",
		"kaname._authority_resource_materialized_types_v2(jsonb,integer,jsonb)",
		"kaname._authority_binding_census_projection_v3(jsonb,jsonb,integer,jsonb)",
		"kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)",
	}
	updated := []string{
		"kaname.authority_metadata_preflight_v4(text,text,boolean,text,jsonb)",
		"kaname.authority_protocol_grant_runtime(regrole)",
		"kaname._authority_crud_storage_v3()",
		"kaname._authority_full_contract_storage_v3()",
	}
	const metadataV5 = "kaname.authority_metadata_preflight_v5(text,text,boolean,text,jsonb)"
	const rowGuard = "kaname.authority_protocol_row_guard()"
	stagedExports := []string{
		"kaname.authority_metadata_preflight_staged_v1(text,text,boolean,text,jsonb)",
		"kaname.authority_metadata_staged_ready_v1(text,text,text)",
	}
	fullContractReady := func() {
		t.Helper()
		var ready bool
		require.NoError(t, db.QueryRow(`
            SELECT kaname._authority_full_contract_storage_v3()
               AND kaname._authority_child_runtime_storage_v1()
        `).Scan(&ready))
		require.True(t, ready)
	}
	functionExists := func(signature string) bool {
		t.Helper()
		var present bool
		require.NoError(t, db.QueryRow("SELECT pg_catalog.to_regprocedure($1) IS NOT NULL", signature).Scan(&present))
		return present
	}

	fullContractReady()
	mainInherited, mainUpdated := snapshot(inherited), snapshot(updated)
	mainRowGuard := snapshot([]string{rowGuard})[rowGuard]
	require.False(t, functionExists(metadataV5))

	require.NoError(t, goose.UpTo(db, ".", own))
	fullContractReady()
	require.True(t, functionExists(metadataV5))
	require.Equal(t, mainInherited, snapshot(inherited))
	composed := snapshot(updated)
	for _, signature := range updated {
		require.NotEqual(t, mainUpdated[signature].definition, composed[signature].definition, signature)
		require.Equal(t, mainUpdated[signature].owner, composed[signature].owner, signature)
		require.Equal(t, mainUpdated[signature].acl, composed[signature].acl, signature)
	}

	// Второй шаг расширяет staged ABI и меняет row guard. Откат этого
	// шага возвращает именно первый согласованный контракт и прежние ACL.
	require.NoError(t, goose.UpTo(db, ".", staged))
	fullContractReady()
	require.True(t, functionExists(metadataV5))
	for _, signature := range stagedExports {
		require.True(t, functionExists(signature), signature)
	}
	require.Equal(t, mainInherited, snapshot(inherited))
	stagedRowGuard := snapshot([]string{rowGuard})[rowGuard]
	require.NotEqual(t, mainRowGuard.definition, stagedRowGuard.definition)
	require.Equal(t, mainRowGuard.owner, stagedRowGuard.owner)
	require.Equal(t, mainRowGuard.acl, stagedRowGuard.acl)
	stagedState := snapshot(updated)
	stagedDefinitions := snapshot(stagedExports)

	require.NoError(t, goose.DownTo(db, ".", own))
	fullContractReady()
	require.Equal(t, composed, snapshot(updated))
	require.Equal(t, mainRowGuard, snapshot([]string{rowGuard})[rowGuard])
	for _, signature := range stagedExports {
		require.False(t, functionExists(signature), signature)
	}

	require.NoError(t, goose.DownTo(db, ".", before))
	fullContractReady()
	require.False(t, functionExists(metadataV5))
	require.Equal(t, mainInherited, snapshot(inherited))
	require.Equal(t, mainUpdated, snapshot(updated))

	require.NoError(t, goose.UpTo(db, ".", own))
	fullContractReady()
	require.True(t, functionExists(metadataV5))
	require.Equal(t, mainInherited, snapshot(inherited))
	require.Equal(t, composed, snapshot(updated))
	require.NoError(t, goose.UpTo(db, ".", staged))
	fullContractReady()
	require.Equal(t, stagedState, snapshot(updated))
	require.Equal(t, stagedDefinitions, snapshot(stagedExports))
	require.Equal(t, stagedRowGuard, snapshot([]string{rowGuard})[rowGuard])
}

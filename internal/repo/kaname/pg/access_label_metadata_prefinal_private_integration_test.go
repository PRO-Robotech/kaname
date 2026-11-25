// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// This only checks the installed private discovery surface. The fixture's full
// writer setup does not establish that protected metadata mutation is enabled.
func TestMetadataAccessLabelPrefinalDiscoveryRemainsOwnerPrivate(t *testing.T) {
	w := metadataFixtureMode(t, false, "prepared")
	r := w.r
	for _, signature := range []string{
		"kaname._authority_metadata_access_label_carrier_census_v1(text,jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_prefinal_carriers_v1(text,text,text,jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_early_source_v1(integer,text,text,integer,integer)",
		"kaname._authority_metadata_access_label_early_frontier_v1(text,text,integer,integer)",
		"kaname._authority_metadata_access_label_early_walk_v1(jsonb,text,text,integer,integer,integer)",
		"kaname._authority_metadata_access_label_early_closure_v1(jsonb,jsonb,integer,integer,integer)",
		"kaname._authority_metadata_access_label_discovery_fence_v1(jsonb)",
	} {
		t.Run(signature, func(t *testing.T) {
			var ownerMatches, invokerOnly, pathClosed, aclClosed bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT
 p.proowner=(SELECT relowner FROM pg_catalog.pg_class WHERE oid='kaname.authority_writer_protocol'::regclass),
 NOT p.prosecdef,
 p.proconfig=ARRAY['search_path=pg_catalog, pg_temp']::text[],
 NOT EXISTS(SELECT 1 FROM pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a
  WHERE a.grantee<>p.proowner)
 FROM pg_catalog.pg_proc p WHERE p.oid=to_regprocedure($1)`, signature).
				Scan(&ownerMatches, &invokerOnly, &pathClosed, &aclClosed))
			require.True(t, ownerMatches, "migration owner must own private discovery")
			require.True(t, invokerOnly, "discovery must not elevate its caller")
			require.True(t, pathClosed, "function search path must be closed")
			require.True(t, aclClosed, "PUBLIC and nonowner default grants must be removed")
			var runtimeCanExecute bool
			require.NoError(t, r.runtime.QueryRow(r.ctx,
				`SELECT has_function_privilege($1, 'EXECUTE')`, signature).Scan(&runtimeCanExecute))
			require.False(t, runtimeCanExecute, "real runtime LOGIN must not execute discovery")
		})
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// verifies https://github.com/PRO-Robotech/kaname/issues/983
func TestRegistrationCatalogWitness_EveryMintPhysicallyFences(t *testing.T) {
	for _, mode := range []string{"insert", "update", "upsert", "copy", "nested_trigger", "frozen_catalog"} {
		t.Run(mode, func(t *testing.T) {
			ctx, _, writer, _ := registrationRRDB(t)
			if mode == "frozen_catalog" {
				_, err := writer.Exec(ctx, `VACUUM (FREEZE, DISABLE_PAGE_SKIPPING) kaname.catalog_resource`)
				require.NoError(t, err)
			}
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			if mode == "update" || mode == "upsert" {
				_, err = tx.Exec(ctx, `SELECT kaname.registration_catalog_fence_ensure('registry','registries')`)
				require.NoError(t, err)
			}
			n := registrationCatalogWrites(t, ctx, tx)
			switch mode {
			case "insert", "frozen_catalog":
				_, err = tx.Exec(ctx, `INSERT INTO kaname.registration_catalog_fence VALUES ('registry','registries','4294967301'::xid8)`)
			case "update":
				_, err = tx.Exec(ctx, `UPDATE kaname.registration_catalog_fence SET fence_xid='5'::xid8 WHERE catalog_module='registry' AND catalog_resource='registries'`)
			case "upsert":
				_, err = tx.Exec(ctx, `INSERT INTO kaname.registration_catalog_fence VALUES ('registry','registries','5'::xid8) ON CONFLICT(catalog_module,catalog_resource) DO UPDATE SET fence_xid=EXCLUDED.fence_xid`)
			case "copy":
				_, err = writer.PgConn().CopyFrom(ctx, strings.NewReader("registry\tregistries\t5\n"), `COPY kaname.registration_catalog_fence FROM STDIN`)
			case "nested_trigger":
				_, err = tx.Exec(ctx, `CREATE TEMP TABLE nested_fence_probe(n int);
 CREATE FUNCTION pg_temp.nested_fence_probe() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 INSERT INTO kaname.registration_catalog_fence VALUES ('registry','registries','5'::xid8); RETURN NEW; END $$;
 CREATE TRIGGER nested_fence_probe BEFORE INSERT ON nested_fence_probe FOR EACH ROW EXECUTE FUNCTION pg_temp.nested_fence_probe();
 INSERT INTO nested_fence_probe VALUES (1)`)
			}
			require.NoError(t, err)
			require.Positive(t, registrationCatalogWrites(t, ctx, tx)-n, "no DML, COPY or nested depth can mint without the actual catalog UPDATE")
			var actual, current string
			require.NoError(t, tx.QueryRow(ctx, `SELECT fence_xid::text,pg_current_xact_id()::text FROM kaname.registration_catalog_fence WHERE catalog_module='registry' AND catalog_resource='registries'`).Scan(&actual, &current))
			require.Equal(t, current, actual, "caller-supplied low or full xid is overwritten after a real fence")
		})
	}
}

func TestRegistrationCatalogWitness_MetadataCannotGrantAuthority(t *testing.T) {
	ctx, admin, writer, _ := registrationRRDB(t)
	allowed := fmt.Sprintf("fence_allowed_%d", writer.PgConn().PID())
	denied := fmt.Sprintf("fence_denied_%d", writer.PgConn().PID())
	for _, role := range []string{allowed, denied} {
		_, err := admin.Exec(ctx, "CREATE ROLE "+role+" NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT")
		require.NoError(t, err)
		t.Cleanup(func() {
			_, _ = writer.Exec(context.Background(), "RESET ROLE")
			_, _ = admin.Exec(context.Background(), "DROP OWNED BY "+role)
			_, _ = admin.Exec(context.Background(), "DROP ROLE "+role)
		})
		// Only existing command/table DML, plus the new metadata DML. No CREATE,
		// TRIGGER, schema ownership, role membership or SECURITY DEFINER grant.
		_, err = admin.Exec(ctx, "GRANT USAGE ON SCHEMA kaname TO "+role+"; "+
			"GRANT SELECT ON kaname.catalog_resource TO "+role+"; "+
			"GRANT SELECT,INSERT,UPDATE,DELETE ON kaname.resource_mirror,kaname.resource_parent_edge,kaname.object_project_binding,kaname.registration_catalog_fence TO "+role+"; "+
			"GRANT INSERT ON kaname.resource_registration_command TO "+role)
		require.NoError(t, err)
	}
	_, err := admin.Exec(ctx, "GRANT UPDATE(project_bindings_held) ON kaname.catalog_resource TO "+allowed)
	require.NoError(t, err)
	t.Run("ordinary_writer", func(t *testing.T) {
		tx, err := writer.Begin(ctx)
		require.NoError(t, err)
		defer tx.Rollback(context.Background())
		_, err = tx.Exec(ctx, "SET LOCAL ROLE "+allowed)
		require.NoError(t, err)
		var elevated bool
		require.NoError(t, tx.QueryRow(ctx, `SELECT rolsuper OR rolcreaterole
 OR has_schema_privilege(current_user,'kaname','CREATE')
 OR has_table_privilege(current_user,'kaname.registration_catalog_fence','TRIGGER')
 FROM pg_roles WHERE rolname=current_user`).Scan(&elevated))
		require.False(t, elevated, "actual ordinary writer has no superuser, role, schema or trigger authority")
		_, err = tx.Exec(ctx, registrationRRCommand, "ordinary-writer")
		require.NoError(t, err, "legitimate writer needs no new privilege authority")
		_, err = tx.Exec(ctx, registrationRRCommand, "ordinary-writer-second")
		require.NoError(t, err)
	})
	for _, mode := range []string{"direct_mint", "role_after_mint"} {
		t.Run(mode, func(t *testing.T) {
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			if mode == "role_after_mint" {
				_, err = tx.Exec(ctx, registrationRRCommand, "owner-before-role")
				require.NoError(t, err)
			}
			_, err = tx.Exec(ctx, "SET LOCAL ROLE "+denied)
			require.NoError(t, err)
			if mode == "direct_mint" {
				_, err = tx.Exec(ctx, `INSERT INTO kaname.registration_catalog_fence VALUES ('registry','registries',pg_current_xact_id())`)
			} else {
				_, err = tx.Exec(ctx, registrationRRCommand, "denied-after-role")
			}
			require.Error(t, err)
			require.Equal(t, "42501", registrationRRState(err), "existing marker and metadata DML cannot replace catalog UPDATE authority")
		})
	}
}

func TestRegistrationCatalogWitness_IdentityAndCardinality(t *testing.T) {
	for _, mode := range []string{"delete_recreate", "move", "logical_update", "truncate"} {
		t.Run(mode, func(t *testing.T) {
			ctx, _, writer, _ := registrationRRDB(t)
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			const add = `INSERT INTO kaname.catalog_resource(module,resource,dotted,object_type) VALUES ('registry','witness_probe','registry.witness_probe','witness_probe')`
			_, err = tx.Exec(ctx, add)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, `SELECT kaname.registration_catalog_fence_ensure('registry','witness_probe')`)
			require.NoError(t, err)
			var n int
			switch mode {
			case "delete_recreate":
				_, err = tx.Exec(ctx, `DELETE FROM kaname.catalog_resource WHERE module='registry' AND resource='witness_probe'`)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, add)
				require.NoError(t, err)
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.registration_catalog_fence WHERE catalog_resource='witness_probe'`).Scan(&n))
				require.Zero(t, n, "same textual key is a new row incarnation")
				before := registrationCatalogWrites(t, ctx, tx)
				_, err = tx.Exec(ctx, `SELECT kaname.registration_catalog_fence_ensure('registry','witness_probe')`)
				require.NoError(t, err)
				require.Positive(t, registrationCatalogWrites(t, ctx, tx)-before)
			case "move":
				_, err = tx.Exec(ctx, `UPDATE kaname.catalog_resource SET resource='witness_moved',dotted='registry.witness_moved' WHERE module='registry' AND resource='witness_probe'`)
				require.NoError(t, err)
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.registration_catalog_fence WHERE catalog_resource IN ('witness_probe','witness_moved')`).Scan(&n))
				require.Zero(t, n, "both identity markers invalidated")
			case "logical_update":
				_, err = tx.Exec(ctx, `UPDATE kaname.catalog_resource SET permanent_project=true WHERE module='registry' AND resource='witness_probe'`)
				require.NoError(t, err)
				_, err = tx.Exec(ctx, `INSERT INTO kaname.resource_registration_command(dotted_type,object_id,parent_project_id,parent_account_id,source_version,parent_chain) VALUES ('registry.witness_probe','fresh-flags','registrationRR-P','registrationRR-A',now(),ARRAY['project:registrationRR-P'])`)
				require.NoError(t, err)
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.object_project_binding WHERE object_id='fresh-flags' AND project_id='registrationRR-P'`).Scan(&n))
				require.Equal(t, 1, n, "witness does not cache declaration fields")
			case "truncate":
				_, err = tx.Exec(ctx, `TRUNCATE kaname.catalog_resource CASCADE`)
				require.NoError(t, err)
				require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.registration_catalog_fence`).Scan(&n))
				require.Zero(t, n)
			}
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.registration_catalog_fence w LEFT JOIN kaname.catalog_resource c ON (c.module,c.resource)=(w.catalog_module,w.catalog_resource) WHERE c.module IS NULL`).Scan(&n))
			require.Zero(t, n, "no orphan identities")
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.registration_catalog_fence`).Scan(&n))
			var catalogs int
			require.NoError(t, tx.QueryRow(ctx, `SELECT count(*) FROM kaname.catalog_resource`).Scan(&catalogs))
			require.LessOrEqual(t, n, catalogs, "one bounded witness per actual catalog identity")
		})
	}
}

func TestRegistrationCatalogWitness_RejectsWrongKeyAndTruncate(t *testing.T) {
	for _, statement := range []string{
		`INSERT INTO kaname.registration_catalog_fence VALUES ('missing','identity',pg_current_xact_id())`,
		`UPDATE kaname.registration_catalog_fence SET catalog_resource='other' WHERE catalog_module='registry' AND catalog_resource='registries'`,
		`TRUNCATE kaname.registration_catalog_fence`,
	} {
		t.Run(statement, func(t *testing.T) {
			ctx, _, writer, _ := registrationRRDB(t)
			tx, err := writer.Begin(ctx)
			require.NoError(t, err)
			defer tx.Rollback(context.Background())
			_, err = tx.Exec(ctx, `SELECT kaname.registration_catalog_fence_ensure('registry','registries')`)
			require.NoError(t, err)
			_, err = tx.Exec(ctx, statement)
			require.Error(t, err)
			require.True(t, strings.HasPrefix(registrationRRState(err), "23"))
		})
	}
}

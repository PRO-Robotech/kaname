// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// verifies https://github.com/PRO-Robotech/kaname/issues/1020

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

func TestRegistrationCommand_DownUpRetainsBindingAndGuards(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))
	_, err = db.Exec(`UPDATE kaname.catalog_resource SET permanent_project=true WHERE dotted='registry.registries';
 INSERT INTO kaname.resource_registration_command(dotted_type,object_id,parent_project_id,parent_account_id,labels,source_version,parent_chain)
 VALUES ('registry.registries','roundtrip-object','roundtrip-project','roundtrip-account','{}',now(),ARRAY['project:roundtrip-project'])`)
	require.NoError(t, err)
	for _, up := range []bool{false, true} {
		if up {
			require.NoError(t, goose.Up(db, "."))
		} else {
			require.NoError(t, goose.DownTo(db, ".", 20261026120000))
		}
		var present bool
		require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.resource_registration_command') IS NOT NULL`).Scan(&present))
		require.Equal(t, up, present)
		var project string
		require.NoError(t, db.QueryRow(`SELECT project_id FROM kaname.object_project_binding WHERE object_type='registry_registry' AND object_id='roundtrip-object'`).Scan(&project))
		require.Equal(t, "roundtrip-project", project)
		_, err = db.Exec(`UPDATE kaname.resource_mirror SET parent_project_id='foreign-project' WHERE object_type='registry.registries' AND object_id='roundtrip-object'`)
		require.Error(t, err, "оба направления держат постоянную привязку")
		_, err = db.Exec(`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version)
    VALUES ('registry_registry','roundtrip-object','project','foreign-project',3,now())`)
		require.Error(t, err)
	}
}

func TestRegistrationReconciliation_DownRefusesAtomically(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	db, err := sql.Open("pgx", pgtest.NewEmptyDB(t))
	require.NoError(t, err)
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))
	var before int
	_, err = db.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
	require.NoError(t, err)
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM goose_db_version`).Scan(&before))
	raw, err := migrations.FS.ReadFile("20261026090001_reconcile_registration_and_creator_lineages.sql")
	require.NoError(t, err)
	down := strings.Split(string(raw), "-- +goose Down")[1]
	tx, err := db.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	_, err = tx.Exec(down)
	var violation *pgconn.PgError
	require.ErrorAs(t, err, &violation)
	require.Equal(t, "23514", violation.Code)
	require.Equal(t, "registration_lineage_lossless_down", violation.ConstraintName)
	require.NoError(t, tx.Rollback())
	var after int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM goose_db_version`).Scan(&after))
	require.Equal(t, before, after)
	var intact bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.resource_registration_command') IS NOT NULL
 AND to_regprocedure('kaname.service_account_creator_is_immutable()') IS NOT NULL
 AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_resource' AND column_name='writes')`).Scan(&intact))
	require.True(t, intact, "отказ не снимает ни одну из согласованных схем")
}

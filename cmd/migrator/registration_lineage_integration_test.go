// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// verifies https://github.com/PRO-Robotech/kaname/issues/1020

import (
	"context"
	"database/sql"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
)

// registrationOriginDB накатывает точные исходные файлы, без правки ledger.
func registrationOriginDB(t *testing.T, origin string) (string, *sql.DB) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	if origin != "fresh" {
		fixture := fstest.MapFS{}
		names, err := fs.Glob(migrations.FS, "*.sql")
		require.NoError(t, err)
		for _, name := range names {
			if name > creatorMigration {
				continue
			}
			if origin != "main" && name == creatorMigration {
				continue
			}
			data, err := migrations.FS.ReadFile(name)
			require.NoError(t, err)
			fixture[name] = &fstest.MapFile{Data: data}
		}
		if origin != "main" {
			data, err := migrations.Historical.ReadFile(writerMigration)
			require.NoError(t, err)
			fixture[strings.TrimPrefix(writerMigration, "historical/")] = &fstest.MapFile{Data: data}
		}
		goose.SetBaseFS(fixture)
		require.NoError(t, goose.SetDialect("postgres"))
		require.NoError(t, goose.Up(db, "."))
		if origin == "both" {
			data, err := migrations.FS.ReadFile(creatorMigration)
			require.NoError(t, err)
			_, err = db.Exec(migrations.MigrationUpText(string(data)))
			require.NoError(t, err)
			require.Contains(t, migrations.MigrationUpText(string(data)), "$$"+registrationScalar(t, db,
				`SELECT prosrc FROM pg_proc WHERE oid='kaname.iam_rules_valid(jsonb)'::regprocedure`)+"$$")
			require.Equal(t, "true:true", registrationScalar(t, db, `SELECT
                (to_regprocedure('kaname.service_account_creator_is_immutable()') IS NOT NULL)::text||':'||
                EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_resource' AND column_name='writes')::text`))
		}
	}
	_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
	require.NoError(t, err)
	return dsn, db
}

func registrationScalar(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	var value string
	require.NoError(t, db.QueryRow(query).Scan(&value))
	return value
}

func TestRegistrationMigrator_OriginalLineageDownUpRoundTrips(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, origin := range []string{"fresh", "main", "feature"} {
		t.Run(origin, func(t *testing.T) {
			dsn, db := registrationOriginDB(t, origin)
			shape := registrationScalar(t, db, `SELECT kaname.registration_lineage_shape()::text`)
			originShape := registrationScalar(t, db, `SELECT jsonb_build_array(had_creator,had_writer,original_shape)::text FROM kaname.registration_lineage_origin`)
			catalog := registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted)::text FROM kaname.catalog_resource c`)
			for _, target := range []string{"20261026090001", "20261026090000", "20261026089999", "1"} {
				_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", target, "--dsn", dsn}, nil)
				require.NoError(t, err, "%s to %s", origin, target)
				if target == "20261026090000" {
					want := "true:false"
					if origin == "feature" {
						want = "false:true"
					}
					require.Equal(t, want, registrationScalar(t, db, `SELECT
                            (to_regprocedure('kaname.service_account_creator_is_immutable()') IS NOT NULL)::text||':'||
                            EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_resource' AND column_name='writes')::text`))
				}
				if target == "20261026089999" {
					require.Equal(t, "0", registrationScalar(t, db, `SELECT count(*)::text FROM information_schema.columns
                            WHERE table_schema='kaname' AND ((table_name='catalog_resource' AND column_name='writes')
                            OR (table_name='service_accounts' AND column_name='created_by_id'))`))
				}
				if target == "1" {
					registrationRestoreEarlyLimits(t, dsn, db)
				}
				require.Equal(t, originShape, registrationScalar(t, db, `SELECT jsonb_build_array(had_creator,had_writer,original_shape)::text FROM kaname.registration_lineage_origin`))
				_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
				require.NoError(t, err)
				require.Equal(t, shape, registrationScalar(t, db, `SELECT kaname.registration_lineage_shape()::text`))
				require.Equal(t, catalog, registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted)::text FROM kaname.catalog_resource c`))
				require.Equal(t, originShape, registrationScalar(t, db, `SELECT jsonb_build_array(had_creator,had_writer,original_shape)::text FROM kaname.registration_lineage_origin`))
			}
		})
	}
}

func TestRegistrationMigrator_UnknownOriginRefusesBeforeAnyDown(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, scenario := range []string{"both", "missing", "tampered"} {
		t.Run(scenario, func(t *testing.T) {
			origin := "main"
			if scenario == "both" {
				origin = "both"
			}
			dsn, db := registrationOriginDB(t, origin)
			if scenario == "missing" {
				_, err := db.Exec(`DROP TABLE kaname.registration_lineage_origin`)
				require.NoError(t, err)
			}
			if scenario == "tampered" {
				_, err := db.Exec(`UPDATE kaname.registration_lineage_origin SET complete_shape='{}'`)
				require.NoError(t, err)
			}
			before := registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`)
			_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
			require.ErrorContains(t, err, "before any Down")
			require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`))
			require.Equal(t, "true", registrationScalar(t, db, `SELECT (to_regclass('kaname.resource_registration_command') IS NOT NULL)::text`))
		})
	}
}

func TestRegistrationMigrator_PreservesExistingWriterPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	dsn, db := registrationOriginDB(t, "feature")
	_, err := db.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
	require.NoError(t, err)
	_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090000", "--dsn", dsn}, nil)
	require.NoError(t, err, "исходная writer-политика переживает снятие добавленной creator-стороны")
	_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026089999", "--dsn", dsn}, nil)
	var violation *pgconn.PgError
	require.ErrorAs(t, err, &violation)
	require.Equal(t, "23514", violation.Code)
	require.Equal(t, "registration_lineage_lossless_down", violation.ConstraintName)
	require.Equal(t, "{owner:user}", registrationScalar(t, db, `SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
	_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
	require.NoError(t, err)
	require.Equal(t, "{owner:user}", registrationScalar(t, db, `SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
}

func TestRegistrationMigrator_RollbackWaitsForWriterThenJudgesCommittedPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, commit := range []bool{true, false} {
		t.Run(map[bool]string{true: "commit", false: "rollback"}[commit], func(t *testing.T) {
			dsn, db := registrationOriginDB(t, "main")
			_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090001", "--dsn", dsn}, nil)
			require.NoError(t, err)
			tx, err := db.Begin()
			require.NoError(t, err)
			defer tx.Rollback()
			_, err = tx.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			result := make(chan error, 1)
			go func() {
				cmd := newRootCmd(migrations.FS)
				cmd.SetContext(ctx)
				cmd.SetArgs([]string{"down", "--target", "20261026090000", "--dsn", dsn})
				result <- cmd.Execute()
			}()
			require.Eventually(t, func() bool { return rollbackIsWaitingForALock(t, db) }, 5*time.Second, 10*time.Millisecond)
			if commit {
				require.NoError(t, tx.Commit())
			} else {
				require.NoError(t, tx.Rollback())
			}
			err = <-result
			if commit {
				var violation *pgconn.PgError
				require.ErrorAs(t, err, &violation)
				require.Equal(t, "23514", violation.Code)
				require.Equal(t, "{owner:user}", registrationScalar(t, db, `SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestRegistrationMigrator_CreatorDataCannotBeDiscarded(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, scenario := range []string{"creator fact", "creator rule", "container declaration", "plain named role"} {
		t.Run(scenario, func(t *testing.T) {
			dsn, db := registrationOriginDB(t, "feature")
			var mutation string
			switch scenario {
			case "creator fact":
				seedCredentialOwners(t, db)
				mutation = `INSERT INTO kaname.service_accounts(id,account_id,name,created_by_type,created_by_id)
                    VALUES ('sva00000000000000own','acc00000000000000mgr','creator-owned','user','usr00000000000000mgr')`
			case "creator rule":
				mutation = `INSERT INTO kaname.roles(id,name,permissions,rules,cluster_id)
                    VALUES ('rol-lineage-creator','iam.lineage.creator','[]',
                    '[{"module":"iam","resources":["serviceAccount"],"verbs":["get"],"created_by_subject":true}]','cluster_root')`
			case "plain named role":
				mutation = `INSERT INTO kaname.roles(id,name,permissions,rules,cluster_id)
                    VALUES ('rol-lineage-plain','iam.service_account.creator','[]',
                    '[{"module":"iam","resources":["serviceAccount"],"verbs":["get"]}]','cluster_root')`
			case "container declaration":
				mutation = `UPDATE kaname.catalog_verb SET container_relation='custom_creator'
                    WHERE module='iam' AND resource='serviceAccount' AND verb='create'`
			}
			_, err := db.Exec(mutation)
			require.NoError(t, err)
			before := registrationScalar(t, db, `SELECT jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM kaname.service_accounts s),
                    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM kaname.roles r),
                    (SELECT jsonb_agg(to_jsonb(v) ORDER BY module,resource,verb) FROM kaname.catalog_verb v))::text`)
			_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090000", "--dsn", dsn}, nil)
			var violation *pgconn.PgError
			require.ErrorAs(t, err, &violation)
			require.Equal(t, "23514", violation.Code)
			require.Equal(t, "registration_lineage_lossless_down", violation.ConstraintName)
			require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM kaname.service_accounts s),
                    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM kaname.roles r),
                    (SELECT jsonb_agg(to_jsonb(v) ORDER BY module,resource,verb) FROM kaname.catalog_verb v))::text`))
		})
	}
}

// Deep Down восстанавливает девять законных значений. Их потребляют ранние Up,
// поэтому разрушительный полный Up сначала обязан отказаться без мутации.
func registrationRestoreEarlyLimits(t *testing.T, dsn string, db *sql.DB) {
	t.Helper()
	require.Equal(t, "9", registrationScalar(t, db, `SELECT count(*)::text FROM kaname.limits`))
	before := registrationScalar(t, db, `SELECT jsonb_build_array(
        (SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM kaname.limits l),
        (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v))::text`)
	_, _, err := runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
	require.Error(t, err)
	require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_build_array(
        (SELECT jsonb_agg(to_jsonb(l) ORDER BY id) FROM kaname.limits l),
        (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v))::text`))
	ceilings := registrationScalar(t, db, `SELECT jsonb_object_agg(kind,limit_value)::text FROM kaname.limits
        WHERE kind IN ('iam.account','iam.user.credential','iam.serviceAccount.credential')`)
	_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--target", "20260910120000", "--dsn", dsn}, nil)
	require.NoError(t, err)
	require.Equal(t, "0", registrationScalar(t, db, `SELECT count(*)::text FROM kaname.limits`))
	require.JSONEq(t, ceilings, registrationScalar(t, db, `SELECT jsonb_object_agg(kind,limit_value)::text FROM kaname.own_ceilings`))
}

func TestRegistrationMigrator_PhasedUpStillRefusesUnconsumedLimit(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	dsn, db := registrationOriginDB(t, "fresh")
	_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
	require.NoError(t, err)
	registrationRestoreEarlyLimits(t, dsn, db)
	_, err = db.Exec(`INSERT INTO kaname.limits(id,scope,kind,limit_value) VALUES
        ('lim-00000000000000999','DEFAULT','vpc.network',17)`)
	require.NoError(t, err)
	before := registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`)
	_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
	require.Error(t, err)
	require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`))
	require.Equal(t, "17", registrationScalar(t, db, `SELECT limit_value::text FROM kaname.limits WHERE id='lim-00000000000000999'`))
}

func TestRegistrationMigrator_OriginFlagsAreBoundToOriginalDefinitions(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	for _, scenario := range []struct{ name, origin, mutation string }{
		{"main-to-feature", "main", `SET had_creator=false,had_writer=true`},
		{"feature-to-main", "feature", `SET had_creator=true,had_writer=false`},
		{"both-to-main", "both", `SET had_writer=false`},
		{"original-shape", "main", `SET original_shape=jsonb_set(original_shape,'{column/service_accounts/created_by_id}','[]')`},
		{"original-function", "feature", `SET original_shape=jsonb_set(original_shape,'{function/iam_rules_valid}','"changed"')`},
		{"old-format", "main", `SET format_version=1`},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			dsn, db := registrationOriginDB(t, scenario.origin)
			if scenario.name == "old-format" {
				_, err := db.Exec(`ALTER TABLE kaname.registration_lineage_origin DROP CONSTRAINT registration_lineage_origin_format_version_check`)
				require.NoError(t, err)
			}
			_, err := db.Exec("UPDATE kaname.registration_lineage_origin " + scenario.mutation)
			require.NoError(t, err)
			before := registrationScalar(t, db, `SELECT jsonb_build_array(
                kaname.registration_lineage_shape(),
                (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v),
                (SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted) FROM kaname.catalog_resource c))::text`)
			_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
			require.ErrorContains(t, err, "before any Down")
			// SQL inverse is independently guarded, even without the CLI preflight.
			raw, err := fs.ReadFile(migrations.FS,"20261026090001_reconcile_registration_and_creator_lineages.sql")
			require.NoError(t, err)
			_, down, ok := strings.Cut(string(raw),migrations.SectionDownMarker)
			require.True(t, ok)
			_, err = db.Exec(down)
			require.ErrorContains(t, err,"provenance or schema differs")
			require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_build_array(
                kaname.registration_lineage_shape(),
                (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v),
                (SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted) FROM kaname.catalog_resource c))::text`))
		})
	}
}

func TestRegistrationMigrator_RepeatableReadRefusesBeforeHistoricalDown(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	for _, commit := range []bool{false,true} {
		t.Run(map[bool]string{true:"writer-commit",false:"writer-rollback"}[commit], func(t *testing.T) {
			dsn, db := registrationOriginDB(t, "feature")
			_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090000", "--dsn", dsn}, nil)
			require.NoError(t, err)
			tx, err := db.BeginTx(context.Background(), &sql.TxOptions{Isolation:sql.LevelRepeatableRead})
			require.NoError(t, err)
			defer tx.Rollback()
			var snapshot string
			require.NoError(t, tx.QueryRow(`SELECT txid_current_snapshot()::text`).Scan(&snapshot))
			writer, err := db.Begin()
			require.NoError(t, err)
			defer writer.Rollback()
			_, err = writer.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
			require.NoError(t, err)
			if commit { require.NoError(t, writer.Commit()) } else { require.NoError(t, writer.Rollback()) }
			before := registrationScalar(t, db, `SELECT kaname.registration_lineage_shape()::text`)
			source := registrationHistoryFS{FS:migrations.FS,writer:true}
			raw, err := fs.ReadFile(source, creatorMigration)
			require.NoError(t, err)
			_, down, ok := strings.Cut(string(raw), migrations.SectionDownMarker)
			require.True(t, ok)
			_, err = tx.Exec(down)
			var violation *pgconn.PgError
			require.ErrorAs(t, err, &violation)
			require.Equal(t, "25001", violation.Code)
			require.NoError(t, tx.Rollback())
			require.Equal(t, before, registrationScalar(t, db, `SELECT kaname.registration_lineage_shape()::text`))
			want := "{}"; if commit { want = "{owner:user}" }
			require.Equal(t, want, registrationScalar(t, db, `SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
		})
	}
}

func TestRegistrationMigrator_DefaultRepeatableReadRefusesBeforeAnyDown(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	dsn, db := registrationOriginDB(t, "main")
	before := registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`)
	name := registrationScalar(t, db, `SELECT current_database()`)
	_, err := db.Exec("ALTER DATABASE " + pgx.Identifier{name}.Sanitize() + " SET default_transaction_isolation='repeatable read'")
	require.NoError(t, err)
	_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "1", "--dsn", dsn}, nil)
	require.ErrorContains(t, err, "READ COMMITTED")
	require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`))
	require.Equal(t, "true", registrationScalar(t, db, `SELECT (to_regclass('kaname.resource_registration_command') IS NOT NULL)::text`))
}

func TestRegistrationMigrator_UnrelatedPlainRoleSurvivesCreatorDown(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	dsn, db := registrationOriginDB(t, "feature")
	_, err := db.Exec(`INSERT INTO kaname.roles(id,name,permissions,rules,cluster_id)
        VALUES ('rol-lineage-unrelated','iam.service_account.observer','[]',
        '[{"module":"iam","resources":["serviceAccount"],"verbs":["get"]}]','cluster_root')`)
	require.NoError(t, err)
	before := registrationScalar(t, db, `SELECT to_jsonb(r)::text FROM kaname.roles r WHERE id='rol-lineage-unrelated'`)
	_, _, err = runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090000", "--dsn", dsn}, nil)
	require.NoError(t, err)
	require.Equal(t, before, registrationScalar(t, db, `SELECT to_jsonb(r)::text FROM kaname.roles r WHERE id='rol-lineage-unrelated'`))
}

func TestRegistrationMigrator_ChangedValidatorStillRefusesReconciliation(t *testing.T) {
	if testing.Short() { t.Skip("integration: PostgreSQL") }
	for _, origin := range []string{"main", "feature"} {
		t.Run(origin, func(t *testing.T) {
			dsn, db := registrationOriginDB(t, origin)
			_, _, err := runCommandFS(t, migrations.FS, []string{"down", "--target", "20261026090000", "--dsn", dsn}, nil)
			require.NoError(t, err)
			_, err = db.Exec(`CREATE OR REPLACE FUNCTION kaname.iam_rules_valid(rules jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN RETURN true; END; $$`)
			require.NoError(t, err)
			before := registrationScalar(t, db, `SELECT jsonb_build_array(kaname.registration_lineage_shape(),
                (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v))::text`)
			_, _, err = runCommandFS(t, migrations.FS, []string{"up", "--dsn", dsn}, nil)
			require.ErrorContains(t, err, "rule validator differs")
			require.Equal(t, before, registrationScalar(t, db, `SELECT jsonb_build_array(kaname.registration_lineage_shape(),
                (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v))::text`))
		})
	}
}

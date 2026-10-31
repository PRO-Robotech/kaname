// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// verifies https://github.com/PRO-Robotech/kaname/issues/1020

import (
    "context"
    "database/sql"
    "io/fs"
    "strings"
    "testing"
    "testing/fstest"

    "github.com/PRO-Robotech/corelib/migratorrun"
    "github.com/PRO-Robotech/corelib/pgtest"
    "github.com/PRO-Robotech/kaname/internal/migrations"
    "github.com/pressly/goose/v3"
    "github.com/stretchr/testify/require"
)

const creator90000="20261026090000_service_account_creation_is_its_own_right.sql"
const writer90000="20261026090000_module_writes_only_what_its_manifest_declares.sql"

func TestRegistrationLineages_ProductMigratorReconcilesBothHistories(t *testing.T){
    if testing.Short(){t.Skip("integration: PostgreSQL")}
    // Do not run in parallel: the product runner and goose own process globals.
    for _,lineage:=range []string{"fresh","main","feature","both","partial"}{
        t.Run(lineage,func(t *testing.T){
            dsn:=pgtest.NewEmptyDB(t)
            db,err:=sql.Open("pgx",dsn);require.NoError(t,err);defer db.Close()
            source:=fstest.MapFS{}
            names,err:=fs.Glob(migrations.FS,"*.sql");require.NoError(t,err)
            for _,name:=range names{
                // Actual full main HEAD ends at creator90000; actual full
                // registration b8 ends at binding120000. No invented prefix.
                if name>="20261031000000"||strings.HasPrefix(name,"20261026090001_"){continue}
                if lineage=="main"&&name>creator90000{continue}
                if (lineage=="feature"||lineage=="both"||lineage=="partial")&&name==creator90000{continue}
                data,e:=migrations.FS.ReadFile(name);require.NoError(t,e)
                source[name]=&fstest.MapFile{Data:data}
            }
            if lineage=="feature"||lineage=="both"||lineage=="partial"{
                old,e:=migrations.Historical.ReadFile("historical/"+writer90000);require.NoError(t,e)
                source[writer90000]=&fstest.MapFile{Data:old}
            }
            if lineage!="fresh"{
                goose.SetBaseFS(source);require.NoError(t,goose.SetDialect("postgres"))
                require.NoError(t,goose.Up(db,"."),"fixture: full original lineage")
                if lineage=="both"{
                    raw,e:=migrations.FS.ReadFile(creator90000);require.NoError(t,e)
                    body:=strings.Split(strings.Split(string(raw),"-- +goose Up")[1],"-- +goose Down")[0]
                    _,e=db.Exec(body);require.NoError(t,e,"fixture: both exact schemas, one ambiguous version record")
                }
                if lineage=="partial"{
                    _,err=db.Exec(`ALTER TABLE kaname.catalog_resource DROP CONSTRAINT catalog_resource_writes_form`)
                    require.NoError(t,err)
                }
                // A lawful later catalog update must survive: do not replay seeds.
                if lineage=="feature"||lineage=="both"{
                    _,err=db.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
                    require.NoError(t,err)
                }
            }
            // Exact product runner (includes WithAllowMissing), not a fabricated
            // goose option in the test. Existing version rows are never rewritten.
            runner,err:=migratorrun.New(migratorrun.Config{Service:"kaname",Dialect:"postgres",DSN:dsn,FS:migrations.FS,MigrationsDir:"."})
            require.NoError(t,err)
            err=runner.Up(context.Background(),"")
            if lineage=="partial"{
                require.ErrorContains(t,err,"90000 lineage reconciliation")
                var absent bool
                require.NoError(t,db.QueryRow(`SELECT NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_verb' AND column_name='container_parent')`).Scan(&absent))
                require.True(t,absent,"failure before missing main schema is installed")
                return
            }
            require.NoError(t,err)
            require.NoError(t,runner.Up(context.Background(),""),"repeated product upgrade")
            var n int
            require.NoError(t,db.QueryRow(`SELECT count(*) FROM goose_db_version WHERE version_id=20261026090000 AND is_applied`).Scan(&n))
            require.Equal(t,1,n,"ambiguous history is preserved, not relabeled")
            require.NoError(t,db.QueryRow(`SELECT count(*) FROM goose_db_version WHERE version_id=20261026090001 AND is_applied`).Scan(&n))
            require.Equal(t,1,n)
            if lineage=="feature"||lineage=="both"{
                var retained bool
                require.NoError(t,db.QueryRow(`SELECT writes=ARRAY['owner:user'] FROM kaname.catalog_resource WHERE dotted='registry.registries'`).Scan(&retained))
                require.True(t,retained,"existing catalog data must not be reseeded")
            }
            var complete bool
            require.NoError(t,db.QueryRow(`SELECT to_regclass('kaname.resource_registration_command') IS NOT NULL
                AND to_regprocedure('kaname.service_account_creator_is_immutable()') IS NOT NULL
                AND EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_resource' AND column_name='parent_names')`).Scan(&complete))
            require.True(t,complete)
        })
    }
}

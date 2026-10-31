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

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// registrationOriginDB накатывает точные исходные файлы, без правки ledger.
func registrationOriginDB(t *testing.T, origin string) (string,*sql.DB) {
	t.Helper()
	dsn:=pgtest.NewEmptyDB(t)
	db,err:=sql.Open("pgx",dsn)
	require.NoError(t,err)
	t.Cleanup(func(){ _=db.Close() })
	if origin!="fresh" {
		fixture:=fstest.MapFS{}
		names,err:=fs.Glob(migrations.FS,"*.sql")
		require.NoError(t,err)
		for _,name:=range names {
			if name>creatorMigration { continue }
			if origin!="main" && name==creatorMigration { continue }
			data,err:=migrations.FS.ReadFile(name)
			require.NoError(t,err)
			fixture[name]=&fstest.MapFile{Data:data}
		}
		if origin!="main" {
			data,err:=migrations.Historical.ReadFile(writerMigration)
			require.NoError(t,err)
			fixture[strings.TrimPrefix(writerMigration,"historical/")]=&fstest.MapFile{Data:data}
		}
		goose.SetBaseFS(fixture)
		require.NoError(t,goose.SetDialect("postgres"))
		require.NoError(t,goose.Up(db,"."))
		if origin=="both" {
			data,err:=migrations.FS.ReadFile(creatorMigration)
			require.NoError(t,err)
			_,err=db.Exec(migrations.MigrationUpSection(string(data)))
			require.NoError(t,err)
		}
	}
	_,_,err=runCommandFS(t,migrations.FS,[]string{"up","--dsn",dsn},nil)
	require.NoError(t,err)
	return dsn,db
}

func registrationScalar(t *testing.T,db *sql.DB,query string) string {
	t.Helper()
	var value string
	require.NoError(t,db.QueryRow(query).Scan(&value))
	return value
}

func TestRegistrationMigrator_OriginalLineageDownUpRoundTrips(t *testing.T) {
	if testing.Short(){ t.Skip("integration: PostgreSQL") }
	for _,origin:=range []string{"fresh","main","feature"} {
		t.Run(origin,func(t *testing.T){
			dsn,db:=registrationOriginDB(t,origin)
			shape:=registrationScalar(t,db,`SELECT kaname.registration_lineage_shape()::text`)
			catalog:=registrationScalar(t,db,`SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted)::text FROM kaname.catalog_resource c`)
			for _,target:=range []string{"20261026090001","20261026090000","20261026089999","1"} {
				_,_,err:=runCommandFS(t,migrations.FS,[]string{"down","--target",target,"--dsn",dsn},nil)
				require.NoError(t,err,"%s to %s",origin,target)
				if target=="20261026090000" {
					want:="true:false"
					if origin=="feature" { want="false:true" }
					require.Equal(t,want,registrationScalar(t,db,`SELECT
                            (to_regprocedure('kaname.service_account_creator_is_immutable()') IS NOT NULL)::text||':'||
                            EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='kaname' AND table_name='catalog_resource' AND column_name='writes')::text`))
				}
				if target=="20261026089999" {
					require.Equal(t,"0",registrationScalar(t,db,`SELECT count(*)::text FROM information_schema.columns
                            WHERE table_schema='kaname' AND ((table_name='catalog_resource' AND column_name='writes')
                            OR (table_name='service_accounts' AND column_name='created_by_id'))`))
				}
				_,_,err=runCommandFS(t,migrations.FS,[]string{"up","--dsn",dsn},nil)
				require.NoError(t,err)
				require.Equal(t,shape,registrationScalar(t,db,`SELECT kaname.registration_lineage_shape()::text`))
				require.Equal(t,catalog,registrationScalar(t,db,`SELECT jsonb_agg(to_jsonb(c) ORDER BY dotted)::text FROM kaname.catalog_resource c`))
			}
		})
	}
}

func TestRegistrationMigrator_UnknownOriginRefusesBeforeAnyDown(t *testing.T) {
	if testing.Short(){ t.Skip("integration: PostgreSQL") }
	for _,scenario:=range []string{"both","missing","tampered"} {
		t.Run(scenario,func(t *testing.T){
			origin:="main"; if scenario=="both" { origin="both" }
			dsn,db:=registrationOriginDB(t,origin)
			if scenario=="missing" { _,err:=db.Exec(`DROP TABLE kaname.registration_lineage_origin`); require.NoError(t,err) }
			if scenario=="tampered" { _,err:=db.Exec(`UPDATE kaname.registration_lineage_origin SET complete_shape='{}'`); require.NoError(t,err) }
			before:=registrationScalar(t,db,`SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`)
			_,_,err:=runCommandFS(t,migrations.FS,[]string{"down","--target","1","--dsn",dsn},nil)
			require.ErrorContains(t,err,"before any Down")
			require.Equal(t,before,registrationScalar(t,db,`SELECT jsonb_agg(to_jsonb(v) ORDER BY id)::text FROM goose_db_version v`))
			require.Equal(t,"true",registrationScalar(t,db,`SELECT (to_regclass('kaname.resource_registration_command') IS NOT NULL)::text`))
		})
	}
}

func TestRegistrationMigrator_PreservesExistingWriterPolicy(t *testing.T) {
	if testing.Short(){ t.Skip("integration: PostgreSQL") }
	dsn,db:=registrationOriginDB(t,"feature")
	_,err:=db.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
	require.NoError(t,err)
	_,_,err=runCommandFS(t,migrations.FS,[]string{"down","--target","20261026090000","--dsn",dsn},nil)
	require.NoError(t,err,"исходная writer-политика переживает снятие добавленной creator-стороны")
	_,_,err=runCommandFS(t,migrations.FS,[]string{"down","--target","20261026089999","--dsn",dsn},nil)
	var violation *pgconn.PgError
	require.ErrorAs(t,err,&violation)
	require.Equal(t,"23514",violation.Code)
	require.Equal(t,"registration_lineage_lossless_down",violation.ConstraintName)
	require.Equal(t,"{owner:user}",registrationScalar(t,db,`SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
	_,_,err=runCommandFS(t,migrations.FS,[]string{"up","--dsn",dsn},nil)
	require.NoError(t,err)
	require.Equal(t,"{owner:user}",registrationScalar(t,db,`SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
}

func TestRegistrationMigrator_RollbackWaitsForWriterThenJudgesCommittedPolicy(t *testing.T) {
	if testing.Short(){ t.Skip("integration: PostgreSQL") }
	for _,commit:=range []bool{true,false} {
		t.Run(map[bool]string{true:"commit",false:"rollback"}[commit],func(t *testing.T){
			dsn,db:=registrationOriginDB(t,"main")
			_,_,err:=runCommandFS(t,migrations.FS,[]string{"down","--target","20261026090001","--dsn",dsn},nil)
			require.NoError(t,err)
			tx,err:=db.Begin()
			require.NoError(t,err)
			defer tx.Rollback()
			_,err=tx.Exec(`UPDATE kaname.catalog_resource SET writes=ARRAY['owner:user'] WHERE dotted='registry.registries'`)
			require.NoError(t,err)
			ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
			defer cancel()
			result:=make(chan error,1)
			go func(){
				cmd:=newRootCmd(migrations.FS)
				cmd.SetContext(ctx)
				cmd.SetArgs([]string{"down","--target","20261026090000","--dsn",dsn})
				result<-cmd.Execute()
			}()
			require.Eventually(t,func()bool{return rollbackIsWaitingForALock(t,db)},5*time.Second,10*time.Millisecond)
			if commit { require.NoError(t,tx.Commit()) } else { require.NoError(t,tx.Rollback()) }
			err=<-result
			if commit {
				var violation *pgconn.PgError
				require.ErrorAs(t,err,&violation)
				require.Equal(t,"23514",violation.Code)
				require.Equal(t,"{owner:user}",registrationScalar(t,db,`SELECT writes::text FROM kaname.catalog_resource WHERE dotted='registry.registries'`))
			} else { require.NoError(t,err) }
		})
	}
}

func TestRegistrationMigrator_CreatorDataCannotBeDiscarded(t *testing.T) {
	if testing.Short(){ t.Skip("integration: PostgreSQL") }
	for _,scenario:=range []string{"creator fact","creator rule","container declaration"} {
		t.Run(scenario,func(t *testing.T){
			dsn,db:=registrationOriginDB(t,"feature")
			var mutation string
			switch scenario {
			case "creator fact":
				seedCredentialOwners(t,db)
				mutation=`INSERT INTO kaname.service_accounts(id,account_id,name,created_by_type,created_by_id)
                    VALUES ('sva00000000000000own','acc00000000000000mgr','creator-owned','user','usr00000000000000mgr')`
			case "creator rule":
				mutation=`INSERT INTO kaname.roles(id,name,permissions,rules,cluster_id)
                    VALUES ('rol-lineage-creator','iam.lineage.creator','[]',
                    '[{"module":"iam","resources":["serviceAccount"],"verbs":["get"],"created_by_subject":true}]','cluster_root')`
			case "container declaration":
				mutation=`UPDATE kaname.catalog_verb SET container_relation='custom_creator'
                    WHERE module='iam' AND resource='serviceAccount' AND verb='create'`
			}
			_,err:=db.Exec(mutation)
			require.NoError(t,err)
			before:=registrationScalar(t,db,`SELECT jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM kaname.service_accounts s),
                    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM kaname.roles r),
                    (SELECT jsonb_agg(to_jsonb(v) ORDER BY module,resource,verb) FROM kaname.catalog_verb v))::text`)
			_,_,err=runCommandFS(t,migrations.FS,[]string{"down","--target","20261026090000","--dsn",dsn},nil)
			var violation *pgconn.PgError
			require.ErrorAs(t,err,&violation)
			require.Equal(t,"23514",violation.Code)
			require.Equal(t,"registration_lineage_lossless_down",violation.ConstraintName)
			require.Equal(t,before,registrationScalar(t,db,`SELECT jsonb_build_array(
                    (SELECT jsonb_agg(to_jsonb(s) ORDER BY id) FROM kaname.service_accounts s),
                    (SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM kaname.roles r),
                    (SELECT jsonb_agg(to_jsonb(v) ORDER BY module,resource,verb) FROM kaname.catalog_verb v))::text`))
		})
	}
}

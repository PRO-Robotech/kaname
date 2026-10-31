// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983

import (
    "context"
    "testing"
    "time"

    "github.com/jackc/pgx/v5"
    "github.com/jackc/pgx/v5/pgconn"
    "github.com/stretchr/testify/require"

    "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

func TestPermanentProjectCommand_StaleDoesNotCreateFirstBinding(t *testing.T) {
    w := newPPWorld(t)
    w.deliverDK()
    version := time.Now().UTC()
    const id = "983-stale-empty-project"
    _, err := w.pool.Exec(w.ctx, `INSERT INTO kaname.resource_mirror
        (object_type,object_id,parent_project_id,parent_account_id,labels,source_version)
        VALUES ($1,$2,'','','{}',$3)`, ppRegCat,id,version)
    require.NoError(t,err)
    tx,err:=w.pool.Begin(w.ctx);require.NoError(t,err)
    defer func(){_=tx.Rollback(context.Background())}()
    out,err:=resource_mirror.UpsertTx(w.ctx,tx,resource_mirror.Row{
        ObjectType:ppRegCat,ObjectID:id,ParentProjectID:string(w.prjA),
        ParentAccountID:string(w.accA),ParentChain:[]string{"project:"+string(w.prjA)},
        SourceVersion:version.Add(-time.Second),
    })
    require.NoError(t,err)
    require.False(t,out.Applied)
    require.False(t,out.ProjectionUnchanged)
    var n int
    require.NoError(t,tx.QueryRow(w.ctx,`SELECT count(*) FROM kaname.object_project_binding WHERE object_type=$1 AND object_id=$2`,pcrRegType,id).Scan(&n))
    require.Zero(t,n,"stale input is not a first accepted registration")
    var project string
    require.NoError(t,tx.QueryRow(w.ctx,`SELECT parent_project_id FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`,ppRegCat,id).Scan(&project))
    require.Empty(t,project)
    require.NoError(t,tx.Commit(w.ctx))
}

func TestPermanentProjectCommand_RawUpsertWaitsOnMirrorBeforeBinding(t *testing.T) {
    w:=newPPWorld(t);w.deliverDK()
    ctx,cancel:=context.WithTimeout(w.ctx,20*time.Second);defer cancel()
    const id="983-raw-command-lock-order"
    version:=time.Now().UTC()
    _,err:=w.pool.Exec(ctx,`INSERT INTO kaname.resource_mirror
        (object_type,object_id,parent_project_id,parent_account_id,labels,source_version)
        VALUES ($1,$2,'','','{}',$3)`,ppRegCat,id,version)
    require.NoError(t,err)
    command,err:=w.pool.Begin(ctx);require.NoError(t,err)
    defer func(){_=command.Rollback(context.Background())}()
    var commandPID int32
    require.NoError(t,command.QueryRow(ctx,`SELECT pg_backend_pid()`).Scan(&commandPID))
    _,err=command.Exec(ctx,`SELECT 1 FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2 FOR NO KEY UPDATE`,ppRegCat,id)
    require.NoError(t,err)
    raw,err:=pgx.ConnectConfig(ctx,w.pool.Config().ConnConfig.Copy());require.NoError(t,err)
    defer func(){_=raw.Close(context.Background())}()
    rawPID:=raw.PgConn().PID()
    result:=make(chan error,1)
    go func(){
        _,e:=raw.Exec(ctx,`INSERT INTO kaname.resource_mirror
            (object_type,object_id,parent_project_id,parent_account_id,labels,source_version)
            VALUES ($1,$2,$3,$4,'{}',$5)
            ON CONFLICT(object_type,object_id) DO UPDATE SET
                parent_project_id=EXCLUDED.parent_project_id,parent_account_id=EXCLUDED.parent_account_id,
                source_version=EXCLUDED.source_version`,ppRegCat,id,string(w.prjA),string(w.accA),version.Add(2*time.Second))
        result<-e
    }()
    require.Eventually(t,func()bool{
        var waiting bool
        e:=w.pool.QueryRow(ctx,`SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`,commandPID,int32(rawPID)).Scan(&waiting)
        return e==nil&&waiting
    },5*time.Second,10*time.Millisecond,"legal schedule: raw UPSERT waits for command mirror lock")
    // Old BEFORE INSERT bound first, then waited on this mirror. The command
    // would next wait on that binding: a real cycle, not a synthetic SQL order.
    out,err:=resource_mirror.UpsertTx(ctx,command,resource_mirror.Row{
        ObjectType:ppRegCat,ObjectID:id,ParentProjectID:string(w.prjA),ParentAccountID:string(w.accA),
        ParentChain:[]string{"project:"+string(w.prjA)},SourceVersion:version.Add(time.Second),
    })
    require.NoError(t,err,"command must not wait on a binding held by the raw mirror waiter")
    require.True(t,out.Applied)
    require.NoError(t,command.Commit(ctx))
    select {case err=<-result: require.NoError(t,err);case <-ctx.Done():t.Fatal(ctx.Err())}
    var bound string
    require.NoError(t,w.pool.QueryRow(ctx,`SELECT project_id FROM kaname.object_project_binding WHERE object_type=$1 AND object_id=$2`,pcrRegType,id).Scan(&bound))
    require.Equal(t,string(w.prjA),bound)
}

func TestPermanentProjectCommand_RefusalRollsBackProvisionalMirrorAndBinding(t *testing.T) {
    w:=newPPWorld(t);w.deliverDK()
    const id="983-command-foreign-chain"
    _,err:=w.pool.Exec(w.ctx,`INSERT INTO kaname.resource_registration_command
        (dotted_type,object_id,parent_project_id,parent_account_id,labels,source_version,parent_chain,
         type_live,model_type,applied,projection_unchanged)
        VALUES ($1,$2,$3,$4,'{}',now(),$5,true,'spoofed',true,true)`,
        ppRegCat,id,string(w.prjA),string(w.accA),[]string{"project:"+string(w.prjA),"project:"+string(w.prjC)})
    var pgerr *pgconn.PgError
    require.ErrorAs(t,err,&pgerr)
    require.Equal(t,"23000",pgerr.Code)
    require.Equal(t,"object_project_binding_holds",pgerr.ConstraintName)
    for _,table:=range []string{"resource_mirror","resource_parent_edge","object_project_binding"}{
        var n int
        require.NoError(t,w.pool.QueryRow(w.ctx,`SELECT count(*) FROM kaname.`+table+` WHERE object_id=$1`,id).Scan(&n))
        require.Zero(t,n,table+" must roll back with the complete command")
    }
}

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
    // Барьер создаёт настоящий command: строка зеркала и общий writer fence
    // удерживаются до коммита. Ручной row lock до входа в протокол не является
    // расписанием реального UpsertTx и может инвертировать любой ранний fence.
    held,err:=resource_mirror.UpsertTx(ctx,command,resource_mirror.Row{
        ObjectType:ppRegCat,ObjectID:id,SourceVersion:version.Add(-time.Second),
    })
    require.NoError(t,err)
    require.False(t,held.Applied)
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
    },5*time.Second,10*time.Millisecond,"законный raw UPSERT ждёт транзакцию настоящего command")
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

func TestPermanentProjectCommand_MixedRawTransactions(t *testing.T) {
    for _, commandFirst := range []bool{false,true} {
        name:="raw_then_command";if commandFirst{name="command_then_raw"}
        t.Run(name,func(t *testing.T){
            w:=newPPWorld(t);w.deliverDK()
            ctx,cancel:=context.WithTimeout(w.ctx,20*time.Second);defer cancel()
            id:="983-mixed-"+name
            first,err:=w.pool.Begin(ctx);require.NoError(t,err)
            defer func(){_=first.Rollback(context.Background())}()
            _,err=first.Exec(ctx,"SET CONSTRAINTS ALL IMMEDIATE");require.NoError(t,err)
            row:=resource_mirror.Row{ObjectType:ppRegCat,ObjectID:id,ParentProjectID:string(w.prjA),ParentAccountID:string(w.accA),
                ParentChain:[]string{"project:"+string(w.prjA)},SourceVersion:time.Now().UTC()}
            if commandFirst {
                _,err=resource_mirror.UpsertTx(ctx,first,row);require.NoError(t,err)
            }else{
                _,err=first.Exec(ctx,`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version)
                    VALUES ($1,$2,'project',$3,3,now())`,pcrRegType,id,string(w.prjA));require.NoError(t,err)
            }
            second,err:=pgx.ConnectConfig(ctx,w.pool.Config().ConnConfig.Copy());require.NoError(t,err)
            defer func(){_=second.Close(context.Background())}()
            firstPID:=first.Conn().PgConn().PID();secondPID:=second.PgConn().PID()
            done:=make(chan error,1)
            go func(){
                tx,e:=second.Begin(ctx);if e!=nil{done<-e;return};defer func(){_=tx.Rollback(context.Background())}()
                _,e=tx.Exec(ctx,"SET CONSTRAINTS ALL IMMEDIATE")
                next:=row;next.SourceVersion=row.SourceVersion.Add(time.Second)
                if e==nil{_,e=resource_mirror.UpsertTx(ctx,tx,next)}
                if e==nil{_,e=tx.Exec(ctx,`INSERT INTO kaname.resource_parent_edge(object_type,object_id,parent_type,parent_id,depth,source_version)
                    VALUES ($1,$2,'project',$3,4,now())`,pcrRegType,id,string(w.prjA))}
                if e==nil{e=tx.Commit(ctx)}
                done<-e
            }()
            require.Eventually(t,func()bool{
                var waits bool
                e:=w.pool.QueryRow(ctx,`SELECT $1::integer=ANY(pg_blocking_pids($2::integer))`,int32(firstPID),int32(secondPID)).Scan(&waits)
                return e==nil&&waits
            },5*time.Second,10*time.Millisecond,"второй writer ждёт первый до захвата строк")
            // Продолжение первой TX после появления конкурента: fence уже взят,
            // поэтому команда и сырой writer не повышают режим замка.
            _,err=first.Exec(ctx,`INSERT INTO kaname.resource_mirror(object_type,object_id,parent_project_id,parent_account_id,labels,source_version)
                VALUES ($1,$2,$3,$4,'{}',$5) ON CONFLICT(object_type,object_id) DO UPDATE
                SET parent_project_id=EXCLUDED.parent_project_id,source_version=EXCLUDED.source_version`,
                ppRegCat,id,string(w.prjA),string(w.accA),row.SourceVersion)
            require.NoError(t,err)
            if !commandFirst{_,err=resource_mirror.UpsertTx(ctx,first,row);require.NoError(t,err)}
            require.NoError(t,first.Commit(ctx))
            select{case err=<-done:require.NoError(t,err);case<-ctx.Done():t.Fatal(ctx.Err())}
            var mismatches int
            require.NoError(t,w.pool.QueryRow(ctx,`SELECT count(*) FROM kaname.resource_parent_edge e
                JOIN kaname.object_project_binding b USING(object_type,object_id)
                WHERE e.object_type=$1 AND e.object_id=$2 AND e.parent_type='project' AND e.parent_id<>b.project_id`,pcrRegType,id).Scan(&mismatches))
            require.Zero(t,mismatches)
        })
    }
}

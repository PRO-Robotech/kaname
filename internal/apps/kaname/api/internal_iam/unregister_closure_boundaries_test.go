// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// verifies https://github.com/PRO-Robotech/kaname/issues/1019

import (
 "context"
 "errors"
 "fmt"
 "testing"
 "time"

 "github.com/stretchr/testify/require"
 "github.com/PRO-Robotech/kaname/internal/domain"
 iamerr "github.com/PRO-Robotech/kaname/internal/errors"
 "github.com/PRO-Robotech/kaname/internal/service"
)

// closureBoundaryTx хранит эффекты отдельно до подтверждённого коммита.
type closureBoundaryTx struct {
 owner *closureBoundaryBeginner
 number, census int
 dropped []string
 events []service.AuditEvent
 committed bool
}
func (tx *closureBoundaryTx) Commit(context.Context) error {
 tx.owner.commits++
 if tx.owner.commitErr != nil { return tx.owner.commitErr }
 tx.committed=true
 tx.owner.persisted=append(tx.owner.persisted,tx.events...)
 return nil
}
func (tx *closureBoundaryTx) Rollback(ctx context.Context) error {
 tx.owner.rollbacks++
 if tx.owner.onRollback!=nil { tx.owner.onRollback(ctx) }
 tx.events=nil
 return tx.owner.rollbackErr
}
type closureBoundaryBeginner struct {
 txs []*closureBoundaryTx
 commits,rollbacks int
 commitErr,rollbackErr error
 onRollback func(context.Context)
 persisted []service.AuditEvent
}
func (b *closureBoundaryBeginner) Begin(context.Context)(service.Tx,error){
 tx:=&closureBoundaryTx{owner:b,number:len(b.txs)+1}
 b.txs=append(b.txs,tx)
 return tx,nil
}
type closureBoundaryMirror struct {
 mirrorAdapter
 expandAttempts int
}
func (*closureBoundaryMirror) DeleteTx(context.Context,service.Tx,string,string,time.Time)(bool,error){return true,nil}
func (m *closureBoundaryMirror) DescendantsTx(_ context.Context, handle service.Tx,_,_ string)([]service.RegisteredDescendant,error){
 tx:=handle.(*closureBoundaryTx);tx.census++
 // Каждый повтор получает новый поздний ключ. Исчезнувший ключ предыдущей
 // попытки остаётся подсказкой замка, но больше не является потомком.
 if tx.census==2 && tx.number<=m.expandAttempts {
  return []service.RegisteredDescendant{{ModelType:"registry_repository",ID:fmt.Sprintf("reg1/late-%d",tx.number)}},nil
 }
 return nil,nil
}
func (*closureBoundaryMirror) DropRegistrationTx(_ context.Context,handle service.Tx,_,_ string,id string)(bool,time.Time,error){
 tx:=handle.(*closureBoundaryTx);tx.dropped=append(tx.dropped,id)
 return true,time.Time{},nil
}
type closureBoundaryAudit struct{noAudit}
func (closureBoundaryAudit) EmitTx(_ context.Context,handle service.Tx,event service.AuditEvent)error{
 tx:=handle.(*closureBoundaryTx);tx.events=append(tx.events,event);return nil
}

func TestUnregisterClosure_Boundaries(t *testing.T){
 for _,scenario:=range []string{"eight_expansions","cancel_before_begin","cancel_during_rollback","rollback_failure","commit_ambiguity","hints_are_not_authority"}{
  t.Run(scenario,func(t *testing.T){
   ctx,cancel:=context.WithCancel(context.Background());defer cancel()
   b:=&closureBoundaryBeginner{}
   m:=&closureBoundaryMirror{expandAttempts:1}
   switch scenario {
   case "eight_expansions":m.expandAttempts=8
   case "cancel_before_begin":cancel()
   case "cancel_during_rollback":
    b.onRollback=func(rollbackCtx context.Context){
     cancel()
     require.NoError(t,rollbackCtx.Err(),"отмена запроса не отменяет откат")
     deadline,ok:=rollbackCtx.Deadline();require.True(t,ok)
     require.WithinDuration(t,time.Now().Add(5*time.Second),deadline,time.Second)
    }
   case "rollback_failure":b.rollbackErr=errors.New("private rollback driver address")
   case "commit_ambiguity":m.expandAttempts=0;b.commitErr=errors.New("private commit driver address")
   }
   withdrawal:=&recordingWithdrawal{}
   emitter:=&recordingEmitter{}
   uc:=NewRegisterResourceUseCase(emitter,m,b,seededCatalogTypes{},&recordingPublisher{},withdrawal,closureBoundaryAudit{},unitScopes())
   err:=uc.Unregister(ctx,&unregReq{subject:"project:prj_a",relation:"project",object:"registry_registry:reg1",version:time.Now()})
   switch scenario {
   case "hints_are_not_authority":
    require.NoError(t,err);require.Len(t,b.txs,2)
    require.Contains(t,withdrawal.locked[1],domain.ResourceRef{Type:"registry.repositories",ID:"reg1/late-1"})
    require.NotContains(t,withdrawnKeys(withdrawal),"registry.repositories/reg1/late-1")
    for _,tx:=range b.txs {require.Empty(t,tx.dropped,"подсказка не разрешает удаление")}
    require.Len(t,b.persisted,1,"отброшенная попытка не оставляет событие")
    require.Equal(t,0,b.persisted[0].Payload["descendants"])
    require.Len(t,emitter.deletes,1,"отброшенная попытка не доходит до журнала фактов")
    require.Equal(t,1,b.commits)
   case "cancel_before_begin":
    require.ErrorIs(t,err,context.Canceled);require.Empty(t,b.txs);require.Zero(t,b.commits)
   case "cancel_during_rollback":
    require.ErrorIs(t,err,context.Canceled);require.Len(t,b.txs,1);require.Zero(t,b.commits)
   default:
    require.ErrorIs(t,err,iamerr.ErrUnavailable)
    require.NotContains(t,err.Error(),"private")
    require.NotContains(t,err.Error(),"closure")
    attempts:=1;if scenario=="eight_expansions"{attempts=8}
    require.Len(t,b.txs,attempts,"новый Begin после границы запрещён")
    require.Empty(t,b.persisted)
    if scenario=="commit_ambiguity"{require.Equal(t,1,b.commits)}else{require.Zero(t,b.commits)}
   }
   require.Equal(t,len(b.txs),b.rollbacks,"каждая попытка завершает откат до нового Begin")
  })
 }
}

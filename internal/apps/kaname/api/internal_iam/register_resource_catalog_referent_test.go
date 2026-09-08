// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// register_resource_catalog_referent_test.go — что видит ВЫЗЫВАЮЩИЙ, когда тип
// объекта не имеет живой строки в каталоге ресурсов платформы.
//
// Сверка с каталогом выражена оператором в базе (`repo/.../resource_mirror`), и
// её собственная проба живёт там. Здесь закрепляется другая половина того же
// предмета — КОНТРАКТ ОТКАЗА, которого оператор не касается:
//
//   - код — `INVALID_ARGUMENT`, а не непрозрачный INTERNAL: форма кортежа верна,
//     негоден вход, и вызывающему есть что чинить;
//   - в отказе НАЗВАНО поле (`object`) отдельным элементом, а не прозой: полос
//     отказа у этого глагола несколько, и различать их машинно должен клиент;
//   - в тексте назван ТИП — иначе «неверный object» не отличить от грамматики;
//   - внутреннее имя шага («upsert resource mirror») наружу НЕ уезжает;
//   - строка НАМЕРЕНИЯ в очередь не кладётся. Это несущее: доставленное
//     намерение, которое принимающая сторона отвергает, приходило бы с отказом на
//     КАЖДОЙ доставке.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// recordingEmitter — очередь намерений, которая ЗАПОМИНАЕТ положенное.
// Утверждать «отказ произошёл» мало: предмет класса в том, что отвергнутое
// намерение не должно доехать до очереди вовсе.
type recordingEmitter struct{ writes, deletes [][]service.RelationTuple }

func (e *recordingEmitter) EmitWriteTx(_ context.Context, _ service.Tx, t []service.RelationTuple) error {
	e.writes = append(e.writes, t)
	return nil
}

func (e *recordingEmitter) EmitDeleteTx(_ context.Context, _ service.Tx, t []service.RelationTuple) error {
	e.deletes = append(e.deletes, t)
	return nil
}

// refusingMirror — зеркало, которое отвергает тип ровно так, как это делает
// оператор каталога. Дублёр НЕ снисходительнее настоящего: он возвращает тот же
// признак и тот же текст, поэтому проба меряет отображение отказа, а не свою
// выдумку.
type refusingMirror struct{ objectType string }

func (m refusingMirror) UpsertTx(_ context.Context, _ service.Tx, row service.ResourceMirrorRow) (bool, bool, error) {
	if row.ObjectType == m.objectType {
		return false, false, iamerr.Wrapf(iamerr.ErrUnknownResourceType,
			"resource type %q is not a live entry of the platform resource catalog", row.ObjectType)
	}
	return true, false, nil
}

func (refusingMirror) DeleteTx(context.Context, service.Tx, string, string, time.Time) error {
	return nil
}

// TestRegisterResource_UnknownResourceType_IsAFieldNamedInvalidArgument — отказ
// назван полем, тип в тексте, намерение в очередь не легло.
func TestRegisterResource_UnknownResourceType_IsAFieldNamedInvalidArgument(t *testing.T) {
	emitter := &recordingEmitter{}
	uc := NewRegisterResourceUseCase(
		emitter,
		// Отвергается тип, ПРОШЕДШИЙ правило приёма: приставка домена у него
		// законная (`vpc_`), отношение иерархическое. Именно этот вход правило
		// приёма пропускает, и именно на нём сверка с каталогом что-то решает.
		refusingMirror{objectType: "vpc_totally_invented"},
		&smTxBeginner{},
		seededCatalogTypes{},
	)

	err := uc.Register(context.Background(), &regReq{
		subject: "project:prj_1", relation: "project", object: "vpc_totally_invented:x1",
	})
	require.Error(t, err)

	mapped := shared.MapRepoErr(err)
	st := status.Convert(mapped)
	assert.Equal(t, codes.InvalidArgument, st.Code(),
		"форма кортежа верна, негоден вход — это неверный аргумент, а не сбой")
	assert.Contains(t, st.Message(), "vpc_totally_invented",
		"отказ обязан НАЗЫВАТЬ тип: без имени вызывающий не знает, что чинить")
	assert.NotContains(t, st.Message(), "upsert resource mirror",
		"внутреннее имя шага наружу не уезжает")

	var named bool
	for _, d := range st.Details() {
		br, ok := d.(*errdetails.BadRequest)
		if !ok {
			continue
		}
		for _, v := range br.GetFieldViolations() {
			if v.GetField() == "object" {
				named = true
			}
		}
	}
	assert.True(t, named,
		"поле обязано быть названо ЭЛЕМЕНТОМ отказа: полос отказа у этого глагола "+
			"несколько, и различать их клиент должен машинно, а не разбором прозы")

	assert.Empty(t, emitter.writes,
		"отвергнутое намерение не вправе лечь в очередь: доставленное, но не "+
			"принимаемое намерение отвергается на КАЖДОЙ доставке")
}

// TestRegisterResource_LiveResourceType_StillRegisters — положительный контроль
// на той же оси. Без него утверждение выше зеленело бы на реализации,
// отвергающей вообще всякую регистрацию.
func TestRegisterResource_LiveResourceType_StillRegisters(t *testing.T) {
	emitter := &recordingEmitter{}
	uc := NewRegisterResourceUseCase(
		emitter,
		refusingMirror{objectType: "vpc_totally_invented"},
		&smTxBeginner{},
		seededCatalogTypes{},
	)

	err := uc.Register(context.Background(), &regReq{
		subject: "project:prj_1", relation: "project", object: "vpc_network:net_1",
	})
	require.NoError(t, err, "живой тип каталога обязан регистрироваться по-прежнему")
	require.Len(t, emitter.writes, 1, "принятое намерение обязано лечь в очередь")
}

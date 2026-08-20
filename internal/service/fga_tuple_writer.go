// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_tuple_writer.go — доступ к хранилищу кортежей движка для
// InternalAuthorizeService: WriteTuples / ReadTuples / GetFGAStoreInfo.
//
// ЧТО ЗДЕСЬ БЫЛО И ПОЧЕМУ СНЯТО. Тип нёс тройку OnAccessBindingCreated /
// Deleted / Updated — проекцию жизненного цикла AccessBinding прямо в движок.
// Прод-вызывающих у неё не было НИ ОДНОГО (выдача давно идёт реконсайлером через
// строку журнала), а вход в движок она открывала настоящий: три места записи,
// каждое мимо `kacho_iam.fga_outbox`. Мёртвый обход опаснее живого — он не
// проявляется ничем, поэтому и не чинится, — и снят вместе со своими пробами.
//
// ОСТАВШЕЕСЯ МЕСТО ЗАПИСИ — ОДНО, И ОНО ОБЪЯВЛЕНО ОБХОДОМ. `WriteRaw` обслуживает
// административный `InternalAuthorizeService.WriteTuples`: кортеж уходит в движок
// НАПРЯМУЮ, минуя журнал, поэтому проекция `relation_fact` (миграция 0098) его не
// увидит никогда. Вызывающих в дереве ноль; терминальный исход — снять RPC, что
// ломает контракт proto и идёт своим изменением. До тех пор место стоит в
// ведомости гейта `tools/authzenginecensus/engineplaces/journaldoor_test.go`
// как объявленное исключение с предикатом снятия.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// RelationWriter — port-iface narrowed to writer-needs.
type RelationWriter interface {
	WriteConditionalTuples(ctx context.Context, writes, deletes []authztypes.ConditionalTuple) error
	ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error)
	GetStoreInfo(ctx context.Context) (authztypes.StoreInfo, error)
}

// RelationProjector — service.
type RelationProjector struct {
	relations RelationWriter
}

// NewRelationProjector — builder.
func NewRelationProjector(relations RelationWriter) *RelationProjector {
	return &RelationProjector{relations: relations}
}

// WriteRaw — pass-through used by InternalAuthorizeService.WriteTuples
// admin RPC.
func (w *RelationProjector) WriteRaw(ctx context.Context, writes, deletes []authztypes.ConditionalTuple) (inserted, deleted int, err error) {
	if w.relations == nil {
		return 0, 0, fmt.Errorf("fga: writer not configured")
	}
	if err := w.relations.WriteConditionalTuples(ctx, writes, deletes); err != nil {
		return 0, 0, err
	}
	return len(writes), len(deletes), nil
}

// ReadRaw — used by InternalAuthorizeService.ReadTuples.
func (w *RelationProjector) ReadRaw(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error) {
	if w.relations == nil {
		return nil, "", fmt.Errorf("fga: writer not configured")
	}
	// Trim trailing `*` wildcard in filters — FGA expects bare prefixes.
	subjectFilter = strings.TrimSuffix(subjectFilter, "*")
	objectFilter = strings.TrimSuffix(objectFilter, "*")
	return w.relations.ReadTuples(ctx, subjectFilter, relationFilter, objectFilter, pageSize, pageToken)
}

// StoreInfo — pass-through for InternalAuthorizeService.GetFGAStoreInfo.
func (w *RelationProjector) StoreInfo(ctx context.Context) (authztypes.StoreInfo, error) {
	if w.relations == nil {
		return authztypes.StoreInfo{}, fmt.Errorf("fga: writer not configured")
	}
	return w.relations.GetStoreInfo(ctx)
}

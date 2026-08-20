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
// МЕСТ ЗАПИСИ ЗДЕСЬ БОЛЬШЕ НЕТ — ТИП ЧИТАЮЩИЙ. `WriteRaw` обслуживал
// административный `InternalAuthorizeService.WriteTuples` и уводил кортеж в движок
// НАПРЯМУЮ, мимо журнала, поэтому проекция `relation_fact` (миграция 0098) его не
// увидела бы никогда. RPC снят целиком (#788) — вызывающих у него не было ни
// одного, — и вместе с ним снята дверь: ведомость гейта
// `tools/authzenginecensus/engineplaces/journaldoor_test.go` больше не несёт
// объявленного исключения на этот файл, а сам гейт покраснел бы, если бы несла.
//
// Порт сужен до чтения НАМЕРЕННО. Запись кортежа выражается строкой
// `kacho_iam.fga_outbox`, и другого способа у сервиса быть не должно: тип, у
// которого нет метода записи, нельзя переоткрыть одной строкой вызова.
package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
)

// RelationReader — port-iface narrowed to the read-only needs of
// InternalAuthorizeService. Запись в движок этим портом невыразима.
type RelationReader interface {
	ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]authztypes.ConditionalTuple, string, error)
	GetStoreInfo(ctx context.Context) (authztypes.StoreInfo, error)
}

// RelationProjector — service.
type RelationProjector struct {
	relations RelationReader
}

// NewRelationProjector — builder.
func NewRelationProjector(relations RelationReader) *RelationProjector {
	return &RelationProjector{relations: relations}
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

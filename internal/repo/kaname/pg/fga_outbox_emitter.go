// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// fga_outbox_emitter.go — адаптер pg для service.RelationOutboxEmitter.
//
// Пересылает вызовы выдачи/отзыва внутри транзакции из путей управления (автовыдача JIT,
// JitPending Approve, исполнители истечения JIT/BG, BG.ApproveB) во
// внутренний вспомогательный пакет `fga_outbox`, выполняющий INSERT.
//
// Адаптер без состояния: настоящий INSERT исполняется на переданной транзакции, никогда не на
// соединении, управляемом пулом (иначе отправка перестала бы быть атомарной с
// доменной мутацией).
package pg

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgtype"
)

// FGAOutboxEmitter — адаптер, реализующий service.RelationOutboxEmitter поверх
// пакета fga_outbox. Без состояния.
type FGAOutboxEmitter struct{}

// NewFGAOutboxEmitter — конструктор корня композиции.
func NewFGAOutboxEmitter() *FGAOutboxEmitter {
	return &FGAOutboxEmitter{}
}

// EmitWriteTx — реализует service.RelationOutboxEmitter. Восстанавливает конкретный
// pgx.Tx из непрозрачного дескриптора и пересылает в fga_outbox.EmitWriteTx.
func (e *FGAOutboxEmitter) EmitWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	// Только частный cluster wrapper несёт завершённый защищённый decision.
	if held, ok := tx.(*clusterAdminParticipantTx); ok && !held.ClusterAdminDecisionAt().IsZero() {
		return fga_outbox.EmitDecisionTx(ctx, txAsPgx(tx), fga_outbox.EventTypeWrite, serviceTuplesToClients(tuples), held.ClusterAdminDecisionAt())
	}
	return fga_outbox.EmitWriteTx(ctx, txAsPgx(tx), serviceTuplesToClients(tuples))
}

// EmitDeleteTx — симметричная сторона отзыва.
func (e *FGAOutboxEmitter) EmitDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple) error {
	// Только частный cluster wrapper несёт завершённый защищённый decision.
	if held, ok := tx.(*clusterAdminParticipantTx); ok && !held.ClusterAdminDecisionAt().IsZero() {
		return fga_outbox.EmitDecisionTx(ctx, txAsPgx(tx), fga_outbox.EventTypeDelete, serviceTuplesToClients(tuples), held.ClusterAdminDecisionAt())
	}
	return fga_outbox.EmitDeleteTx(ctx, txAsPgx(tx), serviceTuplesToClients(tuples))
}

// EmitOrderedWriteTx — запись отношений посредника регистрации, упорядоченная
// версией регистрации владельца (kaname#969). Намерение без версии (производитель
// прежней формы) кладётся с версией '-infinity' — тем же значением, которым его
// хранит строка зеркала: такая запись ложится на пустое место и не опускает
// факт, записанный версией, и снятие любой версии её снимает.
func (e *FGAOutboxEmitter) EmitOrderedWriteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple, version time.Time) error {
	return fga_outbox.EmitOwnerOrderedTx(ctx, txAsPgx(tx), fga_outbox.EventTypeWrite,
		serviceTuplesToClients(tuples), ownerVersionOrMinusInfinity(version))
}

// EmitOrderedDeleteTx — снятие отношений посредника регистрации версией надгробия
// (kaname#969): снимаются факты не новее надгробия, кортежи регистрации новее
// него остаются. Надгробие без версии упорядочить нечем, и снятие идёт прежней
// формой — меткой момента вставки, то есть снимает всё, что видит (fail-closed).
func (e *FGAOutboxEmitter) EmitOrderedDeleteTx(ctx context.Context, tx service.Tx, tuples []service.RelationTuple, tombstone time.Time) error {
	return fga_outbox.EmitRegistrationDeleteTx(ctx, txAsPgx(tx), serviceTuplesToClients(tuples), tombstone)
}

// ownerVersionOrMinusInfinity — версия владельца; нулевая — '-infinity'.
func ownerVersionOrMinusInfinity(v time.Time) pgtype.Timestamptz {
	if v.IsZero() {
		return pgtype.Timestamptz{InfinityModifier: pgtype.NegativeInfinity, Valid: true}
	}
	return pgtype.Timestamptz{Time: v, Valid: true}
}

// serviceTuplesToClients — RelationTuple слоя служб → clients.RelationTuple
// (форма, принимаемая помощником INSERT fga_outbox). Обе формы — одинаковые
// тройки; преобразование нужно лишь для освобождения слоя служб от
// импорта пакета clients.
func serviceTuplesToClients(tuples []service.RelationTuple) []clients.RelationTuple {
	out := make([]clients.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = clients.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}
	return out
}

// EmitVersionedDeleteTx сохраняет индивидуальные версии и единый порядок
// блокировок фактов для родителя и смешанных потомков в одной транзакции вызывающего.
func (e *FGAOutboxEmitter) EmitVersionedDeleteTx(ctx context.Context, tx service.Tx, rows []service.VersionedRelationTuple) error {
	return fga_outbox.EmitVersionedDeleteTx(ctx, txAsPgx(tx), rows)
}

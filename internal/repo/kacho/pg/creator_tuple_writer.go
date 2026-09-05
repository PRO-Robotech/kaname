// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// creator_tuple_writer.go — запись кортежа создателя СТРОКОЙ ЖУРНАЛА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ
//
// `InternalIAMService.WriteCreatorTuple` писал кортеж напрямую в чужое хранилище
// отношений. Хранилища нет; предмет RPC при этом никуда не делся — модуль
// по-прежнему обязан сообщить, что у созданного им объекта есть владелец.
//
// Поэтому запись идёт туда же, куда идёт КАЖДОЕ намерение об отношении: строкой
// журнала `kacho_iam.fga_outbox`. Триггер журнала складывает из неё прямой факт в
// той же транзакции, поэтому у вызывающего «записал» и «действует» совпадают, а
// не разделены дренажом, как раньше.
//
// ПОЧЕМУ ОТДЕЛЬНАЯ ТРАНЗАКЦИЯ, А НЕ ЧУЖАЯ. У этого RPC нет объемлющей мутации: он
// сам по себе и есть вся мутация. Транзакция открывается здесь, и «принято» для
// вызывающего означает «закоммичено», а не «поставлено в очередь».

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// CreatorTupleWriter пишет кортеж создателя строкой журнала намерений.
type CreatorTupleWriter struct {
	pool    *pgxpool.Pool
	emitter *FGAOutboxEmitter
}

// NewCreatorTupleWriter собирает писателя. nil-пул даёт nil: композиционный корень
// без базы получает непровязанный писатель, а не панику, и RPC честно отвечает
// «не сконфигурирован».
func NewCreatorTupleWriter(pool *pgxpool.Pool) *CreatorTupleWriter {
	if pool == nil {
		return nil
	}
	return &CreatorTupleWriter{pool: pool, emitter: NewFGAOutboxEmitter()}
}

// RecordTuples кладёт намерения в журнал одной транзакцией.
//
// Имя говорит «записать намерение», а не «записать кортежи»: второе называло бы
// адресатом хранилище отношений, которого нет.
func (w *CreatorTupleWriter) RecordTuples(ctx context.Context, tuples []clients.RelationTuple) error {
	if w == nil || w.pool == nil {
		return fmt.Errorf("creator tuple writer: не собран")
	}
	if len(tuples) == 0 {
		return nil
	}
	out := make([]service.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = service.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}

	tx, err := w.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("creator tuple writer: транзакция: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if eerr := w.emitter.EmitWriteTx(ctx, tx, out); eerr != nil {
		return fmt.Errorf("creator tuple writer: строка журнала: %w", eerr)
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return fmt.Errorf("creator tuple writer: коммит: %w", cerr)
	}
	return nil
}

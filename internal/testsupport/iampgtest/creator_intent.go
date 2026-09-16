// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iampgtest

// creator_intent.go — запись намерения об отношении ПРОДУКТОВЫМ эмиттером.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТКУДА ВЗЯЛСЯ ЭТОТ ПОМОЩНИК
//
// Тем же делом занимался `pg.CreatorTupleWriter` — адаптер снятого RPC
// `InternalIAMService.WriteCreatorTuple`. RPC снят надгробиями (#788, «порт
// записи снят НАМЕРЕННО»), прод-вызывателей у писателя не осталось НИ ОДНОГО, и
// жив он был только тремя интеграционными пробами (kaname#115).
//
// Прод-код, чей единственный потребитель — проба, есть фикстура, называющая себя
// продуктом. Опаснее всего здесь не лишние строки, а то, что его шапка
// утверждала «предмет RPC никуда не делся»: читатель заключал, что путь живой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СОХРАНЕНО, А ЧТО ПЕРЕЕХАЛО
//
// Сохранено то, ради чего пробы и звали писателя: намерение кладёт ПРОДУКТОВЫЙ
// эмиттер `pg.NewFGAOutboxEmitter`, а не сырой INSERT. Проба, кладущая строку
// своим SQL, осталась бы зелёной при сломанном либо снятом продуктовом пути
// эмиссии — то есть проверяла бы схему, а не тракт.
//
// Переехала ТРАНЗАКЦИЯ вокруг него. Продуктовой логики в ней нет: открыть,
// позвать эмиттер, закоммитить. У снятого RPC она означала «принято =
// закоммичено», потому что объемлющей мутации у него не было; у пробы она
// означает ровно то же и ничего сверх.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗДЕСЬ, А НЕ ФАЙЛОМ `_test.go` РЯДОМ
//
// По той же причине, по какой здесь лежит остальное (см. шапку пакета): помощника
// зовут пробы ДВУХ разных пакетов (`pg` и `pg/relverdict`), а `*_test.go` из
// другого пакета импортировать нельзя.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/clients"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// EmitCreatorIntent кладёт намерения об отношении строкой журнала
// `kaname.fga_outbox` одной транзакцией. Триггер журнала складывает из неё прямой
// факт в той же транзакции, поэтому у вызывающего «записал» и «действует»
// совпадают, а не разделены дренажом.
func EmitCreatorIntent(ctx context.Context, pool *pgxpool.Pool, tuples []clients.RelationTuple) error {
	if pool == nil {
		return fmt.Errorf("iampgtest: пул не собран")
	}
	if len(tuples) == 0 {
		return nil
	}
	out := make([]service.RelationTuple, len(tuples))
	for i, t := range tuples {
		out[i] = service.RelationTuple{User: t.User, Relation: t.Relation, Object: t.Object}
	}

	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("iampgtest: транзакция: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op после Commit

	if eerr := kanamepg.NewFGAOutboxEmitter().EmitWriteTx(ctx, tx, out); eerr != nil {
		return fmt.Errorf("iampgtest: строка журнала: %w", eerr)
	}
	if cerr := tx.Commit(ctx); cerr != nil {
		return fmt.Errorf("iampgtest: коммит: %w", cerr)
	}
	return nil
}

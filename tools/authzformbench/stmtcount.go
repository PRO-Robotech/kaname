// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"context"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
)

// Производитель величины `StmtSQL` — на КАЖДОЕ место снятия, а не один на форму.
//
// Мест было два: Postgres движка отношений (там стейтменты порождал сам движок, и
// увидеть их можно было только его же датастором, дельтой `pg_stat_statements`) и
// Postgres формы E (там стейтменты порождаем мы, и считать их можно на своём
// соединении). Общего производителя у них не было by construction: у первого нет
// хука трассировки, у второго нет расширения статистики.
//
// Первое место снято вместе с движком (S6), и вместе с ним снят его производитель:
// счётчик, которому нечего считать, печатал бы ноль, неотличимый от измеренного.
// Мест по-прежнему два, но обоими сегодня заведует трассировщик ниже — своя
// посадка прибора и продуктовые таблицы iam (прогон Ф5).
//
// Ни один производитель не считается заведённым, пока не показан контроль в ОБЕ
// стороны: (а) счётчик не двигается, когда никто не спрашивает — иначе мерился бы
// фон; (б) счётчик двигается ровно на один на одном заведомом стейтменте — иначе
// мерится что-то другое. Обе половины проверяются исполнением и печатаются в
// провенансе: величина, у входа которой нет производителя, зеленеет молча.

// stmtTracer считает стейтменты, пущенные пулом формы E.
//
// Готового счётчика для этого места не существует, поэтому форма E берёт своё
// соединение и счётчик пишется здесь. Считается КАЖДЫЙ стейтмент,
// включая `begin`/`commit`: транзакция — такая же работа Postgres, и прятать её
// значило бы напечатать заниженную величину под именем измеренной.
type stmtTracer struct {
	n atomic.Int64
}

func (t *stmtTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	t.n.Add(1)
	return ctx
}

func (t *stmtTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func (t *stmtTracer) count() int { return int(t.n.Load()) }

// window — окно измерения: разность показаний трассировщика.
type stmtWindow struct {
	t    *stmtTracer
	base int
}

func (t *stmtTracer) open() stmtWindow { return stmtWindow{t: t, base: t.count()} }

func (w stmtWindow) close() int { return w.t.count() - w.base }

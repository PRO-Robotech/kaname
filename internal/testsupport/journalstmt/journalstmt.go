// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package journalstmt — счётчик операторов журнала прав по транзакциям базы пробы
// (kaname#617).
//
// # Предмет
//
// Свёртка журнала (`kaname.fga_outbox`) в прямой факт берёт замки строк факта в
// общем порядке (объект, субъект, отношение) лишь внутри ОДНОГО оператора. Между
// операторами одной транзакции порядок — порядок вызовов писателя, и транзакция с
// двумя операторами журнала сходится в кольцо (40P01) с любым писателем, берущим
// те же факты в общем порядке. Свойство «один оператор журнала на транзакцию» база
// не держит, и наблюдать его снаружи по строкам нельзя: строки одной транзакции
// неотличимы от строк одного оператора.
//
// # Как считается
//
// В базу пробы (своя база каждой пробы, `pgtest.NewDB`) ставится операторный
// триггер AFTER INSERT на журнале: каждый оператор вставки кладёт строку с
// идентификатором своей транзакции в таблицу счётчика. Число строк на
// транзакцию — число операторов журнала, которые она положила. Пустой оператор
// (вставка без строк) тоже считается — писатели продукта пустых операторов не
// кладут, поэтому лишний счёт был бы находкой, а не шумом.
//
// Счётчик — в схеме `public` базы пробы, а не в схеме продукта: схема продукта
// судится гейтами формы, и объект пробы в ней был бы ложным предметом.
package journalstmt

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Probe — установленный счётчик операторов журнала.
type Probe struct {
	pool *pgxpool.Pool
}

// Install ставит счётчик в базу пробы. Снимается он вместе с базой пробы.
func Install(t testing.TB, ctx context.Context, pool *pgxpool.Pool) *Probe {
	t.Helper()
	_, err := pool.Exec(ctx, `
		CREATE TABLE public.journal_statement_probe (
			xid  xid8   NOT NULL,
			seen bigint GENERATED ALWAYS AS IDENTITY
		);
		CREATE FUNCTION public.journal_statement_probe_count() RETURNS trigger
		LANGUAGE plpgsql AS $$
		BEGIN
			INSERT INTO public.journal_statement_probe (xid) VALUES (pg_current_xact_id());
			RETURN NULL;
		END
		$$;
		CREATE TRIGGER journal_statement_probe AFTER INSERT ON kaname.fga_outbox
			FOR EACH STATEMENT EXECUTE FUNCTION public.journal_statement_probe_count();`)
	require.NoError(t, err, "счётчик операторов журнала не встал в базу пробы")
	return &Probe{pool: pool}
}

// Reset забывает сосчитанное: предмет пробы — транзакции после него.
func (p *Probe) Reset(t testing.TB, ctx context.Context) {
	t.Helper()
	_, err := p.pool.Exec(ctx, `TRUNCATE public.journal_statement_probe`)
	require.NoError(t, err)
}

// Census — перепись после Reset: сколько транзакций писали журнал, сколько
// операторов положила самая многословная из них, сколько операторов всего.
type Census struct {
	Transactions int
	MaxPerTx     int
	Statements   int
}

// Count читает перепись.
func (p *Probe) Count(t testing.TB, ctx context.Context) Census {
	t.Helper()
	var c Census
	require.NoError(t, p.pool.QueryRow(ctx, `
		SELECT count(*), coalesce(max(n), 0), coalesce(sum(n), 0)::bigint
		  FROM (SELECT count(*) AS n FROM public.journal_statement_probe GROUP BY xid) s`).
		Scan(&c.Transactions, &c.MaxPerTx, &c.Statements))
	return c
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_owner_links_are_immutable_concurrent_integration_test.go — неизменяемость
// `accounts.owner_user_id` и `projects.account_id` держится и под параллельной
// правкой той же строки (задача PRO-Robotech/kaname#484, замысел
// `docs/changes/issue-2924/design.md` репозитория PRO-Robotech/kacho-workspace,
// З23 п. 4).
//
// # Что именно может обойти триггер
//
// Отказ судится по паре OLD/NEW строки. Под READ COMMITTED второй писатель той
// же строки ждёт замка первого и после его фиксации перечитывает строку
// (перепроверка условия оператора на новой версии). Если бы суждение шло по
// снимку, взятому ДО ожидания, смена, пришедшая вслед за законной правкой,
// сравнивалась бы с устаревшей строкой. Поэтому здесь два вида доказательства:
//
//   - управляемый порядок: первая транзакция правит `name` и держит замок,
//     вторая пытается сменить связь и ждёт; после фиксации первой вторая
//     получает `23514`, а правка первой остаётся;
//   - шторм: N горутин одновременно правят `name` и пытаются сменить связь;
//     каждая смена — `23514`, каждая правка — проходит, связь в итоге прежняя.
//
// Положительный близнец каждого отказа — правка `name` той же строки в том же
// шторме: отличается ровно одним фактом (колонка связи не меняется).
package migrations_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// stormWriters — число горутин шторма на каждую сторону (смена связи и
// законная правка). Больше одного на сторону — чтобы писатели одной строки
// реально вставали в очередь за замком.
const stormWriters = 8

// linkCase описывает одну неизменяемую связь: таблицу, колонку, строку,
// законное прежнее значение и законное (существующее) новое значение — чтобы
// отказ не мог прийти от внешнего ключа.
type linkCase struct {
	table, column, rowID, keep, change string
}

func scopeOwnerLinkCases() []linkCase {
	return []linkCase{
		{table: "kaname.accounts", column: "owner_user_id", rowID: immAccA, keep: immUser1, change: immUser2},
		{table: "kaname.projects", column: "account_id", rowID: immProjID, keep: immAccA, change: immAccB},
	}
}

// TestIntegration_ScopeOwnerLinkChangeWaitingBehindARenameIsRefused —
// смена связи, ждущая замка строки за законной правкой, после фиксации правки
// отвергается `23514`; правка остаётся.
func TestIntegration_ScopeOwnerLinkChangeWaitingBehindARenameIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	seedScopeOwnerLinks(t, db)

	for _, c := range scopeOwnerLinkCases() {
		t.Run(c.column, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			holder, err := db.BeginTx(ctx, nil)
			require.NoError(t, err)
			defer func() { _ = holder.Rollback() }()
			renamed := "renamed-" + c.rowID
			res, err := holder.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET name = $1 WHERE id = $2`, c.table), renamed, c.rowID)
			require.NoError(t, err, "законная правка держателя замка отвергнута")
			n, _ := res.RowsAffected()
			require.EqualValues(t, 1, n, "держатель не взял строку — порядок не управляется")

			// Смена связи уходит в отдельное соединение и обязана ЖДАТЬ замка.
			changeErr := make(chan error, 1)
			go func() {
				_, err := db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET %s = $1 WHERE id = $2`, c.table, c.column), c.change, c.rowID)
				changeErr <- err
			}()
			waitForRowLockWaiter(ctx, t, db, c.table)

			require.NoError(t, holder.Commit(), "фиксация законной правки")
			select {
			case err := <-changeErr:
				requireCheckViolation(t, err, c.column)
			case <-ctx.Done():
				t.Fatalf("смена %s не завершилась после фиксации держателя", c.column)
			}

			var link, name string
			require.NoError(t, db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s, name FROM %s WHERE id = $1`, c.column, c.table), c.rowID).Scan(&link, &name))
			require.Equal(t, c.keep, link, "смена, ждавшая замка, прошла мимо триггера")
			require.Equal(t, renamed, name, "законная правка держателя потеряна")
		})
	}
}

// waitForRowLockWaiter ждёт, пока в базе появится сессия, ожидающая замка при
// правке таблицы. Без этого «управляемый порядок» вырождается в
// последовательный и ничего не доказывает.
func waitForRowLockWaiter(ctx context.Context, t *testing.T, db *sql.DB, table string) {
	t.Helper()
	for {
		var waiters int
		require.NoError(t, db.QueryRowContext(ctx, `
			SELECT count(*) FROM pg_stat_activity
			 WHERE wait_event_type = 'Lock'
			   AND state = 'active'
			   AND query ILIKE 'UPDATE ' || $1 || ' SET %'`, table).Scan(&waiters))
		if waiters > 0 {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("смена связи в %s так и не встала в ожидание замка", table)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

// TestIntegration_ScopeOwnerLinkStormKeepsTheLink — N параллельных попыток
// сменить связь вперемешку с N законными правками той же строки: каждая смена
// отвергнута `23514`, каждая правка прошла, связь прежняя.
func TestIntegration_ScopeOwnerLinkStormKeepsTheLink(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)
	db.SetMaxOpenConns(2*stormWriters + 2)
	seedScopeOwnerLinks(t, db)

	for _, c := range scopeOwnerLinkCases() {
		t.Run(c.column, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			start := make(chan struct{})
			changeErrs := make([]error, stormWriters)
			renameErrs := make([]error, stormWriters)
			var wg sync.WaitGroup
			for i := 0; i < stormWriters; i++ {
				wg.Add(2)
				go func(i int) {
					defer wg.Done()
					<-start
					_, changeErrs[i] = db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET %s = $1, name = $2 WHERE id = $3`, c.table, c.column),
						c.change, fmt.Sprintf("storm-change-%d", i), c.rowID)
				}(i)
				go func(i int) {
					defer wg.Done()
					<-start
					_, renameErrs[i] = db.ExecContext(ctx, fmt.Sprintf(`UPDATE %s SET name = $1 WHERE id = $2`, c.table),
						fmt.Sprintf("storm-rename-%d", i), c.rowID)
				}(i)
			}
			close(start)
			wg.Wait()

			for i := 0; i < stormWriters; i++ {
				requireCheckViolation(t, changeErrs[i], c.column)
				var pgErr *pgconn.PgError
				if renameErrs[i] != nil && errors.As(renameErrs[i], &pgErr) {
					t.Fatalf("законная правка %d отвергнута базой классом %s: %v", i, pgErr.Code, renameErrs[i])
				}
				require.NoErrorf(t, renameErrs[i], "законная правка %d не прошла", i)
			}

			var link, name string
			require.NoError(t, db.QueryRowContext(ctx, fmt.Sprintf(`SELECT %s, name FROM %s WHERE id = $1`, c.column, c.table), c.rowID).Scan(&link, &name))
			require.Equal(t, c.keep, link, "шторм сменил связь: неизменяемость под параллельной правкой не держится")
			require.Regexp(t, `^storm-rename-\d+$`, name, "итоговое имя — не от законной правки: отвергнутая смена оставила след")
		})
	}
}

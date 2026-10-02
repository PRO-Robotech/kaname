// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package personmarks — ЕДИНСТВЕННОЕ чтение отметки подтверждения адреса для
// предиката допуска (задача PRO-Robotech/kaname#456; приёмка
// `docs/engineering/acceptance/access-beyond-login-needs-a-verified-address.md`,
// Р1, Р4, §8 инв. 4).
//
// Предикат допуска один (`internal/admission`), и спрашивает он хранилище
// отметок ОДНИМ оператором: какие из названных идентификаторов — строки людей
// и подтверждён ли их ТЕКУЩИЙ адрес. Дверь решения, правило выдачи, правило
// предъявления и рубеж слушателей подают сюда свой читатель поверх своего
// соединения, а текст оператора один: второй его текст разошёлся бы с первым
// молча, и неверной была бы их разница.
//
// Вид принципала отсюда и выводится — строкой людей, а не утверждением токена
// или заголовком: идентификатор, которому строки человека нет, в ответе
// отсутствует. Кэша нет намеренно (Р1): снятие отметки и подтверждение
// действуют на следующем вопросе.
package personmarks

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// marksSQL — строки людей среди названных идентификаторов и их отметка.
const marksSQL = `
	SELECT id, (email_verified_at IS NOT NULL) AS verified
	  FROM kaname.users
	 WHERE id = ANY ($1::text[])`

// Querier — соединение, на котором читается оператор: пул либо транзакция
// вызывающего.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// Read — ответ оператора: идентификатор строки человека → подтверждён ли её
// текущий адрес. Ошибка — «спросить не смогли»: третий исход, а не «подтверждён».
func Read(ctx context.Context, q Querier, ids []string) (map[string]bool, error) {
	out := make(map[string]bool, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, marksSQL, ids)
	if err != nil {
		return nil, fmt.Errorf("personmarks: address marks of %d ids: %w", len(ids), err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id       string
			verified bool
		)
		if err := rows.Scan(&id, &verified); err != nil {
			return nil, fmt.Errorf("personmarks: scan: %w", err)
		}
		out[id] = verified
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("personmarks: rows: %w", err)
	}
	return out, nil
}

// Reader — читатель отметок на пуле; реализует `admission.Marks`.
type Reader struct{ pool *pgxpool.Pool }

// New — читатель поверх пула. nil-пул — читатель, отвечающий ошибкой на каждый
// вопрос: «не провязан» не становится «подтверждён».
func New(pool *pgxpool.Pool) *Reader { return &Reader{pool: pool} }

// PersonMarks — см. `admission.Marks`.
func (r *Reader) PersonMarks(ctx context.Context, ids []string) (map[string]bool, error) {
	if r == nil || r.pool == nil {
		return nil, fmt.Errorf("personmarks: reader has no pool")
	}
	return Read(ctx, r.pool, ids)
}

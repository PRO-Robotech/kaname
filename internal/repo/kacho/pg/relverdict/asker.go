// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// asker.go — форма E под порт теневого сравнения.
//
// # Почему отдельный тип, а не метод на пуле
//
// Сравнителю нужен ровно один вопрос, и порт у него узкий. Пул умеет много —
// отдать его целиком значило бы дать сравнению доступ к тому, чего его предмет
// не требует, и следующая правка легко превратила бы теневой путь в пишущий.
//
// # Почему СВОЯ транзакция только на чтение
//
// Вердикт складывается из нескольких источников, и читать их обязано ОДНО
// состояние базы: без общей транзакции запрос мог бы увидеть выдачу до отзыва и
// цепь после переноса, то есть сравнить движок с состоянием, которого не было
// ни в один момент. Транзакция только читает и всегда откатывается.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Asker — форма E как источник теневого вердикта.
type Asker struct{ pool *pgxpool.Pool }

// NewAsker собирает источник. nil-пул — законный вход: сравнение тогда не
// включается вовсе, а не отвечает молча «нет».
func NewAsker(pool *pgxpool.Pool) *Asker {
	if pool == nil {
		return nil
	}
	return &Asker{pool: pool}
}

// Allowed отвечает на прямой вопрос.
//
// Возвращает ОШИБКУ, а не false, когда ответа получить не удалось: сравнитель
// обязан отличить «форма сказала нет» от «форма не ответила», иначе недоступная
// БД читалась бы как поток расхождений либо как согласие — в зависимости от
// вердикта движка, то есть случайно.
func (a *Asker) Allowed(ctx context.Context, subject, objectType, objectID, verb string) (bool, error) {
	if a == nil || a.pool == nil {
		return false, fmt.Errorf("relverdict: источник не собран")
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := Ask(ctx, tx, Query{
		Subject: subject, ObjectType: objectType, ObjectID: objectID, Verb: verb,
	})
	if err != nil {
		return false, err
	}
	switch v {
	case Allow:
		return true, nil
	case Deny:
		return false, nil
	default:
		// Unknown — не «нет». Отдаём ошибкой, чтобы сравнение положило исход в
		// свою корзину «не выполнилось», а не в расхождение.
		return false, fmt.Errorf("relverdict: вердикт не определён (%s)", v)
	}
}

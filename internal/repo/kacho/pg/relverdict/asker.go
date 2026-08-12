// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// asker.go — форма E под порт теневого сравнения.
//
// # Почему отдельный тип, а не метод на пуле
//
// Сравнителю нужны ровно те вопросы, которые форма E умеет отвечать, и порт у
// него узкий. Пул умеет много — отдать его целиком значило бы дать сравнению
// доступ к тому, чего его предмет не требует, и следующая правка легко
// превратила бы теневой путь в пишущий.
//
// # Почему адаптер несёт ВСЕ четыре вопроса, а не один
//
// Форма E отвечает четырьмя запросами — прямой вердикт, перечисление объектов,
// перечисление субъектов, разворот оснований, — и все четыре разложены одной и
// той же раскладкой модели. Адаптер, несущий один из них, оставляет остальные
// три без спрашивающего: сама способность ответить остаётся, а сходимость
// меряется по одному вопросу и объявляется свойством формы целиком.
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
func (a *Asker) Allowed(ctx context.Context, subject, objectType, objectID, relation string, condCtx map[string]any) (bool, error) {
	if a == nil || a.pool == nil {
		return false, fmt.Errorf("relverdict: источник не собран")
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	v, err := Ask(ctx, tx, Query{
		Subject: subject, ObjectType: objectType, ObjectID: objectID, Relation: relation,
		Context: condCtx,
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

// Objects — какие объекты этого типа доступны субъекту.
//
// relations — НАБОР: движок отвечает на читающее действие объединением двух
// отношений (`viewer` ∪ `v_list`), и спросить форму об одном из них значило бы
// сравнить два разных вопроса и записать расхождение там, где спрашивали не то же
// самое. Объединение делается здесь, в одной транзакции: два снимка базы дали бы
// множество, которого не было ни в один момент.
//
// complete=false означает «ответ не помещается в limit» — у сравнения на это своя
// корзина, и выдавать усечённый ответ за полный оно не станет.
func (a *Asker) Objects(ctx context.Context, subject, objectType string, relations []string, limit int) ([]string, bool, error) {
	if a == nil || a.pool == nil {
		return nil, false, fmt.Errorf("relverdict: источник не собран")
	}
	if len(relations) == 0 {
		return nil, false, fmt.Errorf("relverdict: перечисление без отношения — пустой ответ "+
			"за него неотличим от честного «ничего не доступно» (субъект %q, тип %q)", subject, objectType)
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, false, fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	seen := make(map[string]struct{}, limit)
	out := make([]string, 0, limit)
	for _, rel := range relations {
		ids, next, err := List(ctx, tx, ListQuery{
			Subject: subject, ObjectType: objectType, Relation: rel, Limit: limit,
		})
		if err != nil {
			return nil, false, err
		}
		for _, id := range ids {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
		// Курсор непуст — страница полна и продолжение есть: ответ не помещается.
		// Проверяется ПО КАЖДОМУ отношению: объединение двух усечённых страниц
		// длиной обмануло бы проверку на слитом множестве.
		if next != "" {
			return out, false, nil
		}
	}
	return out, true, nil
}

// Subjects — кто имеет это отношение на этом объекте.
func (a *Asker) Subjects(ctx context.Context, objectType, objectID, relation string, limit int) ([]string, bool, error) {
	if a == nil || a.pool == nil {
		return nil, false, fmt.Errorf("relverdict: источник не собран")
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, false, fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	subjects, next, err := Subjects(ctx, tx, SubjectsQuery{
		ObjectType: objectType, ObjectID: objectID, Relation: relation, Limit: limit,
	})
	if err != nil {
		return nil, false, err
	}
	return subjects, next == "", nil
}

// Sources — кого называют основания права на объекте.
//
// Отдаёт СУБЪЕКТОВ, а не сами основания: форма ответа у двух сторон разная — у
// движка дерево наборов, у формы E плоский перечень с носителем и ветвью, — и
// сверять их поэлементно значило бы объявлять расхождением разную форму записи.
// Одинаково обе стороны называют одно: кто в итоге получает право.
func (a *Asker) Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error) {
	if a == nil || a.pool == nil {
		return nil, fmt.Errorf("relverdict: источник не собран")
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	sources, err := Expand(ctx, tx, objectType, objectID, relation)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(sources))
	out := make([]string, 0, len(sources))
	for _, s := range sources {
		if _, ok := seen[s.Subject]; ok {
			continue
		}
		seen[s.Subject] = struct{}{}
		out = append(out, s.Subject)
	}
	return out, nil
}

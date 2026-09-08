// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// asker_gate.go — два вопроса, которые до снятия внешнего движка задавались ЕМУ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОНИ ЗДЕСЬ, А НЕ У ДВЕРИ РЕШЕНИЯ
//
// Оба отвечаются ОДНОЙ читающей транзакцией той же базы, что и прямой вердикт, и
// тем же планом модели. Дверь решения (`internal/authzcascade`) обязана остаться
// переходником: перенеси разбор туда — и рядом с планом появится второе место,
// которое знает про таблицы, а расходятся такие места молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО У НИХ РАЗНОГО С СОСЕДЯМИ ВЫШЕ
//
// `Subjects` (asker.go) отвечает ПОЛНОТОЙ («поместилось ли в предел»), потому что
// сравнителю нужно было отличить усечённый ответ от полного. Публичному
// перечислению нужен КУРСОР — иначе страница без продолжения повторяет ровно ту
// беду, ради которой снято перечисление объектов: остаток недостижим при живых
// правах. Поэтому здесь отдаётся `nextAfter`, а не признак усечения.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SubjectsPage — страница субъектов, держащих отношение на объекте, С КУРСОРОМ.
//
// afterID пуст на первой странице; возвращённый nextAfter пуст, когда страница
// последняя. Курсор — идентификатор субъекта, по которому идёт порядок обхода:
// он монотонен и не зависит ни от времени, ни от того, что изменилось между
// страницами, поэтому продолжение не пропускает и не удваивает строки.
func (a *Asker) SubjectsPage(
	ctx context.Context, objectType, objectID, relation, afterID string, limit int,
) (subjects []string, nextAfter string, err error) {
	if a == nil || a.pool == nil {
		return nil, "", fmt.Errorf("relverdict: источник не собран")
	}
	tx, err := a.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, "", fmt.Errorf("relverdict: транзакция чтения: %w", err)
	}
	defer func() { _ = rollback(ctx, tx) }()

	return Subjects(ctx, tx, SubjectsQuery{
		ObjectType: objectType, ObjectID: objectID, Relation: relation,
		AfterID: afterID, Limit: limit,
	})
}

// DirectRelations — какие отношения субъект уже держит НА ЭТОМ объекте.
//
// # Зачем это нужно и почему ответ узкий
//
// Единственный читатель — текст отказа («не хватает `editor`; сейчас есть
// [`viewer`]»). Вопрос диагностический: он обязан назвать то, что вызывающий
// может увидеть в своих правах, а не восстановить весь вывод модели. Поэтому
// читаются ПРЯМЫЕ факты объекта — те же строки, из которых прямой вердикт
// собирает безусловное основание, — и ничего сверх них.
//
// Раньше на этот вопрос отвечало чтение хранилища кортежей у движка. Читатель тот
// же, единица та же (имя отношения), источник — своя таблица.
//
// # Ошибка НЕ поднимается вызывающему
//
// Диагностика не вправе испортить ответ: не прочитали — текст отказа обходится
// без хвоста, ровно как обходился, когда хранилище кортежей не отвечало.
func (a *Asker) DirectRelations(
	ctx context.Context, subject, objectType, objectID string, limit int,
) ([]string, error) {
	if a == nil || a.pool == nil {
		return nil, fmt.Errorf("relverdict: источник не собран")
	}
	if subject == "" || objectType == "" || objectID == "" {
		return nil, nil
	}
	if limit <= 0 {
		limit = 16
	}
	rows, err := a.pool.Query(ctx, `
		SELECT DISTINCT f.relation
		  FROM kaname.relation_fact f
		 WHERE f.object_type = $1
		   AND f.object_id   = $2
		   AND f.subject     = $3
		 ORDER BY f.relation
		 LIMIT $4`, objectType, objectID, subject, limit)
	if err != nil {
		return nil, fmt.Errorf("relverdict: прямые отношения субъекта: %w", err)
	}
	defer rows.Close()

	out := make([]string, 0, limit)
	for rows.Next() {
		var rel string
		if serr := rows.Scan(&rel); serr != nil {
			return nil, fmt.Errorf("relverdict: разбор прямого отношения: %w", serr)
		}
		out = append(out, rel)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("relverdict: чтение прямых отношений: %w", rerr)
	}
	return out, nil
}

// DirectRelationsMany — те же прямые отношения субъекта, но о СТРАНИЦЕ объектов
// одного типа, ОДНИМ запросом.
//
// # Зачем отдельный метод, а не цикл по DirectRelations
//
// Хвост текста отказа платится на КАЖДОМ отказанном объекте, а страница списка
// отказами и состоит — она ими сужается. Цикл вернул бы стоимость набора ровно
// туда, откуда её убрал страничный вердикт: партия из ста отказов стоила бы ста
// запросов диагностики при одном запросе на сам вердикт.
//
// # Предел — НА ОБЪЕКТ, и он держится запросом, а не отбором в памяти
//
// Диагностике нужен намёк, а не полный разбор, поэтому у каждого объекта не
// более `limit` отношений. Считает это сама база (нумерация внутри объекта),
// иначе запрос вернул бы все отношения всех объектов и обрезался бы после
// чтения — то есть предел ограничивал бы длину ответа, но не работу.
//
// Ключа у объекта без прямых отношений в ответе нет: пустой срез и отсутствие
// ключа означают для вызывающего одно и то же — «хвоста не будет».
func (a *Asker) DirectRelationsMany(
	ctx context.Context, subject, objectType string, objectIDs []string, limit int,
) (map[string][]string, error) {
	if a == nil || a.pool == nil {
		return nil, fmt.Errorf("relverdict: источник не собран")
	}
	if subject == "" || objectType == "" || len(objectIDs) == 0 {
		return nil, nil
	}
	if limit <= 0 {
		limit = 16
	}
	rows, err := a.pool.Query(ctx, `
		SELECT r.object_id, r.relation
		  FROM (
		    SELECT d.object_id, d.relation,
		           row_number() OVER (PARTITION BY d.object_id ORDER BY d.relation) AS rn
		      FROM (
		        SELECT DISTINCT f.object_id, f.relation
		          FROM kaname.relation_fact f
		         WHERE f.object_type = $1
		           AND f.object_id = ANY ($2::text[])
		           AND f.subject   = $3
		      ) d
		  ) r
		 WHERE r.rn <= $4::int
		 ORDER BY r.object_id, r.rn`, objectType, objectIDs, subject, limit)
	if err != nil {
		return nil, fmt.Errorf("relverdict: прямые отношения субъекта на странице: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]string, len(objectIDs))
	for rows.Next() {
		var objectID, rel string
		if serr := rows.Scan(&objectID, &rel); serr != nil {
			return nil, fmt.Errorf("relverdict: разбор прямого отношения страницы: %w", serr)
		}
		out[objectID] = append(out[objectID], rel)
	}
	if rerr := rows.Err(); rerr != nil {
		return nil, fmt.Errorf("relverdict: чтение прямых отношений страницы: %w", rerr)
	}
	return out, nil
}

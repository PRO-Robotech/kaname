// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// list.go — перечисление объектов, доступных субъекту, СТРАНИЦЕЙ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО ЧИНИТ
//
// У движка перечисление имеет ЖЁСТКИЙ серверный предел и не имеет продолжения:
// запрос вообще не несёт поля страницы, поэтому «лимит» на стороне клиента —
// лишь обрезка уже усечённого ответа. Следствие наблюдалось вживую: ресурсы
// сверх предела становились владельцу НЕВИДИМЫ навсегда при живых правах, а
// предел был общим на тип, а не по-арендаторным — то есть величиной, на которую
// в многоарендной системе закладываться нельзя вовсе.
//
// Здесь предела нет by construction: это наш запрос к нашей таблице, и страница
// делается курсором так же, как везде. Контракт RPC уже несёт
// `next_page_token` — движок его просто не мог заполнить.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ КУРСОР ПО ИДЕНТИФИКАТОРУ, А НЕ СМЕЩЕНИЕ
//
// Смещение теряет строки при вставке между страницами и повторяет при удалении.
// Курсор по возрастающему идентификатору не пропускает ни одной строки, которая
// существовала весь обход, — та же дисциплина, что у списочных RPC продукта.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// ListQuery — вопрос «какие объекты этого типа доступны субъекту».
type ListQuery struct {
	Subject    string
	ObjectType string
	Verb       string
	// AfterID — курсор: строго больший идентификатор. Пусто — первая страница.
	AfterID string
	// Limit — размер страницы. Ноль → DefaultPageSize.
	Limit int
}

// DefaultPageSize — размер страницы по умолчанию.
//
// Величина здесь не «сколько влезет», а «сколько отдать за один вопрос»:
// страница обязана быть достаточно мелкой, чтобы её стоимость принадлежала
// запросу, и достаточно крупной, чтобы обход не превращался в тысячу вызовов.
const DefaultPageSize = 500

// listSQL — та же логика источников, что у вердикта, но перечислением.
//
// Читается так же: цепь областей КАЖДОГО объекта-кандидата, субъекты, за которых
// говорит вызывающий, затем источники права. Отличие одно и оно принципиально:
// кандидаты берутся из ЗЕРКАЛА этого типа, то есть из своей таблицы, а не из
// ответа чужого хранилища с его пределом.
//
// $1 subject · $2 object_type · $3 verb · $4 after_id · $5 limit · $6 max_depth
const listSQL = `
WITH RECURSIVE speaker(subject) AS (
    SELECT $1::text
  UNION
    SELECT 'group:' || gm.group_id
      FROM kacho_iam.group_members gm
     WHERE gm.member_type || ':' || gm.member_id = $1::text
  UNION
    SELECT 'user:*'
),
candidate(object_id) AS (
    SELECT m.object_id
      FROM kacho_iam.resource_mirror m
     WHERE m.object_type = $2::text
       AND m.object_id > $4::text
),
scope(object_id, s_type, s_id, depth) AS (
    SELECT c.object_id, $2::text, c.object_id, 0 FROM candidate c
  UNION
    SELECT s.object_id, e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $6::int
)
SELECT c.object_id
  FROM candidate c
 WHERE EXISTS (
        SELECT 1
          FROM kacho_iam.relation_fact f
          JOIN speaker sp ON sp.subject = f.subject
         WHERE f.object_type = $2::text AND f.object_id = c.object_id
           AND f.relation = $3::text
       )
    OR EXISTS (
        SELECT 1
          FROM kacho_iam.access_bindings b
          JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
          JOIN speaker sp ON sp.subject = bs.subject_type || ':' || bs.subject_id
          JOIN kacho_iam.role_verb rv
            ON rv.role_id = b.role_id AND rv.object_type = $2::text AND rv.verb = $3::text
          JOIN kacho_iam.role_rule_selectors rs
            ON rs.role_id = b.role_id AND $2::text = ANY (rs.object_types)
          JOIN scope sc
            ON sc.object_id = c.object_id
           AND sc.s_type = b.resource_type AND sc.s_id = b.resource_id
          LEFT JOIN kacho_iam.resource_mirror m
            ON m.object_type = $2::text AND m.object_id = c.object_id
         WHERE b.status = 'ACTIVE'
           AND (b.expires_at IS NULL OR b.expires_at > now())
           AND b.revoked_at IS NULL
           AND (
                 rs.arm = 'anchor'
              OR (rs.arm = 'names'  AND c.object_id = ANY (rs.resource_names))
              OR (rs.arm = 'labels' AND m.labels IS NOT NULL
                                    AND m.labels @> rs.match_labels)
           )
       )
 ORDER BY c.object_id
 LIMIT $5::int`

// List отдаёт страницу доступных объектов и курсор следующей.
//
// Курсор пуст, когда страница неполна: это признак конца обхода, а не
// отдельный запрос «есть ли ещё». Лишний запрос стоил бы столько же, сколько
// сама страница, и на последней странице — всегда впустую.
func List(ctx context.Context, q pgx.Tx, in ListQuery) (ids []string, nextAfterID string, err error) {
	if in.Subject == "" || in.ObjectType == "" || in.Verb == "" {
		return nil, "", fmt.Errorf("relverdict: неполный вопрос перечисления %+v — пустая "+
			"часть делает ответ бессмысленным, а пустой список за него неотличим от "+
			"честного «ничего не доступно»", in)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultPageSize
	}

	rows, err := q.Query(ctx, listSQL,
		in.Subject, in.ObjectType, in.Verb, in.AfterID, limit, MaxAncestorDepth)
	if err != nil {
		return nil, "", fmt.Errorf("relverdict: перечисление: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, "", fmt.Errorf("relverdict: чтение строки: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("relverdict: обход: %w", err)
	}
	if len(ids) == limit {
		nextAfterID = ids[len(ids)-1]
	}
	return ids, nextAfterID, nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// expand.go — из чего складывается право на объекте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ОТДЕЛЬНЫЙ ВОПРОС, ЕСЛИ ЕСТЬ ПЕРЕЧИСЛЕНИЕ СУБЪЕКТОВ
//
// Перечисление отвечает КТО. Этот вопрос отвечает ПОЧЕМУ — и без него ответ «да»
// неразбираем: администратор видит, что доступ есть, и не видит, какую строку
// снять, чтобы его не стало. Именно поэтому ветвь называется вместе с областью,
// на которой сделана выдача: одно и то же право нередко приходит с двух сторон
// сразу, и снятие одной ничего не меняет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО НЕ ДЕЛАЕТ
//
// Не строит дерево произвольной формы. Источников ровно четыре, и каждый —
// плоская запись: факт, выдача (с ветвью правила), членство. Дерево здесь было
// бы формой без содержания: у него не бывает глубины, которой неоткуда взяться.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Source — одно основание права.
type Source struct {
	// Kind — «fact» | «binding» | «group».
	Kind string
	// Subject — кому основание даёт право.
	Subject string
	// Detail — что именно: для выдачи это её идентификатор и ветвь правила, для
	// членства — группа, для факта — отношение.
	Detail string
	// ScopeType/ScopeID — область, на которой сделана выдача. Пусто у факта.
	ScopeType string
	ScopeID   string
}

// expandSQL — перечисляет ОСНОВАНИЯ, а не субъектов.
//
// $1 object_type · $2 object_id · $3 verb · $4 max_depth
const expandSQL = `
WITH RECURSIVE scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $4::int
)
SELECT 'fact'::text, f.subject, f.relation, ''::text, ''::text
  FROM kacho_iam.relation_fact f
 WHERE f.object_type = $1::text AND f.object_id = $2::text AND f.relation = $3::text
UNION ALL
SELECT 'binding'::text,
       bs.subject_type || ':' || bs.subject_id,
       b.id || ' (' || rs.arm || ')',
       b.resource_type, b.resource_id
  FROM kacho_iam.access_bindings b
  JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
  JOIN kacho_iam.role_verb rv
    ON rv.role_id = b.role_id AND rv.object_type = $1::text AND rv.verb = $3::text
  JOIN kacho_iam.role_rule_selectors rs
    ON rs.role_id = b.role_id AND $1::text = ANY (rs.object_types)
  JOIN scope sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
  LEFT JOIN kacho_iam.resource_mirror m
    ON m.object_type = $1::text AND m.object_id = $2::text
 WHERE b.status = 'ACTIVE'
   AND (b.expires_at IS NULL OR b.expires_at > now())
   AND b.revoked_at IS NULL
   AND (
         rs.arm = 'anchor'
      OR (rs.arm = 'names'  AND $2::text = ANY (rs.resource_names))
      OR (rs.arm = 'labels' AND m.labels IS NOT NULL AND m.labels @> rs.match_labels)
   )
UNION ALL
SELECT 'group'::text,
       gm.member_type || ':' || gm.member_id,
       'через group:' || gm.group_id,
       b.resource_type, b.resource_id
  FROM kacho_iam.access_bindings b
  JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
  JOIN kacho_iam.group_members gm ON gm.group_id = bs.subject_id
  JOIN kacho_iam.role_verb rv
    ON rv.role_id = b.role_id AND rv.object_type = $1::text AND rv.verb = $3::text
  JOIN kacho_iam.role_rule_selectors rs
    ON rs.role_id = b.role_id AND $1::text = ANY (rs.object_types)
  JOIN scope sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
 WHERE bs.subject_type = 'group'
   AND b.status = 'ACTIVE'
   AND (b.expires_at IS NULL OR b.expires_at > now())
   AND b.revoked_at IS NULL
   AND rs.arm = 'anchor'
 ORDER BY 1, 2, 3`

// Expand перечисляет основания права на объекте.
func Expand(ctx context.Context, q pgx.Tx, objectType, objectID, verb string) ([]Source, error) {
	if objectType == "" || objectID == "" || verb == "" {
		return nil, fmt.Errorf("relverdict: неполный вопрос разбора (%q,%q,%q) — пустой "+
			"список за него неотличим от честного «оснований нет»", objectType, objectID, verb)
	}
	rows, err := q.Query(ctx, expandSQL, objectType, objectID, verb, MaxAncestorDepth)
	if err != nil {
		return nil, fmt.Errorf("relverdict: разбор: %w", err)
	}
	defer rows.Close()
	var out []Source
	for rows.Next() {
		var s Source
		if err := rows.Scan(&s.Kind, &s.Subject, &s.Detail, &s.ScopeType, &s.ScopeID); err != nil {
			return nil, fmt.Errorf("relverdict: чтение основания: %w", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("relverdict: обход оснований: %w", err)
	}
	return out, nil
}

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
	// членства — группа, для факта — отношение (и условие, если запись его несёт).
	Detail string
	// ScopeType/ScopeID — НОСИТЕЛЬ основания: объект, на котором сделана выдача,
	// либо объект, на котором лежит строка факта.
	//
	// У факта это поле раньше пустовало, и пока факт искали только на самом
	// объекте, пустота была честной. С выводом по модели факт лежит и на ПРЕДКЕ —
	// администратор облака держит строку на кластере, — и основание, названное
	// без носителя, отправляет снимать её на самом объекте, где её нет. Вопрос
	// задают именно ради «что снять», поэтому носитель называется всегда.
	ScopeType string
	ScopeID   string
}

// expandSQL — перечисляет ОСНОВАНИЯ, а не субъектов, и раскладывает вопрос тем
// же планом модели, что вердикт.
//
// Прямые основания собираются в `ground`, а членство разворачивается ОДИН раз
// поверх них — как в перечислении субъектов и по той же причине: разворот,
// приписанный к одной ветви, молча теряет остальные. Заодно у членства пропала
// прежняя оговорка «только якорная ветвь правила»: она делала невидимым право
// членов группы, которой выдано по именам или по меткам, — то есть скрывала
// основание ровно там, где оно менее очевидно.
//
// $1 object_type · $2 object_id · $3 max_depth ·
// $4 типы предков атомов-фактов · $5 отношения атомов-фактов · $6 глаголы атомов-выдачи
const expandSQL = `
WITH RECURSIVE scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $3::int
),
fact_atom(parent_type, relation) AS (
    SELECT * FROM unnest($4::text[], $5::text[])
),
ground(kind, subject, detail, scope_type, scope_id) AS (
    -- Факт на объекте ЛИБО на предке названного планом типа. Условие записи
    -- называется рядом с отношением: обратный вопрос его не вычисляет (доводов
    -- запроса у него нет), и промолчать о нём значило бы выдать условное
    -- основание за безусловное.
    SELECT 'fact'::text, f.subject,
           f.relation || CASE WHEN f.condition_name <> ''
                              THEN ' (условие ' || f.condition_name || ')'
                              ELSE '' END,
           sc.s_type, sc.s_id
      FROM kacho_iam.relation_fact f
      JOIN scope sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
      JOIN fact_atom fa
        ON fa.relation = f.relation
       AND CASE WHEN fa.parent_type = ''
                THEN sc.depth = 0
                ELSE fa.parent_type = sc.s_type
           END
  UNION
    SELECT 'binding'::text,
           bs.subject_type || ':' || bs.subject_id,
           b.id || ' (' || rs.arm || ')',
           b.resource_type, b.resource_id
      FROM kacho_iam.access_bindings b
      JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN kacho_iam.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $1::text
       AND rv.verb = ANY ($6::text[])
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
)
SELECT g.kind, g.subject, g.detail, g.scope_type, g.scope_id FROM ground g
UNION
SELECT 'group'::text,
       gm.member_type || ':' || gm.member_id,
       'через ' || g.subject || ' → ' || g.detail,
       g.scope_type, g.scope_id
  FROM ground g
  JOIN kacho_iam.group_members gm ON 'group:' || gm.group_id = g.subject
 ORDER BY 1, 2, 3`

// Expand перечисляет основания права на объекте.
func Expand(ctx context.Context, q pgx.Tx, objectType, objectID, relation string) ([]Source, error) {
	if objectType == "" || objectID == "" || relation == "" {
		return nil, fmt.Errorf("relverdict: неполный вопрос разбора (%q,%q,%q) — пустой "+
			"список за него неотличим от честного «оснований нет»", objectType, objectID, relation)
	}
	factParents, factRelations, bindVerbs, err := sourcesOf(objectType, relation)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, expandSQL, objectType, objectID, MaxAncestorDepth,
		factParents, factRelations, bindVerbs)
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

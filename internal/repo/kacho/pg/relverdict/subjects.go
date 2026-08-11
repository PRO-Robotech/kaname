// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// subjects.go — кто имеет этот глагол на этом объекте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ЗЕРКАЛО ВЕРДИКТА
//
// Вердикт спрашивает про ОДНОГО субъекта и волен опросить его группы по имени.
// Здесь субъект неизвестен, и группы разворачиваются в обратную сторону: выдача,
// сделанная ГРУППЕ, обязана назвать её членов — иначе ответ перечислит группу
// как субъект, а спрашивающий ожидал людей и машины.
//
// Обе формы называются: и сама группа (она действительно субъект выдачи), и её
// члены (они действительно имеют право). Свести их к одному значило бы потерять
// либо адресата выдачи, либо того, кто ею пользуется.

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// SubjectsQuery — вопрос «кто может это над этим объектом».
type SubjectsQuery struct {
	ObjectType string
	ObjectID   string
	Verb       string
	AfterID    string
	Limit      int
}

// subjectsSQL — источники те же, но развёрнутые от объекта к субъектам.
//
// $1 object_type · $2 object_id · $3 verb · $4 after · $5 limit · $6 max_depth
const subjectsSQL = `
WITH RECURSIVE scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $6::int
),
granted(subject) AS (
    -- прямой факт
    SELECT f.subject
      FROM kacho_iam.relation_fact f
     WHERE f.object_type = $1::text AND f.object_id = $2::text
       AND f.relation = $3::text
  UNION
    -- субъект выдачи (в том числе группа: она и есть адресат)
    SELECT bs.subject_type || ':' || bs.subject_id
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
  UNION
    -- ЧЛЕНЫ группы, которой выдано: разворот в обратную сторону
    SELECT gm.member_type || ':' || gm.member_id
      FROM kacho_iam.access_bindings b
      JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN kacho_iam.group_members gm ON gm.group_id = bs.subject_id
      JOIN kacho_iam.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $1::text AND rv.verb = $3::text
      JOIN kacho_iam.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $1::text = ANY (rs.object_types)
      JOIN scope sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
      LEFT JOIN kacho_iam.resource_mirror m
        ON m.object_type = $1::text AND m.object_id = $2::text
     WHERE bs.subject_type = 'group'
       AND b.status = 'ACTIVE'
       AND (b.expires_at IS NULL OR b.expires_at > now())
       AND b.revoked_at IS NULL
       AND (
             rs.arm = 'anchor'
          OR (rs.arm = 'names'  AND $2::text = ANY (rs.resource_names))
          OR (rs.arm = 'labels' AND m.labels IS NOT NULL AND m.labels @> rs.match_labels)
       )
)
SELECT g.subject
  FROM granted g
 WHERE g.subject > $4::text
 ORDER BY g.subject
 LIMIT $5::int`

// Subjects отдаёт страницу субъектов, имеющих глагол на объекте.
func Subjects(ctx context.Context, q pgx.Tx, in SubjectsQuery) (subjects []string, nextAfter string, err error) {
	if in.ObjectType == "" || in.ObjectID == "" || in.Verb == "" {
		return nil, "", fmt.Errorf("relverdict: неполный вопрос о субъектах %+v — пустой "+
			"список за него неотличим от честного «никто не имеет»", in)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultPageSize
	}
	rows, err := q.Query(ctx, subjectsSQL,
		in.ObjectType, in.ObjectID, in.Verb, in.AfterID, limit, MaxAncestorDepth)
	if err != nil {
		return nil, "", fmt.Errorf("relverdict: перечисление субъектов: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, "", fmt.Errorf("relverdict: чтение субъекта: %w", err)
		}
		subjects = append(subjects, s)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("relverdict: обход субъектов: %w", err)
	}
	if len(subjects) == limit {
		nextAfter = subjects[len(subjects)-1]
	}
	return subjects, nextAfter, nil
}

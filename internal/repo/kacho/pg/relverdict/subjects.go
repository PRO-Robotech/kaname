// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict

// subjects.go — кто имеет это отношение на этом объекте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ЗЕРКАЛО ВЕРДИКТА
//
// Вопрос тот же и раскладывается тем же планом модели (`sourcesOf`), но обход
// идёт в другую сторону, и две вещи вердикт делать не обязан.
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
	// Relation — модельное имя отношения, та же единица, что у прямого вопроса
	// (см. `ListQuery.Relation`).
	Relation string
	AfterID  string
	Limit    int
}

// subjectsSQL — источники ПЛАНА, развёрнутые от объекта к субъектам.
//
// Разворот групп сделан ОДИН раз, поверх всех прямых источников сразу, а не
// приписан к каждому. Причина не в краткости: приписанный к одному источнику
// разворот молча теряет остальные — членам группы, которой принадлежит СТРОКА
// ФАКТА (владелец-группа, администратор-группа), право принадлежит ровно так же,
// как членам группы, которой сделана выдача. Один разворот поверх набора не
// может разойтись сам с собой.
//
// $1 object_type · $2 object_id · $3 after · $4 limit · $5 max_depth ·
// $6 типы предков атомов-фактов · $7 отношения атомов-фактов · $8 глаголы атомов-выдачи
const subjectsSQL = `
WITH RECURSIVE scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $5::int
),
fact_atom(parent_type, relation) AS (
    SELECT * FROM unnest($6::text[], $7::text[])
),
named(subject) AS (
    -- (1) прямой факт — на объекте ЛИБО на предке типа, названного планом. Без
    -- второго администратор облака не назвал бы себя: его строка лежит на
    -- кластере под именем system_admin, а спрашивают про глагол.
    SELECT f.subject
      FROM kacho_iam.relation_fact f
      JOIN scope sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
      JOIN fact_atom fa
        ON fa.relation = f.relation
       AND CASE WHEN fa.parent_type = ''
                THEN sc.depth = 0
                ELSE fa.parent_type = sc.s_type
           END
  UNION
    -- (2) субъект выдачи (в том числе группа: она и есть адресат)
    SELECT bs.subject_type || ':' || bs.subject_id
      FROM kacho_iam.access_bindings b
      JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN kacho_iam.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $1::text
       AND rv.verb = ANY ($8::text[])
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
),
granted(subject) AS (
    SELECT n.subject FROM named n
  UNION
    -- ЧЛЕНЫ названной группы: разворот в обратную сторону. Обе формы остаются —
    -- и группа (адресат, который отзывают), и члены (те, кто правом пользуется).
    SELECT gm.member_type || ':' || gm.member_id
      FROM named n
      JOIN kacho_iam.group_members gm ON 'group:' || gm.group_id = n.subject
)
SELECT g.subject
  FROM granted g
 WHERE g.subject > $3::text
 ORDER BY g.subject
 LIMIT $4::int`

// Subjects отдаёт страницу субъектов, имеющих отношение на объекте.
func Subjects(ctx context.Context, q pgx.Tx, in SubjectsQuery) (subjects []string, nextAfter string, err error) {
	if in.ObjectType == "" || in.ObjectID == "" || in.Relation == "" {
		return nil, "", fmt.Errorf("relverdict: неполный вопрос о субъектах %+v — пустой "+
			"список за него неотличим от честного «никто не имеет»", in)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultPageSize
	}
	factParents, factRelations, bindVerbs, err := sourcesOf(in.ObjectType, in.Relation)
	if err != nil {
		return nil, "", err
	}
	rows, err := q.Query(ctx, subjectsSQL,
		in.ObjectType, in.ObjectID, in.AfterID, limit, MaxAncestorDepth,
		factParents, factRelations, bindVerbs)
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

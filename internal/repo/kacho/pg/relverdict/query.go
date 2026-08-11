// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package relverdict — вердикт о доступе запросом к собственному Postgres iam.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО ОТВЕЧАЕТ
//
// Один вопрос: «может ли ЭТОТ субъект сделать ЭТОТ глагол над ЭТИМ объектом».
// Ответ складывается из четырёх источников, и все четыре живут в схеме iam:
//
//  1. ПРЯМОЙ ФАКТ — владение, поставленное при создании, иерархический
//     указатель, подстановочный субъект (`relation_fact`);
//  2. ВЫДАЧА РОЛИ на область — сама область объекта либо любой его предок
//     (`access_bindings` × `role_verb`, цепь из `resource_parent_edge`);
//  3. ВЫДАЧА ПО МЕТКАМ — то же, плюс совпадение меток объекта с селектором
//     (`access_binding_selector` × `resource_mirror.labels`);
//  4. ЧЛЕНСТВО В ГРУППЕ — субъектом выдачи бывает группа (`group_members`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЗАПРОС, А НЕ МАТЕРИАЛИЗАЦИЯ
//
// Материализовать — значит хранить произведение «субъекты × объекты». Выдача по
// меткам делает это произведение комбинаторным по числу ключей меток, а СМЕНА
// ОДНОЙ МЕТКИ заставляет пересчитывать доступ для всех субъектов с меточными
// выдачами. Здесь ничего не хранится: предикат проверяется для ТОГО объекта, о
// котором спросили, поэтому смена метки — один UPDATE, а не пересчёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА ЭТОЙ ФАЗЫ, НАЗВАННАЯ ЯВНО
//
// Отвечает по-прежнему движок. Этот запрос спрашивается РЯДОМ и только
// сравнивается: его ошибка не может дать лишний доступ, потому что решение
// принимает не он. Это и есть безопасное место ошибиться — и единственное, где
// расхождение видно раньше, чем становится инцидентом.
//
// Условие на кортеже (свежесть аутентификации) здесь НЕ вычисляется: оно
// зависит от «сейчас» и приезжает контекстом запроса — отдельная фаза. Пока
// отношение с условием встречено, запрос обязан сказать «не знаю», а не «нет»:
// молчаливое «нет» слилось бы с честным отказом.
package relverdict

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// MaxAncestorDepth — предел обхода цепи предков.
//
// Совпадает с ограничением таблицы рёбер и с пределом компилятора модели. Здесь
// он повторён НЕ как вторая истина, а как страховка обхода: рекурсивный запрос
// без предела на данных с циклом не завершается, и полагаться на то, что цикла
// нет, — значит полагаться на ограничение, которое проверяет другая сторона.
const MaxAncestorDepth = 4

// Verdict — исход вопроса. Три состояния, а не два: «не знаю» отличимо от «нет».
type Verdict int

const (
	// Deny — ни один источник не дал права.
	Deny Verdict = iota
	// Allow — хотя бы один дал.
	Allow
	// Unknown — вопрос затрагивает то, чего эта форма пока не вычисляет
	// (отношение с условием). НЕ «нет»: слить их значило бы объявить отказом то,
	// на что ответа не получено, и расхождение с движком стало бы неотличимо от
	// согласия.
	Unknown
)

func (v Verdict) String() string {
	switch v {
	case Allow:
		return "allow"
	case Deny:
		return "deny"
	case Unknown:
		return "unknown"
	}
	return "invalid"
}

// Query — вопрос к форме E.
type Query struct {
	// Subject — целиком, в форме `"user:usr-1"`: подстановочный и групповой
	// субъекты на пару не раскладываются.
	Subject string
	// ObjectType/ObjectID — объект парой, как его называет вопрос и как он лежит
	// в зеркале.
	ObjectType string
	ObjectID   string
	// Verb — глагол в канонической форме, БЕЗ приставки отношения.
	Verb string
}

// verdictSQL — единственный запрос, отвечающий на вопрос.
//
// Читается сверху вниз: сначала цепь областей объекта (сам объект + предки),
// затем субъекты, за которых говорит вызывающий (он сам, его группы,
// подстановка), затем четыре источника права через OR.
//
// $1 subject · $2 object_type · $3 object_id · $4 verb · $5 max_depth
const verdictSQL = `
WITH RECURSIVE scope(s_type, s_id, depth) AS (
    -- Сам объект — тоже область: выдача, сделанная НА него, действует.
    SELECT $2::text, $3::text, 0
  UNION
    -- Предки по цепи. Предел обхода — параметром, а не «пока не кончится»:
    -- цикл в данных иначе не завершает запрос.
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      JOIN kacho_iam.resource_parent_edge e
        ON e.object_type = s.s_type AND e.object_id = s.s_id
     WHERE s.depth < $5::int
),
speaker(subject) AS (
    -- За вызывающего говорит он сам…
    SELECT $1::text
  UNION
    -- …его группы (членство — источник, а не отдельное право). Член группы
    -- бывает и служебной учётной записью, поэтому сравнение идёт по ПАРЕ
    -- (тип, идентификатор), а не по одному лишь пользователю: сузить до
    -- пользователя значило бы терять права машинных принципалов молча.
    SELECT 'group:' || gm.group_id
      FROM kacho_iam.group_members gm
     WHERE gm.member_type || ':' || gm.member_id = $1::text
  UNION
    -- …и подстановка, если модель её принимает на этом отношении. Она объявлена
    -- НАМЕРЕННО (глобальный справочник читает всякий аутентифицированный), и
    -- потому перечислена здесь явно, а не выведена из формы имени.
    SELECT 'user:*'
)
SELECT EXISTS (
    -- (1) прямой факт
    SELECT 1
      FROM kacho_iam.relation_fact f
      JOIN speaker sp ON sp.subject = f.subject
     WHERE f.object_type = $2::text AND f.object_id = $3::text
       AND f.relation = $4::text
  UNION ALL
    -- (2) выдача роли на область объекта или любого его предка.
    --
    -- Роль адресует объекты ПРАВИЛАМИ, и у правила три ветви: якорь (весь тип в
    -- области), имена (перечисленные идентификаторы), метки (совпадение по
    -- меткам объекта). Ветвь выбирает колонка arm, и разбирать её обязан ЗАПРОС, а не
    -- вызывающий: правило — состояние роли, и вычислять его снаружи значило бы
    -- завести второе место, знающее, что такое «подходит».
    SELECT 1
      FROM kacho_iam.access_bindings b
      JOIN kacho_iam.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN speaker sp ON sp.subject = bs.subject_type || ':' || bs.subject_id
      JOIN kacho_iam.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $2::text AND rv.verb = $4::text
      JOIN kacho_iam.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $2::text = ANY (rs.object_types)
      JOIN scope sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
      -- Зеркало нужно только ветви меток; LEFT, чтобы объект без строки зеркала
      -- не выпадал из ветвей якоря и имён — иначе отсутствие меток читалось бы
      -- как отсутствие права.
      LEFT JOIN kacho_iam.resource_mirror m
        ON m.object_type = $2::text AND m.object_id = $3::text
     WHERE b.status = 'ACTIVE'
       AND (b.expires_at IS NULL OR b.expires_at > now())
       AND b.revoked_at IS NULL
       AND (
             rs.arm = 'anchor'
          OR (rs.arm = 'names'  AND $3::text = ANY (rs.resource_names))
          OR (rs.arm = 'labels' AND m.labels IS NOT NULL
                                AND m.labels @> rs.match_labels)
       )
) AS allowed`

// Ask задаёт вопрос форме E.
//
// Ошибка запроса — это ОШИБКА, а не отказ: вернуть Deny на сбое означало бы
// сказать «прав нет» там, где ответ не получен, и сравнение с движком показало
// бы согласие вместо расхождения. Вызывающий обязан отличать одно от другого.
func Ask(ctx context.Context, q pgx.Tx, in Query) (Verdict, error) {
	if in.Subject == "" || in.ObjectType == "" || in.ObjectID == "" || in.Verb == "" {
		return Unknown, fmt.Errorf("relverdict: неполный вопрос %+v — пустая часть делает "+
			"ответ бессмысленным, и отдавать за него Deny значит выдавать незнание за отказ", in)
	}
	var allowed bool
	if err := q.QueryRow(ctx, verdictSQL,
		in.Subject, in.ObjectType, in.ObjectID, in.Verb, MaxAncestorDepth,
	).Scan(&allowed); err != nil {
		return Unknown, fmt.Errorf("relverdict: запрос: %w", err)
	}
	if allowed {
		return Allow, nil
	}
	return Deny, nil
}

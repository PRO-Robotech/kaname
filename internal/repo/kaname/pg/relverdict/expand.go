// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"strings"

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
// $1 object_type в словаре МОДЕЛИ · $2 object_id · $3 max_depth ·
// $4 типы предков атомов-фактов · $5 отношения атомов-фактов · $6 глаголы атомов-выдачи
// $7 object_type в словаре КАТАЛОГА — им названы `resource_mirror.object_type`,
// `role_verb.object_type` и `role_rule_selectors.object_types`, тогда как вопрос
// приходит словарём модели. Перевод делается ОДИН раз, на входе, и читает ЖИВУЮ
// строку каталога (`catalogTypeName`, catalogtype.go): таблица, порождённая
// сборкой, о типе, заведённом применением манифеста в работающем процессе, не
// знает (kacho#1986). Двух словарей в одном соединении быть не должно —
// соединение по разным написаниям не совпадает НИКОГДА и молча.
const expandSQL = `
WITH RECURSIVE
-- scope — ОБЛАСТИ, на которые может быть сделана действующая выдача: сам объект
-- и вся его цепь предков.
--
-- ОБХОД, А НЕ ОДНО ЧТЕНИЕ, и это не осторожность. Цепь читается представлением
-- resource_scope_edge: оно объединяет рёбра, ПРИСЛАННЫЕ владельцами ресурсов,
-- с двумя звеньями, выводимыми из собственной схемы iam (предок проекта — его
-- аккаунт, предок аккаунта — кластер). Замыканием не является НИ ОДНА из сторон:
-- владельцы шлют короткую цепь (ресурсы vpc, storage и compute — одно звено,
-- реестр — два), выводимые звенья идут по одному. Полный путь до корня
-- собирается ИМЕННО обходом, и снять его значит схлопнуть область до «объект +
-- его непосредственный предок».
--
-- Измерено пробой, сеющей цепь ЧЕРЕЗ ПРОИЗВОДИТЕЛЯ: на одном чтении выдача на
-- аккаунт и факт администратора облака на кластере перестают действовать, а
-- отказ неотличим от честного. Отсюда правило для следующего читателя: прежде
-- чем менять эту форму, докажи полноту замыкания — его не даёт ни схема, ни
-- набор производителей.
--
-- ЦЕНА ОБХОДА ЗАПЛАЧЕНА СОЕДИНЕНИЕМ ВБОК, А НЕ ОБЫЧНЫМ. Рекурсивная ветвь с
-- обычным соединением даёт планировщику право прочитать таблицу рёбер ЦЕЛИКОМ на
-- каждом шаге: измерено 2412 строк за один вердикт при трёх рёбрах у объекта.
-- Соединение вбок с пределом заставляет ходить указателем по ключу. Предел НЕ
-- УСЕКАЕТ и усечь не может: у объекта не бывает больше рёбер, чем глубин (ключ
-- таблицы уникален по глубине), а сама глубина ограничена проверкой схемы тем же
-- числом. Выведенное звено этого равенства не нарушает: представление выводит
-- предка ТОЛЬКО там, где владелец объекта своей цепи не назвал, поэтому строки
-- не складываются.
-- Та же форма и по той же причине стоит на пути перечисления — одна семантика
-- области на обе точки входа.
scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, s.depth + 1
      FROM scope s
      CROSS JOIN LATERAL (
             SELECT pe.parent_type, pe.parent_id
               FROM kaname.resource_scope_edge pe
              WHERE pe.object_type = s.s_type AND pe.object_id = s.s_id
              ORDER BY pe.depth
              LIMIT $3::int
           ) e
     WHERE s.depth < $3::int
),
-- scope_distinct — ОБЛАСТИ БЕЗ ПОВТОРОВ, и это ЕДИНСТВЕННОЕ, что читают армы.
--
-- Обход выше несёт в кортеже ГЛУБИНУ ШАГА, поэтому UNION не схлопывает предка,
-- достигнутого разными путями. Форма цепи, которую пишет производитель для
-- compute и nlb (ownerregister.ParentChain — проект И аккаунт сразу), даёт
-- аккаунт на глубинах 1 и 2, а стоящий над ним кластер — на 2 и 3: шесть строк
-- при четырёх различных областях.
--
-- Каждая лишняя строка УМНОЖАЕТ ОБА АРМА: ветвь выдач соединена с набором
-- CROSS JOIN, ветвь фактов — по паре колонок. Отбор различных над ОТВЕТОМ
-- прячет это в ответе и не трогает СТОИМОСТЬ, а на отказном вопросе короткого
-- замыкания нет, и цена платится целиком. Измерено пробой
-- scopedistinct_integration_test.go: 6 строк при 4 различных областях.
--
-- ОБХОД СОХРАНЯЕТСЯ ЦЕЛИКОМ — снимается только повтор. Это НЕ переход на одно
-- чтение таблицы рёбер: тот переход опровергнут (таблица хранит присланную
-- цепь, а не замыкание), и здесь его нет.
--
-- Наименьшая глубина БЕЗОПАСНА, и это проверяемо: единственное употребление
-- глубины ниже по запросу — дискриминатор якоря sc.depth = 0, а якорь
-- засевается нулём и по построению остаётся минимумом (выведенная строка даёт
-- s.depth + 1 при s.depth не меньше нуля, то есть нуля дать не может).
scope_distinct(s_type, s_id, depth) AS (
    SELECT s_type, s_id, min(depth) FROM scope GROUP BY s_type, s_id
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
      FROM kaname.relation_fact f
      JOIN scope_distinct sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
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
      FROM kaname.access_bindings b
      JOIN kaname.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN kaname.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $7::text
       AND rv.verb = ANY ($6::text[])
      JOIN kaname.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $7::text = ANY (rs.object_types)
      JOIN scope_distinct sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
      -- Метки лежат там, где велит ТИП (labelaxis.go): у чужого ресурса — в
      -- зеркале, у собственного объекта iam — в его таблице.
      {{labels_join}}
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
  FROM ground g{{members_join}}
 ORDER BY 1, 2, 3`

// expandQuerySQL — ГОТОВЫЙ запрос разбора для выбранной оси меток.
//
// Собран отдельной функцией, а не на месте вызова, потому что у собранного
// запроса появляется второй читатель — гейт словарей. Гейт, собирающий запрос
// сам, судил бы СВОЮ сборку: подстановка не того параметра прошла бы мимо него
// ровно потому, что он подставляет свой.
func expandQuerySQL(labelTable string) string {
	sql := strings.Replace(expandSQL, labelsJoinMark,
		labelsJoinPinned(labelTable, "$7", "$2"), 1)
	return strings.Replace(sql, membersJoinMark, membersOfNamedGroups("g.subject"), 1)
}

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
	// Имя типа в словаре КАТАЛОГА — у ЖИВОЙ строки каталога (kacho#1986). Читается
	// ПЕРЕД выбором оси: ось выбирается по этому же имени (kacho#2036), и второго
	// чтения каталога ради неё не заводится.
	catalogType, err := catalogTypeName(ctx, q, objectType)
	if err != nil {
		return nil, err
	}
	// Неназначенная ось меток — ошибка, а не пустой перечень оснований: пустой
	// перечень неотличим от честного «оснований нет» (см. labelAxisOf).
	labelTable, err := labelAxisOf(catalogType, objectType)
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, expandQuerySQL(labelTable), objectType, objectID, MaxAncestorDepth,
		factParents, factRelations, bindVerbs, catalogType)
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

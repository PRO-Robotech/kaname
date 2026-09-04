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
	"strings"

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
// $1 object_type в словаре МОДЕЛИ · $2 object_id · $3 after · $4 limit · $5 max_depth ·
// $6 типы предков атомов-фактов · $7 отношения атомов-фактов · $8 глаголы атомов-выдачи
// $9 object_type в словаре КАТАЛОГА — им названы `resource_mirror.object_type`,
// `role_verb.object_type` и `role_rule_selectors.object_types`, тогда как вопрос
// приходит словарём модели. Перевод делается ОДИН раз, на входе, и читает ЖИВУЮ
// строку каталога (`catalogTypeName`, catalogtype.go): таблица, порождённая
// сборкой, о типе, заведённом применением манифеста в работающем процессе, не
// знает (kacho#1986). Двух словарей в одном соединении быть не должно —
// соединение по разным написаниям не совпадает НИКОГДА и молча.
const subjectsSQL = `
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
               FROM kacho_iam.resource_scope_edge pe
              WHERE pe.object_type = s.s_type AND pe.object_id = s.s_id
              ORDER BY pe.depth
              LIMIT $5::int
           ) e
     WHERE s.depth < $5::int
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
    SELECT * FROM unnest($6::text[], $7::text[])
),
named(subject) AS (
    -- (1) прямой факт — на объекте ЛИБО на предке типа, названного планом. Без
    -- второго администратор облака не назвал бы себя: его строка лежит на
    -- кластере под именем system_admin, а спрашивают про глагол.
    SELECT f.subject
      FROM kacho_iam.relation_fact f
      JOIN scope_distinct sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
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
        ON rv.role_id = b.role_id AND rv.object_type = $9::text
       AND rv.verb = ANY ($8::text[])
      JOIN kacho_iam.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $9::text = ANY (rs.object_types)
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
),
granted(subject) AS (
    SELECT n.subject FROM named n
  UNION
    -- ЧЛЕНЫ названной группы: разворот в обратную сторону. Обе формы остаются —
    -- и группа (адресат, который отзывают), и члены (те, кто правом пользуется).
    SELECT gm.member_type || ':' || gm.member_id
      FROM named n{{members_join}}
)
SELECT g.subject
  FROM granted g
 WHERE g.subject > $3::text
 ORDER BY g.subject
 LIMIT $4::int`

// subjectsQuerySQL — ГОТОВЫЙ запрос перечисления субъектов для выбранной оси
// меток (довод — у expandQuerySQL).
func subjectsQuerySQL(labelTable string) string {
	sql := strings.Replace(subjectsSQL, labelsJoinMark,
		labelsJoinPinned(labelTable, "$9", "$2"), 1)
	return strings.Replace(sql, membersJoinMark, membersOfNamedGroups("n.subject"), 1)
}

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
	// Неназначенная ось меток — ошибка, а не пустой перечень: пустой перечень
	// неотличим от честного «никто не имеет» (см. labelAxisOf).
	labelTable, err := labelAxisOf(in.ObjectType)
	if err != nil {
		return nil, "", err
	}
	// Имя типа в словаре КАТАЛОГА — у ЖИВОЙ строки каталога, а не у таблицы,
	// порождённой сборкой (kacho#1986, catalogtype.go).
	catalogType, err := catalogTypeName(ctx, q, in.ObjectType)
	if err != nil {
		return nil, "", err
	}
	rows, err := q.Query(ctx, subjectsQuerySQL(labelTable),
		in.ObjectType, in.ObjectID, in.AfterID, limit, MaxAncestorDepth,
		factParents, factRelations, bindVerbs, catalogType)
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

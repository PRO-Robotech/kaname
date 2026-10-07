// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// fenced.go — аудитория версии события: «кто может читать объект» с оградой
// токена версии прав `R_E` (приёмка NTF-3, kacho#2918, Р30 «Вопрос с оградой»,
// «Какие строки читает вопрос с оградой»; Д133).
//
// ─────────────────────────────────────────────────────────────────────────────
// ТОТ ЖЕ ВОПРОС, ЧТО У Subjects, — С ТРЕМЯ ОТЛИЧИЯМИ, И КАЖДОЕ НАЗВАНО
//
// Раскладка отношения — тот же план модели (`sourcesOf`), имя типа в словаре
// каталога — та же живая строка каталога (`catalogTypeName`), разворот групп —
// тот же единственный фрагмент (`membersOfNamedGroups`). Паритет на
// бесконечности с `Subjects` держит проба NTF3-181: расхождение допустимо
// только классами, которые Р30 исключает из аудитории.
//
//  1. ОБЛАСТИ — ИЗ ФАКТОВ СОБЫТИЯ, а не из рёбер предков. Цепь областей
//     `Subjects` читает представлением `resource_scope_edge` — объектной
//     стороной, которую пишет применение поколения: к моменту вопроса она может
//     нести более новое поколение объекта (или не нести объекта вовсе — у
//     снятого). Вопрос о версии события судит область этой версии: сам объект,
//     его проект, аккаунт и цепь предков, переданные вызывающим (`facts`), у
//     `UPDATED` — объединённо с фактами поколения `g_E − 1`.
//  2. МЕТКИ — ИЗ ФАКТОВ СОБЫТИЯ, а не из зеркала, по той же причине. Ветвь
//     меток совпадает, если правило покрывает метки поколения `g_E` ЛИБО
//     `g_E − 1` (объединение аудиторий `UPDATED`, NTF3-167).
//  3. ОГРАДА. Каждая исходная строка права — выдача, её субъект, роль, глагол
//     роли, правило роли, членство, прямой кортеж — читается, только если
//     транзакция, последней изменившая право строки (`authz_rev`), видна в
//     снимке `R_E` (`pg_visible_in_snapshot`). Токен — ПОЛНЫЙ снимок: строка,
//     закоммиченная до снятия токена, видна, даже если её номер не ниже
//     нижней границы снимка; строка транзакции, шедшей в момент снятия, не
//     видна, даже если её номер ниже верхней (проба гонки ограды).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИЗ АУДИТОРИИ ИСКЛЮЧЕНО ПОСТРОЕНИЕМ (Р30, Д129 (1), Д133 (3), (4))
//
//   - права уровня кластера: объект `cluster` в область не входит, поэтому ни
//     факт на кластере (`system_admin`), ни выдача на кластер основанием не
//     становятся. Признак `ViaSubscription` (подписчик цели, Р11) — единственный
//     путь, на котором кластер в область входит;
//   - условные права: прямой кортеж с условием (`condition_name <> ''`)
//     основанием не бывает ни при каком признаке — условие невычислимо
//     достоверно на момент события;
//   - подстановочный субъект, сервисные аккаунты, группы как таковые и
//     служебные субъекты: выдача отдаёт только `user:<id>` (члены групп
//     раскрыты).
//
// Объектная сторона — зеркало, рёбра предков и областей, голова объекта — этим
// запросом не читается вовсе; барьер поколения спрашивает голову объекта
// отдельным оператором той же транзакции у вызывающего.

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// FencedSubjectsQuery — вопрос об аудитории версии события.
type FencedSubjectsQuery struct {
	// ObjectType, ObjectID — объект в словаре МОДЕЛИ.
	ObjectType string
	ObjectID   string
	// Relation — модельное имя отношения (у аудитории — `v_get`).
	Relation string
	// AuthzRev — токен версии прав `R_E`: текстовая форма `pg_snapshot`.
	AuthzRev string
	// Scope — области события, кроме самого объекта: `<тип модели>:<id>` (проект,
	// аккаунт и цепь предков обоих поколений). Объект `cluster` здесь
	// игнорируется: кластер входит в область только по ViaSubscription.
	Scope []string
	// LabelsJSON, PreviousLabelsJSON — метки поколений `g_E` и `g_E − 1`
	// объектом JSON (`{}` — меток нет).
	LabelsJSON         string
	PreviousLabelsJSON string
	// ViaSubscription — права уровня кластера учитываются (Р11).
	ViaSubscription bool
	// Subject — непусто: вопрос о членстве одного субъекта `user:<id>`.
	Subject string
	// AfterSubject — субъекты строго больше (форма `user:<id>`).
	AfterSubject string
	// Limit — размер страницы. Ноль → DefaultPageSize.
	Limit int
}

// fencedSubjectsSQL — источники плана с оградой токена.
//
// $1 object_type (модель) · $2 object_id · $3 токен `R_E` · $4 области `<тип>:<id>` ·
// $5 метки g_E · $6 метки g_E−1 · $7 признак подписки · $8 типы предков атомов-фактов ·
// $9 отношения атомов-фактов · $10 глаголы атомов-выдачи · $11 object_type (каталог) ·
// $12 субъект членства (пусто — перечень) · $13 after · $14 limit
const fencedSubjectsSQL = `
WITH
-- scope — ОБЛАСТИ ВЕРСИИ СОБЫТИЯ: объект (глубина 0) и области из фактов
-- (глубина 1). Разбор <тип>:<id> — по ПЕРВОМУ двоеточию: id может нести своё
-- (у репозитория — косую, у иных — что угодно, кроме двоеточия в типе).
-- Кластер из фактов отбрасывается: права уровня кластера аудитории не образуют.
scope(s_type, s_id, depth) AS (
    SELECT $1::text, $2::text, 0
  UNION
    SELECT split_part(c, ':', 1), substr(c, length(split_part(c, ':', 1)) + 2), 1
      FROM unnest($4::text[]) AS c
     WHERE split_part(c, ':', 1) <> 'cluster'
),
fact_atom(parent_type, relation) AS (
    SELECT * FROM unnest($8::text[], $9::text[])
),
named(subject) AS (
    -- (1) прямой кортеж права — на объекте либо на предке типа, названного
    -- планом; безусловный и не изменённый после R_E.
    SELECT f.subject
      FROM kaname.relation_fact f
      JOIN fact_atom fa ON fa.relation = f.relation
      LEFT JOIN scope sc ON sc.s_type = f.object_type AND sc.s_id = f.object_id
     WHERE f.condition_name = ''
       AND pg_visible_in_snapshot(f.authz_rev, $3::pg_snapshot)
       AND (
             (sc.s_type IS NOT NULL
              AND CASE WHEN fa.parent_type = '' THEN sc.depth = 0 ELSE fa.parent_type = sc.s_type END)
          OR ($7::boolean AND f.object_type = 'cluster' AND fa.parent_type = 'cluster')
       )
  UNION
    -- (2) субъект выдачи (в том числе группа) — каждая строка цепочки «выдача →
    -- субъект → роль → глагол → правило» не изменена после R_E.
    SELECT bs.subject_type || ':' || bs.subject_id
      FROM kaname.access_bindings b
      JOIN kaname.access_binding_subjects bs ON bs.binding_id = b.id
      JOIN kaname.roles ro ON ro.id = b.role_id
      JOIN kaname.role_verb rv
        ON rv.role_id = b.role_id AND rv.object_type = $11::text
       AND rv.verb = ANY ($10::text[])
      JOIN kaname.role_rule_selectors rs
        ON rs.role_id = b.role_id AND $11::text = ANY (rs.object_types)
      LEFT JOIN scope sc ON sc.s_type = b.resource_type AND sc.s_id = b.resource_id
     WHERE b.status = 'ACTIVE'
       AND (b.expires_at IS NULL OR b.expires_at > now())
       AND b.revoked_at IS NULL
       AND (sc.s_type IS NOT NULL OR ($7::boolean AND b.resource_type = 'cluster'))
       AND pg_visible_in_snapshot(b.authz_rev, $3::pg_snapshot)
       AND pg_visible_in_snapshot(bs.authz_rev, $3::pg_snapshot)
       AND pg_visible_in_snapshot(ro.authz_rev, $3::pg_snapshot)
       AND pg_visible_in_snapshot(rv.authz_rev, $3::pg_snapshot)
       AND pg_visible_in_snapshot(rs.authz_rev, $3::pg_snapshot)
       AND (
             rs.arm = 'anchor'
          OR (rs.arm = 'names'  AND $2::text = ANY (rs.resource_names))
          OR (rs.arm = 'labels' AND ($5::jsonb @> rs.match_labels OR $6::jsonb @> rs.match_labels))
       )
),
granted(subject) AS (
    SELECT n.subject FROM named n
  UNION
    -- ЧЛЕНЫ названной группы; членство не изменено после R_E.
    SELECT gm.member_type || ':' || gm.member_id
      FROM named n{{members_join}}
     WHERE pg_visible_in_snapshot(gm.authz_rev, $3::pg_snapshot)
)
SELECT g.subject
  FROM granted g
 WHERE g.subject LIKE 'user:_%'
   AND g.subject <> 'user:*'
   AND ($12::text = '' OR g.subject = $12::text)
   AND g.subject > $13::text
 ORDER BY g.subject
 LIMIT $14::int`

// fencedSubjectsQuerySQL — готовый запрос аудитории с оградой.
func fencedSubjectsQuerySQL() string {
	return strings.Replace(fencedSubjectsSQL, membersJoinMark, membersOfNamedGroups("n.subject"), 1)
}

// FencedSubjects отдаёт страницу аудитории версии события. q — транзакция
// вызывающего: барьер поколения и аудитория читаются ОДНИМ снимком.
func FencedSubjects(ctx context.Context, q pgx.Tx, in FencedSubjectsQuery) (subjects []string, nextAfter string, err error) {
	if in.ObjectType == "" || in.ObjectID == "" || in.Relation == "" || in.AuthzRev == "" {
		return nil, "", fmt.Errorf("relverdict: неполный вопрос об аудитории %+v — пустой "+
			"перечень за него неотличим от честного «никто не имеет»", in)
	}
	limit := in.Limit
	if limit <= 0 {
		limit = DefaultPageSize
	}
	factParents, factRelations, bindVerbs, err := sourcesOf(in.ObjectType, in.Relation)
	if err != nil {
		return nil, "", err
	}
	catalogType, err := catalogTypeName(ctx, q, in.ObjectType)
	if err != nil {
		return nil, "", err
	}
	scope := in.Scope
	if scope == nil {
		scope = []string{}
	}
	labels, prev := in.LabelsJSON, in.PreviousLabelsJSON
	if labels == "" {
		labels = "{}"
	}
	if prev == "" {
		prev = "{}"
	}
	rows, err := q.Query(ctx, fencedSubjectsQuerySQL(),
		in.ObjectType, in.ObjectID, in.AuthzRev, scope, labels, prev, in.ViaSubscription,
		factParents, factRelations, bindVerbs, catalogType, in.Subject, in.AfterSubject, limit)
	if err != nil {
		return nil, "", fmt.Errorf("relverdict: аудитория версии события: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, "", fmt.Errorf("relverdict: чтение субъекта аудитории: %w", err)
		}
		subjects = append(subjects, s)
	}
	if err := rows.Err(); err != nil {
		return nil, "", fmt.Errorf("relverdict: обход аудитории: %w", err)
	}
	if len(subjects) == limit {
		nextAfter = subjects[len(subjects)-1]
	}
	return subjects, nextAfter, nil
}

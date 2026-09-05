// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ПЕРЕПИСЬ СЕТКИ ПРЕДЕЛА ПРОЧНОСТИ — ПО ТОЙ ЖЕ ДИСЦИПЛИНЕ, ЧТО СОСЕДНЯЯ
//
// Считается ПО ФАКТУ, запросом к таблицам, и по КАЖДОЙ величине порознь. Ноль —
// не красное, а ТРЕТИЙ исход («условие замера не создано»): прибор отказывается
// считать и называет пустую строку.
//
// # Чем эта перепись отличается от соседней и почему её нельзя было переиспользовать
//
// Соседняя (census.go) считает членства ГЛОБАЛЬНО — `count(*) FROM group_members`.
// Для оси M нужна доля СПРАШИВАЕМОГО: посторонние членства в ветвь `speaker_pair`
// не входят вовсе, и глобальный счётчик объявил бы условие созданным там, где
// членств у спрашиваемого ноль. То же с L: нужны строки, совпавшие с ПАРОЙ
// (говорящий, область), а не все строки таблицы.

// StrengthCensusInput — координаты, по которым снимается перепись.
//
// Названы явно, а не выведены из точки: перепись обязана спрашивать РОВНО о том
// объекте и о той области, которых касается вопрос, иначе она удостоверяет
// посев соседней точки.
type StrengthCensusInput struct {
	// Speakers — все написания субъекта, под которыми за него говорят.
	Speakers []string
	// MemberType/MemberID — сам субъект парой колонок, как его читает
	// `group_members`.
	MemberType string
	MemberID   string
	// ScopeType/ScopeID — область, на которой стоят выдачи оси L.
	ScopeType string
	ScopeID   string
	// ObjectType/ObjectID — измеряемый объект в словаре МОДЕЛИ: по нему
	// считается мощность цепи областей.
	ObjectType string
	ObjectID   string
	// RoleID — роль, чьи правила считаются осью K.
	RoleID string
	// MaxDepth — предел обхода цепи, тот же, что у запроса вердикта.
	MaxDepth int
}

// StrengthCensus — что реально лежит в таблицах на момент замера.
type StrengthCensus struct {
	MirrorObjects int64
	Edges         int64
	// SubjectMemberships — членств СПРАШИВАЕМОГО (ось M по факту).
	SubjectMemberships int64
	// AllMemberships — членств всего; печатается рядом, чтобы «у спрашиваемого
	// ноль» было отличимо от «таблица пуста».
	AllMemberships int64
	// SpeakerScopeRows — строк `access_binding_subjects`, совпавших с ПАРОЙ
	// (говорящий, область) (ось L по факту).
	SpeakerScopeRows int64
	// Bindings — выдач всего.
	Bindings int64
	// ScopeRows — мощность CTE `scope` в СТРОКАХ (ось S по факту).
	ScopeRows int64
	// ScopeDistinct — различных сущностей на цепи; печатается рядом со
	// ScopeRows, потому что их путают.
	ScopeDistinct int64
	// RoleRules — правил роли (ось K по факту).
	RoleRules int64
	// RoleVerbs — проекций глаголов роли; ноль означает, что дорогой отказ
	// выродился в дешёвый и точка мерила не то.
	RoleVerbs int64
	// Facts — прямых фактов всего.
	Facts int64
	// VerdictsAsked — вопросов задано в точке.
	VerdictsAsked int64
}

// TakeStrengthCensus — перепись по каждой величине порознь.
func TakeStrengthCensus(ctx context.Context, tx pgx.Tx, in StrengthCensusInput) (StrengthCensus, error) {
	var c StrengthCensus
	scalar := func(dst *int64, sql string, args ...any) error {
		if err := tx.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
			return fmt.Errorf("scalegrid: перепись прочности (%s): %w", firstLine(sql), err)
		}
		return nil
	}

	if err := scalar(&c.MirrorObjects,
		`SELECT count(*)::bigint FROM kacho_iam.resource_mirror`); err != nil {
		return c, err
	}
	if err := scalar(&c.Edges,
		`SELECT count(*)::bigint FROM kacho_iam.resource_parent_edge`); err != nil {
		return c, err
	}
	if err := scalar(&c.SubjectMemberships,
		`SELECT count(*)::bigint FROM kacho_iam.group_members
		  WHERE member_type = $1 AND member_id = $2`, in.MemberType, in.MemberID); err != nil {
		return c, err
	}
	if err := scalar(&c.AllMemberships,
		`SELECT count(*)::bigint FROM kacho_iam.group_members`); err != nil {
		return c, err
	}
	// Пара (говорящий, область) — ровно тем соединением, которым её читает
	// ветвь выдач: колонками, а не склейкой.
	//
	// ЗДЕСЬ ЭТОТ КОММЕНТАРИЙ ДОЛГО БЫЛ ЛОЖЕН. Он обещал колонки, а стоявший под
	// ним предикат сравнивал СКЛЕЙКУ (#758) — то есть прибор мерил стоимость
	// формы, от которой сам же и предостерегал, и гасил
	// access_binding_subjects_subject_scope_idx на каждой точке сетки. Довод
	// целиком — у census.go, где та же правка сделана тем же способом.
	if err := scalar(&c.SpeakerScopeRows,
		`SELECT count(*)::bigint
		   FROM kacho_iam.access_binding_subjects bs
		   JOIN kacho_iam.access_bindings b ON b.id = bs.binding_id
		   JOIN (SELECT DISTINCT split_part(w, ':', 1) AS s_type,
		                substr(w, length(split_part(w, ':', 1)) + 2) AS s_id
		           FROM unnest($1::text[]) AS w) sp
		     ON bs.subject_type = sp.s_type AND bs.subject_id = sp.s_id
		  WHERE bs.resource_type = $2 AND bs.resource_id = $3
		    AND b.status = 'ACTIVE' AND b.revoked_at IS NULL`,
		in.Speakers, in.ScopeType, in.ScopeID); err != nil {
		return c, err
	}
	if err := scalar(&c.Bindings,
		`SELECT count(*)::bigint FROM kacho_iam.access_bindings`); err != nil {
		return c, err
	}
	// Мощность цепи — ТЕМ ЖЕ обходом, каким её строит запрос вердикта. Своя
	// редакция обхода была бы вторым местом об одном предмете и разошлась бы
	// молча — причём в сторону «условие создано».
	//
	// ОБХОД тот же, а ПОТРЕБЛЯЕМЫЙ НАБОР с #811 — уже нет: армы вердикта читают
	// отбор различных поверх обхода (scope_distinct), то есть ScopeDistinct, а
	// не ScopeRows. Обе величины считаются и печатаются ПОРОЗНЬ ровно затем,
	// чтобы их нельзя было перепутать: ось S объявляет мощность ОБХОДА (свойство
	// фикстуры, и Verify сверяет именно её), а стоимость арма растёт по числу
	// РАЗЛИЧНЫХ областей. Подменить одно другим значило бы переопределить ось
	// сетки задним числом.
	if err := tx.QueryRow(ctx, `
		WITH RECURSIVE scope(s_type, s_id, depth) AS (
		    SELECT $1::text, $2::text, 0
		  UNION
		    SELECT e.parent_type, e.parent_id, s.depth + 1
		      FROM scope s
		      CROSS JOIN LATERAL (
		             SELECT pe.parent_type, pe.parent_id
		               FROM kacho_iam.resource_parent_edge pe
		              WHERE pe.object_type = s.s_type AND pe.object_id = s.s_id
		              ORDER BY pe.depth
		              LIMIT $3::int
		           ) e
		     WHERE s.depth < $3::int
		)
		SELECT count(*)::bigint, count(DISTINCT (s_type, s_id))::bigint FROM scope`,
		in.ObjectType, in.ObjectID, in.MaxDepth).Scan(&c.ScopeRows, &c.ScopeDistinct); err != nil {
		return c, fmt.Errorf("scalegrid: перепись прочности (мощность цепи): %w", err)
	}
	if err := scalar(&c.RoleRules,
		`SELECT count(*)::bigint FROM kacho_iam.role_rule_selectors WHERE role_id = $1`,
		in.RoleID); err != nil {
		return c, err
	}
	if err := scalar(&c.RoleVerbs,
		`SELECT count(*)::bigint FROM kacho_iam.role_verb WHERE role_id = $1`,
		in.RoleID); err != nil {
		return c, err
	}
	if err := scalar(&c.Facts,
		`SELECT count(*)::bigint FROM kacho_iam.relation_fact`); err != nil {
		return c, err
	}
	return c, nil
}

// Verify — перепись против того, что точка СОБИРАЛАСЬ посадить.
//
// Проверяются ОБЕ стороны: и недосев, и пересев. Недосев выглядит как «величина
// не выросла», пересев — как «выросла сильнее ожидаемого»; ни одно из двух не
// является свойством запроса.
func (c StrengthCensus) Verify(p StrengthPoint) error {
	var bad []string
	exact := func(name string, got int64, want int64) {
		if got != want {
			bad = append(bad, fmt.Sprintf("%s: в таблице %d, точка объявила %d", name, got, want))
		}
	}
	atLeast := func(name string, got int64, want int64) {
		if got < want {
			bad = append(bad, fmt.Sprintf("%s: в таблице %d, объявлено не меньше %d", name, got, want))
		}
	}
	atLeast("объектов зеркала", c.MirrorObjects, int64(p.N))
	exact("членств СПРАШИВАЕМОГО (ось M)", c.SubjectMemberships, int64(p.M))
	exact("строк (говорящий, область) (ось L)", c.SpeakerScopeRows, int64(p.L))
	exact("мощность цепи областей в строках (ось S)", c.ScopeRows, int64(p.S))
	exact("правил роли (ось K)", c.RoleRules, int64(p.K))
	// Проекция глагола — ПРЕДПОСЫЛКА дорогого отказа: без неё он вырождается в
	// дешёвый, и точка меряет не то, что называет, оставаясь внешне исправной.
	atLeast("проекций глаголов роли", c.RoleVerbs, 1)
	atLeast("вопросов задано", c.VerdictsAsked, 1)
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w — точка %s:\n    %s\n  Это ТРЕТИЙ исход, а не красный: искать дефект "+
		"в измеряемом коде здесь нечего, прогон недействителен и повторяется после устранения причины",
		ErrConditionNotCreated, p, strings.Join(bad, "\n    "))
}

// String — перепись строками отчёта.
func (c StrengthCensus) String() string {
	var b strings.Builder
	f := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	f("    объектов зеркала / рёбер родителя      %d / %d\n", c.MirrorObjects, c.Edges)
	f("    членств СПРАШИВАЕМОГО / всего          %d / %d\n", c.SubjectMemberships, c.AllMemberships)
	f("    строк (говорящий, область) / выдач     %d / %d\n", c.SpeakerScopeRows, c.Bindings)
	f("    цепь областей: строк / различных       %d / %d\n", c.ScopeRows, c.ScopeDistinct)
	f("    правил роли / проекций глаголов        %d / %d\n", c.RoleRules, c.RoleVerbs)
	f("    прямых фактов всего                    %d\n", c.Facts)
	f("    вопросов задано                        %d\n", c.VerdictsAsked)
	return b.String()
}

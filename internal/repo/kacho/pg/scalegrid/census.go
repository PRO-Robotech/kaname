// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// ПЕРЕПИСЬ ПОСАЖЕННОГО — ЕДИНСТВЕННОЕ СВИДЕТЕЛЬСТВО, ЧТО УСЛОВИЕ ЗАМЕРА СОЗДАНО
//
// Считается ПО ФАКТУ, запросом к таблицам, а не «сколько собирались вставить».
// Разница не педантическая: `ON CONFLICT DO NOTHING` без последующего пересчёта
// даёт тихий недосев, и точка, объявившая F = 100 при двенадцати строках в
// таблице, мерит не то, что называет, — а выглядит как «величина не выросла».
//
// Ноль в любой строке — НЕ красное. Это ТРЕТИЙ исход («условие замера не
// создано»), и в дереве он уже закодирован: `deploy/scripts/classify-integration-outcome.sh`
// → `make test-integration` → `.github/workflows/ci.yaml`. Второго кодирования
// того же исхода здесь не заводится — два места об одном предмете расходятся
// молча. Прибор лишь ОТКАЗЫВАЕТСЯ считать и называет пустую строку.

// ErrConditionNotCreated — предпосылка замера не выполнена.
var ErrConditionNotCreated = errors.New("scalegrid: условие замера не создано")

// Census — что реально лежит в таблицах на момент замера.
type Census struct {
	// MirrorObjects — объектов зеркала.
	MirrorObjects int64
	// Edges — рёбер родителя всего и с распределением по глубине.
	Edges        int64
	EdgesByDepth map[int]int64
	// Bindings — выдач всего; BindingsNamingSubject — из них называющих
	// спрашиваемого субъекта на цепи областей (то есть ось R по факту).
	Bindings              int64
	BindingsNamingSubject int64
	// GroupMemberships — членств в группах.
	GroupMemberships int64
	// Roles / RoleVerbs / RoleRules — роли и их проекции.
	Roles     int64
	RoleVerbs int64
	RoleRules int64
	// Facts — прямых фактов всего; FactsNamingSubject — называющих
	// спрашиваемого (ось F по факту).
	Facts              int64
	FactsNamingSubject int64
	// VerdictsAsked — сколько вердиктов задано в этой точке. Без него «величина
	// не двигалась» тождественно верно для точки, где вопроса не задали.
	VerdictsAsked int64
}

// TakeCensus — перепись по КАЖДОЙ таблице ПОРОЗНЬ.
//
// Порознь, а не одним квантифицирующим стейтментом, и это не стилистика: гейт
// `TestCensusFixturesSeedThroughTheProducer` различает именно это. Утверждение
// «у каждой строки зеркала есть цепь предков» — квантор, его вправе делать
// только проба, идущая через производителя. Счёт по таблице квантора не несёт.
//
// `subject` — субъект вопроса целиком (`"user:usr-1"`), `speakerSubjects` — все
// написания, которыми за него говорят (он сам, его группы, подстановка):
// «называет спрашиваемого» решается по ним, а не по одному лишь личному имени,
// иначе выдача через группу не была бы сосчитана и ось R показала бы ноль там,
// где посажена сотня.
func TakeCensus(ctx context.Context, tx pgx.Tx, speakerSubjects []string) (Census, error) {
	var c Census
	c.EdgesByDepth = map[int]int64{}

	scalar := func(dst *int64, sql string, args ...any) error {
		if err := tx.QueryRow(ctx, sql, args...).Scan(dst); err != nil {
			return fmt.Errorf("scalegrid: перепись (%s): %w", firstLine(sql), err)
		}
		return nil
	}

	if err := scalar(&c.MirrorObjects, `SELECT count(*)::bigint FROM kacho_iam.resource_mirror`); err != nil {
		return c, err
	}
	if err := scalar(&c.Edges, `SELECT count(*)::bigint FROM kacho_iam.resource_parent_edge`); err != nil {
		return c, err
	}
	rows, err := tx.Query(ctx,
		`SELECT depth, count(*)::bigint FROM kacho_iam.resource_parent_edge GROUP BY depth ORDER BY depth`)
	if err != nil {
		return c, fmt.Errorf("scalegrid: перепись рёбер по глубине: %w", err)
	}
	for rows.Next() {
		var d int
		var n int64
		if err := rows.Scan(&d, &n); err != nil {
			rows.Close()
			return c, fmt.Errorf("scalegrid: перепись рёбер по глубине: %w", err)
		}
		c.EdgesByDepth[d] = n
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return c, fmt.Errorf("scalegrid: перепись рёбер по глубине: %w", err)
	}

	if err := scalar(&c.Bindings, `SELECT count(*)::bigint FROM kacho_iam.access_bindings`); err != nil {
		return c, err
	}
	// Выдача «называет спрашиваемого», если её субъект — одно из написаний, под
	// которыми за него говорят. Соединение идёт через `access_binding_subjects`,
	// потому что именно её читает вердикт: считать по колонкам родительской
	// таблицы значило бы завести второе представление о том, кто назван.
	//
	// СУБЪЕКТ — ПАРОЙ КОЛОНОК, а не склейкой (#758). Склейка
	// subject_type || ':' || subject_id выводит обе колонки из-под
	// access_binding_subjects_subject_scope_idx: сравнивать приходится
	// вычисленное значение, а вычисленное значение отбирает строки только ПОСЛЕ
	// того, как они прочитаны. Разбирается ПАРАМЕТР — ровно так же, как это
	// делает speaker_pair запроса вердикта.
	//
	// Отбор различных на разобранных парах обязателен: без него строка выдачи
	// сосчиталась бы по разу на каждое повторяющееся написание во входном
	// наборе, и перепись разошлась бы со склейкой. Одна пара соответствует ровно
	// одному написанию, поэтому на различных парах числа тождественны.
	if err := scalar(&c.BindingsNamingSubject,
		`SELECT count(*)::bigint
		   FROM kacho_iam.access_binding_subjects bs
		   JOIN (SELECT DISTINCT split_part(w, ':', 1) AS s_type,
		                substr(w, length(split_part(w, ':', 1)) + 2) AS s_id
		           FROM unnest($1::text[]) AS w) sp
		     ON bs.subject_type = sp.s_type AND bs.subject_id = sp.s_id`, speakerSubjects); err != nil {
		return c, err
	}
	if err := scalar(&c.GroupMemberships, `SELECT count(*)::bigint FROM kacho_iam.group_members`); err != nil {
		return c, err
	}
	if err := scalar(&c.Roles, `SELECT count(*)::bigint FROM kacho_iam.roles`); err != nil {
		return c, err
	}
	if err := scalar(&c.RoleVerbs, `SELECT count(*)::bigint FROM kacho_iam.role_verb`); err != nil {
		return c, err
	}
	if err := scalar(&c.RoleRules, `SELECT count(*)::bigint FROM kacho_iam.role_rule_selectors`); err != nil {
		return c, err
	}
	if err := scalar(&c.Facts, `SELECT count(*)::bigint FROM kacho_iam.relation_fact`); err != nil {
		return c, err
	}
	if err := scalar(&c.FactsNamingSubject,
		`SELECT count(*)::bigint FROM kacho_iam.relation_fact f WHERE f.subject = ANY($1::text[])`,
		speakerSubjects); err != nil {
		return c, err
	}
	return c, nil
}

// Verify — перепись против того, что точка СОБИРАЛАСЬ посадить.
//
// Проверяются обе стороны: ноль там, где ждали непустое, и расхождение с
// объявленным. Первое ловит «условие не создано», второе — тихий недосев,
// который выглядит неотличимо от «величина не выросла».
//
// Ось F законно бывает нулевой — точка F = 0 обязательна как нижняя, — поэтому
// её ноль исключением не является, и это записано, а не подразумевается.
func (c Census) Verify(p Point) error {
	var bad []string
	req := func(name string, got int64, wantAtLeast int64) {
		if got < wantAtLeast {
			bad = append(bad, fmt.Sprintf("%s: в таблице %d, объявлено не меньше %d",
				name, got, wantAtLeast))
		}
	}
	req("объектов зеркала", c.MirrorObjects, int64(p.N))
	req("рёбер родителя", c.Edges, int64(p.N))
	req("выдач всего", c.Bindings, int64(p.B))
	req("выдач, называющих спрашиваемого", c.BindingsNamingSubject, int64(p.R))
	req("фактов, называющих спрашиваемого", c.FactsNamingSubject, int64(p.F))
	req("ролей", c.Roles, 1)
	req("правил ролей", c.RoleRules, 1)
	req("вердиктов задано", c.VerdictsAsked, 1)
	if p.Recruit == RecruitViaGroup || p.Recruit == RecruitFactGroup {
		req("членств в группах", c.GroupMemberships, 1)
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w — точка %s:\n    %s\n  Это ТРЕТИЙ исход, а не красный: искать дефект "+
		"в измеряемом коде здесь нечего, прогон недействителен и повторяется после устранения причины",
		ErrConditionNotCreated, p, strings.Join(bad, "\n    "))
}

// String — перепись строками отчёта.
func (c Census) String() string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }
	p("    объектов зеркала                       %d\n", c.MirrorObjects)
	p("    рёбер родителя                         %d", c.Edges)
	if len(c.EdgesByDepth) > 0 {
		depths := make([]int, 0, len(c.EdgesByDepth))
		for d := range c.EdgesByDepth {
			depths = append(depths, d)
		}
		sort.Ints(depths)
		p("  (по глубине:")
		for _, d := range depths {
			p(" %d→%d", d, c.EdgesByDepth[d])
		}
		p(")")
	}
	p("\n")
	p("    выдач всего                            %d\n", c.Bindings)
	p("    выдач, называющих спрашиваемого        %d\n", c.BindingsNamingSubject)
	p("    членств в группах                      %d\n", c.GroupMemberships)
	p("    ролей / проекций глаголов / правил     %d / %d / %d\n", c.Roles, c.RoleVerbs, c.RoleRules)
	p("    прямых фактов всего                    %d\n", c.Facts)
	p("    фактов, называющих спрашиваемого       %d\n", c.FactsNamingSubject)
	p("    вердиктов задано                       %d\n", c.VerdictsAsked)
	return b.String()
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

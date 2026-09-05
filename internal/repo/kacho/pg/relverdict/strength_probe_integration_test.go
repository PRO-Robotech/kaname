// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// strength_probe_integration_test.go — ПРИБОР ПРЕДЕЛА ПРОЧНОСТИ: ПЯТЬ НОВЫХ ОСЕЙ
// И ИСХОД ВЕРДИКТА НА КАЖДОЙ ТОЧКЕ.
//
// # Чем эта проба отличается от соседней (scalegrid_probe_integration_test.go)
//
// Соседняя отвечает на вопрос «растёт ли стоимость от размера облака» и
// отвечает ОДНИМ исходом: все её 24 точки дали `allow`. Отказной путь там не
// измерен ни разу. Между тем ранний выход работает ТОЛЬКО на «да» — предел одной
// строки стоит ВНУТРИ ветви выдач, — значит отказ обязан дочитать ровно то, что
// разрешение бросает первой же строкой. Потолок живёт на отказе, и мерить его
// разрешающим вопросом нельзя.
//
// Поэтому здесь ТОЧКА — НЕ ОДИН ВОПРОС, А ТРИ, и все три задаются на ОДНОМ И ТОМ
// ЖЕ посеве (см. scalegrid.AskModes). Дельта «allow → deny(правило)» и есть цена
// недочитанного; без пары вся стоимость приписалась бы отказу.
//
// # Что здесь утверждается, а что нет
//
// Проба меряет путь, который СЕГОДНЯ и принимает решение о доступе: внешнего
// движка отношений в продукте нет — он снят стадией S6 эпика #747, — теневого
// сравнителя рядом с ним нет тоже, вердикт вычисляется в своей базе.
//
// Прежняя редакция этой шапки называла числа «БУДУЩИМ путём» и запрещала читать
// их как сегодняшние. Она пережила свой предмет.
//
// НЕ утверждается характеристика продуктового трафика: посев — фикстура прибора
// на одной машине.
//
// # Несущая величина — строки, а не миллисекунды
//
// Время печатается и никогда не выносит вердикта: оно есть свойство машины и на
// другой машине ложно. На отказных вопросах несущей становится «тронуто»
// (отдано + отброшено): отвергнутая строка прочитана ровно так же, как принятая,
// и колонка «строк» на отказе показывает ноль там, где работа сделана.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/planrows"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/scalegrid"
)

// strengthEnv — ручка «запускать сетку предела прочности», и только это.
// Что мерить, решает константа в pg/scalegrid.
const strengthEnv = "KACHO_STRENGTH_FULL"

// Координаты фикстуры. Тип тот же, что у соседней пробы: его цепь предков — самая
// длинная в продукте, а на вырожденной цепи неподвижным выглядит и то, что
// умножается.
const (
	strCatalogType = "registry.repositories"
	strModelType   = "registry_repository"
	// strRelation / strVerb — разрешаемый вопрос.
	strRelation = "v_get"
	strVerb     = "get"
	// strDenyVerbRelation — отношение ДЕШЁВОГО отказа: роли фикстуры несут
	// только `get`, поэтому соединение схлопывается на role_verb, до оснований
	// запрос не доходит. Отношение обязано существовать в модели — иначе `Ask`
	// вернёт ошибку, а не отказ, и точка измерит опечатку.
	strDenyVerbRelation = "v_delete"

	strRoleID   = "rol-str"
	strRoleName = "probe.strength"

	// strAllowObj / strDenyObj — два объекта на ОДНОМ посеве.
	//
	// Разные объекты, а не разные субъекты: субъект несёт выдачи, и менять его
	// значило бы менять ветвь `speaker`, то есть двигать две оси разом. Цепь у
	// обоих одна и та же, метки — разные, и отвергает ровно ПОСЛЕДНЕЕ звено.
	strAllowObj = "repo-allow"
	strDenyObj  = "repo-deny"

	strGroupID = "grp-str"
	strSubject = "user:usr-1"
	strUserID  = "usr-1"

	// strMaxDepth — предел обхода цепи; тот же, что у запроса вердикта.
	strMaxDepth = 4

	// strRepeats — повторов вопроса на точку; нулевой прогревочный и в выборку
	// не входит.
	strRepeats = 11
)

// strSpeakers — все написания, под которыми за спрашиваемого говорят.
var strSpeakers = []string{
	strSubject,
	"group:" + strGroupID,
	"group:" + strGroupID + "#member",
	"user:*",
}

// strWantRelations — ПРЕДПОСЫЛКА замера: отношения, которые запрос обязан читать.
var strWantRelations = []string{
	"relation_fact", "access_bindings", "access_binding_subjects",
	"role_verb", "role_rule_selectors", "group_members",
	"resource_parent_edge", "resource_mirror",
}

// ── РЕЗУЛЬТАТ ────────────────────────────────────────────────────────────────

// askResult — один вопрос, снятый приборами.
type askResult struct {
	mode    scalegrid.AskMode
	verdict string
	rows    int64 // отдано узлами плана (Actual Rows × Loops)
	removed int64 // отброшено фильтром/перепроверкой/соединением
	touched int64 // rows + removed — НЕСУЩАЯ на отказных вопросах
	loops   int64 // СО-НЕСУЩАЯ: число сканов, сумма Actual Loops листовых узлов
	tuples  int64 // сверочная: pg_stat_xact_all_tables
	calls   int64 // обращений к БД на один вопрос
	p50     time.Duration
	p99     time.Duration
	plan    string
	// sweeps / listed / scanned — только у оси перечисления.
	sweeps  int
	listed  int
	scanned int
}

// strPointResult — строка отчёта: точка и три её вопроса.
type strPointResult struct {
	point  scalegrid.StrengthPoint
	asks   []askResult
	census scalegrid.StrengthCensus
	seedIn time.Duration
	// census0 — перепись прибора (доля неотнесённого), с разрешающего вопроса.
	census0 string
}

// ask — результат нужного вопроса; пустой, если такого вопроса не задавали.
func (r strPointResult) ask(m scalegrid.AskMode) askResult {
	for _, a := range r.asks {
		if a.mode == m {
			return a
		}
	}
	return askResult{mode: m}
}

// ── ФИКСТУРА ─────────────────────────────────────────────────────────────────

// strFixture — состояние посева одной оси.
//
// Ось растёт ПРИРАЩЕНИЕМ там, где приращение возможно (N, M, L, K), и
// пересевается там, где точка меняет ФОРМУ данных (S — своя цепь на точку,
// Pg — своя раскраска меток).
type strFixture struct {
	tx pgx.Tx
	// seedN — объектов зеркала посажено.
	seedN int
	// seedM / seedL / seedK — достигнутые значения соответствующих осей.
	seedM int
	seedL int
	seedK int
	// allowObj / denyObj — измеряемые объекты ТЕКУЩЕЙ точки. Ось S меняет их
	// на точке, прочие оси держат неподвижными.
	allowObj string
	denyObj  string
	// scopeType / scopeID — область, на которой стоят выдачи оси L.
	scopeType string
	scopeID   string
	// shareSeeded — доля доступных, посаженная осью Pg (-1 — не сеялась).
	shareSeeded int
}

// strLabelKeys — метки объекта разрешения. Их 64 — предел, объявленный продуктом
// (pkg/validate MaxLabels); селектор оси K берёт из них по 16 ключей.
func strLabelKeys() map[string]string {
	m := make(map[string]string, 64)
	for i := 0; i < 64; i++ {
		m[fmt.Sprintf("k%02d", i)] = "v"
	}
	return m
}

// strSelectorLabels — набор из 16 ключей для k-го правила роли.
//
// Ключи берутся ШАГОМ по кольцу, а не подряд: подряд идущие наборы у соседних
// правил пересекались бы почти целиком, и планировщик мог бы схлопнуть их в один
// проход — то есть ось K мерила бы не K правил, а одно.
func strSelectorLabels(k int) map[string]string {
	m := make(map[string]string, 16)
	for j := 0; j < 16; j++ {
		m[fmt.Sprintf("k%02d", (k*7+j*3)%64)] = "v"
	}
	return m
}

func strJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("сериализация меток: %v", err)
	}
	return string(b)
}

// newStrFixture — база оси: аренда, роль с МЕТОЧНОЙ ветвью правила, цепь
// областей, два измеряемых объекта.
//
// Ветвь правила здесь МЕТОЧНАЯ, а не якорная, и это несущее отличие от соседней
// пробы. Якорная ветвь истинна для любого объекта типа — на ней ДОРОГОГО отказа
// не существует вовсе: отвергать нечему. Меточная делает последним звеном
// предикат, и ровно он отвергает объект отказа.
func newStrFixture(t *testing.T, ctx context.Context, tx pgx.Tx) *strFixture {
	t.Helper()
	f := &strFixture{tx: tx, shareSeeded: -1}

	exec(t, ctx, tx, `INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ('acc-1', 'strength-account', $1)`,
		strUserID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ($1, 'ext-1', 'usr-1@kacho.local', 'acc-1')`, strUserID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-1', 'acc-1', 'strength-project')`)
	// Группа заводится ВСЕГДА, даже при M = 0: за спрашиваемого говорят четыре
	// написания, и три из них называют группу. Отсутствие самой группы сделало
	// бы точку M = 0 неотличимой от «в базе групп нет вовсе».
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, 'acc-1', 'strength-group')`,
		strGroupID)

	strSeedRole(t, ctx, tx, strRoleID, strRoleName, 1)

	s := scalegrid.NewSeeder(tx)
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: "iam.project", ObjectID: "prj-1",
		ParentAccountID: "acc-1", ParentChain: []string{"account:acc-1"},
	}))
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: "registry.registries", ObjectID: "reg-1",
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		ParentChain: []string{"project:prj-1", "account:acc-1"},
	}))
	// Два измеряемых объекта на цепи глубины 3 (S_набл = 7 — сегодняшняя форма).
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: strCatalogType, ObjectID: strAllowObj,
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		Labels:      strLabelKeys(),
		ParentChain: []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
	}))
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: strCatalogType, ObjectID: strDenyObj,
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		Labels:      map[string]string{"env": "dev"},
		ParentChain: []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
	}))
	must(t, s.Flush(ctx))

	f.allowObj, f.denyObj = strAllowObj, strDenyObj
	f.scopeType, f.scopeID = "project", "prj-1"
	f.seedK = 1

	// Выдача L = 1: сам спрашиваемый на проекте.
	strSeedBinding(t, ctx, tx, "acb-str-base", "user", strUserID, strRoleID, "project", "prj-1", nil)
	f.seedL = 1
	return f
}

// strSeedRole — роль с k меточными правилами и проекцией глагола.
func strSeedRole(t *testing.T, ctx context.Context, tx pgx.Tx, roleID, roleName string, k int) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module', 'probe', 'resources', jsonb_build_array('*'),
		             'verbs',  jsonb_build_array($3::text))),
		         'cluster_kacho_root')`, roleID, roleName, strVerb)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		roleID, strCatalogType, strVerb)
	for i := 0; i < k; i++ {
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ($1, $2, 'labels', ARRAY[$3::text], $4::jsonb)`,
			roleID, fmt.Sprintf("fp-%04d", i), strCatalogType, strJSON(t, strSelectorLabels(i)))
	}
}

// strSeedBinding — действующая выдача плюс строки её субъектов.
//
// `extraSubjects` — субъекты СВЕРХ легаси-субъекта строки выдачи. Ими и
// набирается ось L: уникальность действующей выдачи ключуется легаси-субъектом,
// поэтому k привязок вида subjects=[болван_i, U] дают k строк (U, область) и в
// уникальность не упираются.
func strSeedBinding(t *testing.T, ctx context.Context, tx pgx.Tx,
	bindingID, subjType, subjID, roleID, resType, resID string, extraSubjects [][2]string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')`,
		bindingID, subjType, subjID, roleID, resType, resID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, $2, $3)`, bindingID, subjType, subjID)
	for _, s := range extraSubjects {
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, $2, $3)`, bindingID, s[0], s[1])
	}
}

// growN — досыпать объектов зеркала.
//
// `allowedShare` — доля объектов, чьи метки удовлетворяют селектору роли, в
// процентах. Раскладка ЧЕРЕДУЮЩАЯСЯ (i % 100 < share), а не «первые share
// процентов»: перечисление идёт по первичному ключу, и доступные, лежащие
// подряд в начале, наполнили бы страницу первым же заходом — то есть худший
// случай оказался бы не измерен, а обойдён.
func (f *strFixture) growN(t *testing.T, ctx context.Context, target, allowedShare int) {
	t.Helper()
	if allowedShare != f.shareSeeded {
		// Смена раскраски переписывает метки УЖЕ посаженных: досыпать поверх
		// значило бы получить смесь двух долей и назвать её одной.
		if f.seedN > 0 {
			exec(t, ctx, f.tx,
				`UPDATE kacho_iam.resource_mirror SET labels = CASE
				    WHEN (substr(object_id, 6)::int % 100) < $1 THEN $2::jsonb ELSE $3::jsonb END
				  WHERE object_type = $4 AND object_id LIKE 'bulk-%'`,
				allowedShare, strJSON(t, strSelectorLabels(0)), strJSON(t, map[string]string{"env": "dev"}),
				strCatalogType)
		}
		f.shareSeeded = allowedShare
	}
	if target <= f.seedN {
		return
	}
	// Массовые объекты несут РОВНО тот набор, который требует единственный
	// селектор точки (16 ключей), а не все 64: 64 ключа на 10⁵ объектов — это
	// вчетверо больший разбор JSON на посеве, не меняющий ни одного предиката.
	// Все 64 несёт только измеряемый объект оси K.
	allowLabels := strSelectorLabels(0)
	denyLabels := map[string]string{"env": "dev"}
	s := scalegrid.NewSeeder(f.tx)
	for i := f.seedN; i < target; i++ {
		labels := denyLabels
		if i%100 < allowedShare {
			labels = allowLabels
		}
		must(t, s.Queue(ctx, scalegrid.MirrorRow{
			ObjectType:      strCatalogType,
			ObjectID:        fmt.Sprintf("bulk-%07d", i),
			ParentProjectID: "prj-1",
			ParentAccountID: "acc-1",
			Labels:          labels,
			ParentChain:     []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
		}))
	}
	must(t, s.Flush(ctx))
	f.seedN = target
}

// setM — членств спрашивающего ровно target.
func (f *strFixture) setM(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target < f.seedM {
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.group_members WHERE member_id = $1`, strUserID)
		f.seedM = 0
	}
	if target <= f.seedM {
		return
	}
	s := scalegrid.NewSeeder(f.tx)
	for i := f.seedM; i < target; i++ {
		gid := fmt.Sprintf("grp-m%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, 'acc-1', $2)
			 ON CONFLICT DO NOTHING`, gid, fmt.Sprintf("strength-m-%05d", i)))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
			 VALUES ($1, 'user', $2)`, gid, strUserID))
	}
	must(t, s.Flush(ctx))
	f.seedM = target
}

// setL — строк (говорящий, область) ровно target.
func (f *strFixture) setL(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target < f.seedL {
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.access_bindings WHERE id LIKE 'acb-l%'`)
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.access_bindings WHERE id = 'acb-str-base'`)
		f.seedL = 0
	}
	if target <= f.seedL {
		return
	}
	s := scalegrid.NewSeeder(f.tx)
	if f.seedL == 0 {
		// Первая строка — сам спрашиваемый легаси-субъектом.
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-str-base', 'user', $1, $2, $3, $4, 'ACTIVE')`,
			strUserID, strRoleID, f.scopeType, f.scopeID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-str-base', 'user', $1)`, strUserID))
		f.seedL = 1
	}
	for i := f.seedL; i < target; i++ {
		uid := fmt.Sprintf("usr-l%05d", i)
		bid := fmt.Sprintf("acb-l%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ($1, $1, $1 || '@kacho.local', 'acc-1') ON CONFLICT DO NOTHING`, uid))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE')`,
			bid, uid, strRoleID, f.scopeType, f.scopeID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, bid, uid))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, bid, strUserID))
	}
	must(t, s.Flush(ctx))
	f.seedL = target
}

// setK — правил роли ровно target.
func (f *strFixture) setK(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target < f.seedK {
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, strRoleID)
		f.seedK = 0
	}
	if target <= f.seedK {
		return
	}
	s := scalegrid.NewSeeder(f.tx)
	for i := f.seedK; i < target; i++ {
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ($1, $2, 'labels', ARRAY[$3::text], $4::jsonb)`,
			strRoleID, fmt.Sprintf("fp-%04d", i), strCatalogType, strJSON(t, strSelectorLabels(i))))
	}
	must(t, s.Flush(ctx))
	f.seedK = target
}

// setScopeShape — цепь областей заданной МОЩНОСТИ, со своими объектами.
//
// Мощность CTE — не глубина: обход разворачивается вбок, и у каждого узла до
// четырёх рёбер (ключ (объект, глубина) плюс проверка глубины 1..4). Отсюда три
// формы, и все три — разные состояния данных, а не одно с разными числами:
//
//	S = 1   — рёбер нет вовсе: область есть сам объект;
//	S = 7   — согласованное замыкание глубины 3 (1+3+2+1) — СЕГОДНЯШНЯЯ форма;
//	S = 11  — согласованное замыкание глубины 4 (1+4+3+2+1);
//	S = 341 — схемный потолок: у КАЖДОГО узла свои четыре ребра (1+4+16+64+256).
//
// Выдача на этой оси ставится НА САМ ОБЪЕКТ, а не на проект: иначе точка S = 1
// не существует как состояние — у объекта без рёбер проекта в области нет.
func (f *strFixture) setScopeShape(t *testing.T, ctx context.Context, s int) {
	t.Helper()
	allow := fmt.Sprintf("scp-%03d-allow", s)
	deny := fmt.Sprintf("scp-%03d-deny", s)
	f.allowObj, f.denyObj = allow, deny
	f.scopeType, f.scopeID = strModelType, allow

	sd := scalegrid.NewSeeder(f.tx)
	// Сами объекты — в зеркало, БЕЗ цепи: рёбра кладутся ниже своей формой.
	for _, pair := range [][2]any{{allow, strLabelKeys()}, {deny, map[string]string{"env": "dev"}}} {
		must(t, sd.Queue(ctx, scalegrid.MirrorRow{
			ObjectType: strCatalogType, ObjectID: pair[0].(string),
			ParentProjectID: "prj-1", ParentAccountID: "acc-1",
			Labels: pair[1].(map[string]string),
		}))
	}
	must(t, sd.Flush(ctx))

	edge := func(objID string, depth int, parentType, parentID string) {
		must(t, sd.QueueRaw(ctx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			strModelType, objID, parentType, parentID, depth))
	}
	// Рёбра синтетических предков кладутся своим типом модели: типы предков в
	// эту таблицу приезжают уже словарём модели, и точка в имени запрещена
	// проверкой схемы.
	synthEdge := func(objType, objID string, depth int, parentType, parentID string) {
		must(t, sd.QueueRaw(ctx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			objType, objID, parentType, parentID, depth))
	}

	switch s {
	case 1:
		// Рёбер нет.
	case 7, 11:
		// Согласованное замыкание глубины d: объект знает d предков, предок
		// глубины i знает d-i своих.
		d := 3
		if s == 11 {
			d = 4
		}
		anc := make([]string, d+1)
		for i := 1; i <= d; i++ {
			anc[i] = fmt.Sprintf("anc%d-s%03d", i, s)
		}
		for _, obj := range []string{allow, deny} {
			for i := 1; i <= d; i++ {
				edge(obj, i, "scope_anc", anc[i])
			}
		}
		for i := 1; i <= d; i++ {
			for j := i + 1; j <= d; j++ {
				synthEdge("scope_anc", anc[i], j-i, "scope_anc", anc[j])
			}
		}
	case 341:
		// СХЕМНЫЙ ПОТОЛОК: у каждого узла четыре РАЗЛИЧНЫХ предка на глубинах
		// 1..4, и так до четвёртого уровня. 1 + 4 + 16 + 64 + 256 = 341.
		//
		// Состояние ПОСЕВНОЕ: производители дерева шлют одно-два звена, а формы
		// цепи не проверяет никто — `RegisterResource` передаёт её как есть.
		// Точка отвечает на вопрос «что схема допускает», а не «что бывает».
		for _, obj := range []string{allow, deny} {
			// Уровень 1 — общий у обоих объектов: иначе дерево удвоилось бы,
			// а мощность цепи КАЖДОГО осталась той же.
			for i := 1; i <= 4; i++ {
				edge(obj, i, "scope_anc", fmt.Sprintf("n1-%d", i))
			}
		}
		var frontier []string
		for i := 1; i <= 4; i++ {
			frontier = append(frontier, fmt.Sprintf("n1-%d", i))
		}
		for level := 2; level <= 4; level++ {
			var next []string
			for _, node := range frontier {
				for i := 1; i <= 4; i++ {
					child := fmt.Sprintf("%s.%d", node, i)
					synthEdge("scope_anc", node, i, "scope_anc", child)
					next = append(next, child)
				}
			}
			frontier = next
		}
	default:
		t.Fatalf("форма цепи мощности %d не описана: точка сетки не имеет посева, и её "+
			"молчание неотличимо от исполненной", s)
	}
	must(t, sd.Flush(ctx))

	// Выдача — на самом объекте разрешения и на объекте отказа: без своей выдачи
	// объект отказа дал бы ДЕШЁВЫЙ отказ (пары «субъект+область» нет вовсе), и
	// ось мерила бы работу индекса, а не предикат правила.
	for _, obj := range []string{allow, deny} {
		must(t, sd.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE') ON CONFLICT DO NOTHING`,
			"acb-s-"+obj, strUserID, strRoleID, strModelType, obj))
		must(t, sd.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2) ON CONFLICT DO NOTHING`, "acb-s-"+obj, strUserID))
	}
	must(t, sd.Flush(ctx))
	f.seedL = 1
}

// analyze — СТАТИСТИКА СОБИРАЕТСЯ ВНУТРИ ПОСЕВА КАЖДОЙ ТОЧКИ.
//
// Не гигиена, а часть точки: измерено на соседнем приборе, что без неё оси
// расходятся на одной и той же фикстуре. Точка без статистики мерит ОТСУТСТВИЕ
// СТАТИСТИКИ, а не запрос.
func (f *strFixture) analyze(t *testing.T, ctx context.Context) {
	t.Helper()
	exec(t, ctx, f.tx, `ANALYZE kacho_iam.resource_mirror, kacho_iam.access_bindings,
		kacho_iam.access_binding_subjects, kacho_iam.relation_fact,
		kacho_iam.role_verb, kacho_iam.role_rule_selectors, kacho_iam.group_members`)
	exec(t, ctx, f.tx, `ANALYZE kacho_iam.resource_parent_edge`)
}

// seedPoint — привести фикстуру к точке.
func (f *strFixture) seedPoint(t *testing.T, ctx context.Context, p scalegrid.StrengthPoint) time.Duration {
	t.Helper()
	start := time.Now()
	share := 100
	if p.Axis == scalegrid.AxisPg {
		share = p.AllowedShare
	}
	f.growN(t, ctx, p.N, share)
	if p.Axis == scalegrid.AxisS {
		f.setScopeShape(t, ctx, p.S)
	}
	f.setM(t, ctx, p.M)
	f.setL(t, ctx, p.L)
	f.setK(t, ctx, p.K)
	f.analyze(t, ctx)
	return time.Since(start)
}

// ── ЗАМЕР ────────────────────────────────────────────────────────────────────

// askFor — вопрос, отвечающий режиму.
func (f *strFixture) askFor(mode scalegrid.AskMode) relverdict.Query {
	switch mode {
	case scalegrid.AskDenyLabel:
		return relverdict.Query{Subject: strSubject, ObjectType: strModelType,
			ObjectID: f.denyObj, Relation: strRelation}
	case scalegrid.AskDenyVerb:
		return relverdict.Query{Subject: strSubject, ObjectType: strModelType,
			ObjectID: f.allowObj, Relation: strDenyVerbRelation}
	default:
		return relverdict.Query{Subject: strSubject, ObjectType: strModelType,
			ObjectID: f.allowObj, Relation: strRelation}
	}
}

// measureAsk — один вопрос, снятый ТРЕМЯ приборами на одной фикстуре.
func measureAsk(t *testing.T, ctx context.Context, tx pgx.Tx, capture *verdictCapture,
	p scalegrid.StrengthPoint, q relverdict.Query, mode scalegrid.AskMode) askResult {
	t.Helper()
	res := askResult{mode: mode}

	before := tuplesRead(t, ctx, tx)
	capture.reset()
	verdict, _, err := relverdict.Ask(ctx, tx, q)
	after := tuplesRead(t, ctx, tx)
	if err != nil {
		t.Fatalf("вопрос %s в точке %s: %v", mode, p, err)
	}
	res.verdict = verdict.String()
	res.tuples = after - before
	res.calls = int64(capture.count())

	axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	stmts := capture.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("в точке %s (вопрос %s) захвачено %d операторов, тождественных запросу вердикта, "+
			"ожидался один: ноль означает, что продукт исполняет другой текст, больше одного — "+
			"что точка мерит два вопроса", p, mode, len(stmts))
	}
	stmt := stmts[0]

	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+stmt.sql, stmt.args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана в точке %s (вопрос %s): %v", p, mode, err)
	}
	m, err := planrows.Extract(raw, strWantRelations)
	if err != nil {
		t.Fatalf("прибор отказал в точке %s (вопрос %s): %v", p, mode, err)
	}
	res.rows, res.removed, res.touched = m.Rows, m.Removed, m.Touched
	res.loops = sumLoops(m)
	res.plan = planShape(raw)

	durs := make([]time.Duration, 0, strRepeats-1)
	for i := 0; i < strRepeats; i++ {
		t0 := time.Now()
		if _, _, err := relverdict.Ask(ctx, tx, q); err != nil {
			t.Fatalf("повтор вопроса %s в точке %s: %v", mode, p, err)
		}
		if i > 0 {
			durs = append(durs, time.Since(t0))
		}
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	res.p50, res.p99 = quantile(durs, 0.50), quantile(durs, 0.99)
	return res
}

// sumLoops — ЧИСЛО СКАНОВ: сумма циклов по отнесённым доступам плана.
//
// СО-НЕСУЩАЯ величина, и без неё половина отказных точек отчиталась бы нулём.
// Обращение по индексу, не нашедшее строки, отдаёт ноль и отбрасывает ноль: обе
// колонки — «строк» и «отброшено» — показывают ноль там, где работа сделана.
// Число сканов — единственное, что эту работу видит.
func sumLoops(m planrows.Measurement) int64 {
	var n int64
	for _, a := range m.Accesses {
		n += int64(a.Loops)
	}
	return n
}

// measureList — точка оси перечисления.
//
// Заходы считаются по ЗАХВАЧЕННЫМ операторам: `List` их не возвращает, а завести
// счётчик внутри него значило бы править прод-код ради прибора. Величина
// несущая: при доле доступных 0 % страница не наполняется никогда, и один вызов
// просматривает весь тип.
func measureList(t *testing.T, ctx context.Context, tx pgx.Tx, capture *verdictCapture,
	p scalegrid.StrengthPoint) askResult {
	t.Helper()
	res := askResult{mode: scalegrid.AskAllow}
	if p.AllowedShare == 0 {
		res.mode = scalegrid.AskDenyLabel
	}

	axis, err := relverdict.LabelAxisForTest(strCatalogType, strModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	listSQL := relverdict.ListQuerySQLForTest(axis)

	before := tuplesRead(t, ctx, tx)
	capture.reset()
	t0 := time.Now()
	ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
		Subject: strSubject, ObjectType: strModelType, Relation: strRelation, Limit: p.Pg,
	})
	elapsed := time.Since(t0)
	after := tuplesRead(t, ctx, tx)
	if err != nil {
		t.Fatalf("перечисление в точке %s: %v", p, err)
	}
	res.tuples = after - before
	res.calls = int64(capture.count())
	res.listed = len(ids)
	res.p50, res.p99 = elapsed, elapsed
	res.verdict = fmt.Sprintf("отдано %d", len(ids))

	sweeps := capture.matching(listSQL)
	res.sweeps = len(sweeps)
	if res.sweeps == 0 {
		t.Fatalf("в точке %s не захвачено ни одного захода перечисления: продукт исполняет "+
			"другой текст, и число заходов измерено быть не может", p)
	}
	// План снимается с ПЕРВОГО захода: последующие отличаются только курсором, а
	// суммировать планы разных заходов нельзя — это разные исполнения.
	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+sweeps[0].sql, sweeps[0].args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана перечисления в точке %s: %v", p, err)
	}
	m, err := planrows.Extract(raw, strWantRelations)
	if err != nil {
		t.Fatalf("прибор отказал на перечислении в точке %s: %v", p, err)
	}
	res.rows, res.removed, res.touched = m.Rows, m.Removed, m.Touched
	res.loops = sumLoops(m)
	res.plan = planShape(raw)
	res.scanned = res.sweeps * p.Pg
	return res
}

// measureStrengthPoint — точка целиком: три вопроса на одном посеве плюс перепись.
func measureStrengthPoint(t *testing.T, ctx context.Context, tx pgx.Tx, capture *verdictCapture,
	f *strFixture, p scalegrid.StrengthPoint) strPointResult {
	t.Helper()
	res := strPointResult{point: p}

	if p.Axis == scalegrid.AxisPg {
		res.asks = append(res.asks, measureList(t, ctx, tx, capture, p))
	} else {
		for _, mode := range scalegrid.AskModes() {
			res.asks = append(res.asks, measureAsk(t, ctx, tx, capture, p, f.askFor(mode), mode))
		}
	}

	census, err := scalegrid.TakeStrengthCensus(ctx, tx, scalegrid.StrengthCensusInput{
		Speakers:   strSpeakers,
		MemberType: "user", MemberID: strUserID,
		ScopeType: f.scopeType, ScopeID: f.scopeID,
		ObjectType: strModelType, ObjectID: f.allowObj,
		RoleID: strRoleID, MaxDepth: strMaxDepth,
	})
	if err != nil {
		t.Fatalf("перепись в точке %s: %v", p, err)
	}
	census.VerdictsAsked = int64(len(res.asks) * strRepeats)
	res.census = census
	if err := census.Verify(p); err != nil {
		t.Fatalf("%v", err)
	}
	return res
}

// runStrengthAxis — одна ось на СВОЕЙ базе.
//
// Своя база на ось, а не общая: оси держат РАЗНЫЕ величины неподвижными, и
// приращение между ними невозможно by construction.
func runStrengthAxis(t *testing.T, ctx context.Context, axis []scalegrid.StrengthPoint) []strPointResult {
	t.Helper()
	if len(axis) == 0 {
		return nil
	}
	tx, capture := openProbeTx(t, ctx)
	f := newStrFixture(t, ctx, tx)
	out := make([]strPointResult, 0, len(axis))
	for _, p := range axis {
		seedFor := f.seedPoint(t, ctx, p)
		r := measureStrengthPoint(t, ctx, tx, capture, f, p)
		r.seedIn = seedFor
		var parts []string
		for _, a := range r.asks {
			parts = append(parts, fmt.Sprintf("%s: строк %d, отброш. %d, тронуто %d, сканов %d, "+
				"обращ. %d, вердикт %s, p50 %s",
				a.mode, a.rows, a.removed, a.touched, a.loops, a.calls, a.verdict,
				a.p50.Round(time.Microsecond)))
		}
		t.Logf("точка %s: посев %s\n    %s", p, seedFor.Round(time.Millisecond),
			strings.Join(parts, "\n    "))
		out = append(out, r)
	}
	return out
}

// ── ПРОГОН ───────────────────────────────────────────────────────────────────

// TestStrengthGrid_Report — сетка предела прочности, РУЧНОЙ прогон.
//
// Переменная окружения решает, ЗАПУСКАТЬ ли прогон, и НИКОГДА — что мерить.
func TestStrengthGrid_Report(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if os.Getenv(strengthEnv) == "" {
		t.Skipf("сетка предела прочности идёт РУЧНЫМ прогоном: %s=1 go test -C services/iam "+
			"./internal/repo/kacho/pg/relverdict/ -run TestStrengthGrid_Report "+
			"-count=1 -v -timeout 120m", strengthEnv)
	}
	ctx := context.Background()
	grid := scalegrid.Strength()

	runCommand := fmt.Sprintf("%s=1 go test -C services/iam ./internal/repo/kacho/pg/relverdict/ "+
		"-run TestStrengthGrid_Report -count=1 -v -timeout 120m", strengthEnv)
	prov := scalegrid.TakeProvenance(runCommand, nil)
	// Сетка у этого прибора СВОЯ, и провенанс обязан назвать именно её: шапка,
	// напечатавшая соседнюю, описывала бы другой замер.
	prov.GridDigest = scalegrid.StrengthDigest(grid)
	prov.GridText = scalegrid.StrengthDescribe(grid)

	started := time.Now()
	results := make([][]strPointResult, 0, len(grid))
	for _, axis := range grid {
		axisStart := time.Now()
		results = append(results, runStrengthAxis(t, ctx, axis))
		t.Logf("ось %s прогнана за %s", axis[0].Axis, time.Since(axisStart).Round(time.Second))
		// Отчёт пишется ПОСЛЕ КАЖДОЙ ОСИ, а не в конце: если дорогая ось
		// сорвётся, дешёвые уже сняты и предъявлены файлом. Прежний порядок
		// («всё разом в конце») отдавал за срыв последней оси весь прогон.
		writeStrengthReport(t, prov, grid, results, time.Since(started), false)
	}
	prov.Postgres = postgresVersion(t, ctx)
	writeStrengthReport(t, prov, grid, results, time.Since(started), true)
}

// writeStrengthReport — отчёт файлом дерева, а не выводом прогона: иначе число
// нельзя оспорить.
func writeStrengthReport(t *testing.T, prov scalegrid.Provenance, grid [][]scalegrid.StrengthPoint,
	results [][]strPointResult, wall time.Duration, final bool) {
	t.Helper()
	title := "R7-2 — ПРЕДЕЛ ПРОЧНОСТИ: ЧТЕНИЕ (рамка A, реляционный вердикт)\n" +
		"Сетка пяти новых осей; КАЖДАЯ точка снята ТРЕМЯ вопросами на одном посеве."
	if !final {
		title += "\nПРОМЕЖУТОЧНЫЙ СРЕЗ: прогон не окончен, оси ниже ещё не сняты."
	}
	header, err := prov.Header(title)
	if err != nil {
		t.Fatalf("шапка отчёта: %v", err)
	}
	body := renderStrengthReport(grid, results, wall, final)
	path, err := scalegrid.AbsPathOf(scalegrid.StrengthReportPath)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, []byte(header+body), 0o644); err != nil {
		t.Fatalf("запись отчёта: %v", err)
	}
	if final {
		t.Logf("отчёт записан: %s\n\n%s%s", path, header, body)
	}
}

func renderStrengthReport(grid [][]scalegrid.StrengthPoint, results [][]strPointResult,
	wall time.Duration, final bool) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("ТРИ УТВЕРЖДЕНИЯ, КОТОРЫЕ ЭТОТ ОТЧЁТ НЕСЁТ ДОСЛОВНО\n")
	w("  1. Числа описывают путь, который СЕГОДНЯ И ПРИНИМАЕТ РЕШЕНИЕ О ДОСТУПЕ.\n")
	w("     Внешнего движка отношений в продукте НЕТ — он снят стадией S6 эпика\n")
	w("     #747, — и теневого сравнителя рядом с ним нет тоже: вердикт вычисляется\n")
	w("     в своей базе, и эта форма провязана в композиционном корне сервиса.\n")
	w("     Складывать эти числа со стоимостью движка больше не с чем: второго\n")
	w("     слагаемого не существует. Предел у них остаётся один, и он честный:\n")
	w("     это фикстура прибора на одной машине, а не продуктовый трафик, и время\n")
	w("     здесь вердикта не выносит — несущая величина строки.\n")
	w("  2. Точки, помеченные «*», описывают состояние, которое продукт объявил\n")
	w("     невозможным (умолчания пределов, миграция 0094) ЛИБО не проверяет вовсе\n")
	w("     (форма цепи областей). Пределы объявлены и НЕ ЭНФОРСЯТСЯ: таблицы учёта\n")
	w("     для видов iam в дереве нет, обращений к пределам в use-cases нет.\n")
	w("     «Потолок продукта», взятый с такой точки, — число про непризнанное состояние.\n")
	w("  3. Ноль отказов, ноль осмотренного, ноль исполненных точек — ТРЕТИЙ исход,\n")
	w("     а не успех. Объём осмотренного печатается всегда.\n")

	w("\nЧЕМ СНЯТА КАЖДАЯ КОЛОНКА (единицы не складываются между собой)\n")
	w("  строк      — Actual Rows × Actual Loops листовых узлов плана (pg/planrows)\n")
	w("  отброш.    — Rows Removed by Filter/Index Recheck/Join Filter, тем же прибором\n")
	w("  тронуто    — строк + отброш. НА ОТКАЗНЫХ ВОПРОСАХ ВЕРДИКТ ВЫНОСИТСЯ ПО НЕЙ:\n")
	w("               отвергнутая строка прочитана ровно так же, как принятая\n")
	w("  сканов     — сумма Actual Loops отнесённых узлов. СО-НЕСУЩАЯ: обращение по\n")
	w("               индексу, не нашедшее строки, даёт ноль и в «строк», и в «отброш.»,\n")
	w("               и без этой колонки сделанная работа была бы невидима\n")
	w("  сверочная  — pg_stat_xact_all_tables (seq_tup_read + idx_tup_fetch)\n")
	w("  обращ.     — круговых обращений к БД на один вопрос, трассировщиком pgx\n")
	w("  p50/p99    — часы; нулевой повтор прогревочный и в выборку не входит\n")

	for ai, axis := range results {
		if len(axis) == 0 {
			continue
		}
		name := string(axis[0].point.Axis)
		w("\n\nОСЬ %s — %s\n%s\n", name, strengthAxisTitle(axis[0].point.Axis), strings.Repeat("-", 78))

		if axis[0].point.Axis == scalegrid.AxisPg {
			renderListAxis(&b, axis)
		} else {
			renderVerdictAxis(&b, axis)
		}

		w("\n  ПЕРЕПИСЬ ПОСАЖЕННОГО в верхней точке (по каждой величине порознь, счётом по факту):\n")
		w("%s", axis[len(axis)-1].census.String())
		_ = ai
	}

	w("\n\nОБЪЁМ ОСМОТРЕННОГО\n")
	points, asks := 0, 0
	for _, axis := range results {
		points += len(axis)
		for _, r := range axis {
			asks += len(r.asks)
		}
	}
	w("  осей исполнено %d из %d, точек %d, вопросов задано %d (по %d повторов на вопрос),\n",
		len(results), len(grid), points, asks, strRepeats)
	w("  настенное время %s\n", wall.Round(time.Second))
	if !final {
		w("\n  ПРОГОН НЕ ОКОНЧЕН: оси ниже исполненных не сняты. Это ТРЕТИЙ исход по ним,\n")
		w("  а не «величина не выросла».\n")
	}
	if points == 0 {
		w("\n  ТОЧЕК ИСПОЛНЕНО НОЛЬ — отчёт беспредметен, и его молчание не является замером.\n")
	}
	return b.String()
}

func strengthAxisTitle(a scalegrid.Axis) string {
	switch a {
	case scalegrid.AxisV:
		return "ИСХОД ВЕРДИКТА против размера облака (варьируется N)"
	case scalegrid.AxisM:
		return "ЧЛЕНСТВ СПРАШИВАЮЩЕГО (входит в обе ветви запроса разом)"
	case scalegrid.AxisL:
		return "СТРОК (говорящий, область) в access_binding_subjects"
	case scalegrid.AxisS:
		return "МОЩНОСТЬ ЦЕПИ ОБЛАСТЕЙ в строках CTE scope"
	case scalegrid.AxisK:
		return "ПРАВИЛ РОЛИ, накрывших объект"
	case scalegrid.AxisPg:
		return "СТРАНИЦА ПЕРЕЧИСЛЕНИЯ × доля доступных"
	}
	return string(a)
}

func renderVerdictAxis(b *strings.Builder, axis []strPointResult) {
	w := func(f string, a ...any) { fmt.Fprintf(b, f, a...) }
	for _, mode := range scalegrid.AskModes() {
		w("\n  вопрос %s\n", mode)
		w("  %-9s %8s %9s %9s %8s %10s %6s %10s %10s %-8s\n",
			"значение", "строк", "отброш.", "тронуто", "сканов", "сверочная", "обращ.", "p50", "p99", "вердикт")
		for _, r := range axis {
			a := r.ask(mode)
			mark := ""
			if r.point.Seeded {
				mark = "*"
			}
			w("  %-9s %8d %9d %9d %8d %10d %6d %10s %10s %-8s\n",
				fmt.Sprintf("%d%s", r.point.Value(), mark),
				a.rows, a.removed, a.touched, a.loops, a.tuples, a.calls,
				a.p50.Round(time.Microsecond), a.p99.Round(time.Microsecond), a.verdict)
		}
		lo, hi := axis[0].ask(mode), axis[len(axis)-1].ask(mode)
		w("    отношение верхней к нижней: тронуто %s · сканов %s\n",
			ratioText(hi.touched, lo.touched), ratioText(hi.loops, lo.loops))
	}
	w("\n  ДЕЛЬТА ОТКАЗА (цена недочитанного): «тронуто» на deny(правило) минус на allow\n")
	w("  %-9s %12s %12s %12s %14s\n", "значение", "allow", "deny(правило)", "дельта", "во сколько раз")
	for _, r := range axis {
		al, dn := r.ask(scalegrid.AskAllow), r.ask(scalegrid.AskDenyLabel)
		w("  %-9d %12d %12d %+12d %14s\n",
			r.point.Value(), al.touched, dn.touched, dn.touched-al.touched,
			ratioText(dn.touched, al.touched))
	}
	w("\n  КОНТРОЛЬ ДЕШЁВОГО ОТКАЗА: ddeny(глагол) обязан быть ДЕШЕВЛЕ deny(правило).\n")
	w("  Без него отчёт сказал бы «отказ дёшев» — и это была бы правда про фикстуру.\n")
	w("  %-9s %14s %14s\n", "значение", "deny(глагол)", "deny(правило)")
	for _, r := range axis {
		w("  %-9d %14d %14d\n", r.point.Value(),
			r.ask(scalegrid.AskDenyVerb).touched, r.ask(scalegrid.AskDenyLabel).touched)
	}
	w("\n  план по точкам (отношение двух приборов читается ТОЛЬКО внутри одного плана):\n")
	for _, r := range axis {
		w("    %-9d allow [%s]\n", r.point.Value(), r.ask(scalegrid.AskAllow).plan)
		w("    %-9s deny  [%s]\n", "", r.ask(scalegrid.AskDenyLabel).plan)
	}
}

func renderListAxis(b *strings.Builder, axis []strPointResult) {
	w := func(f string, a ...any) { fmt.Fprintf(b, f, a...) }
	w("\n  ЗАХОД — НЕ ВЫЗОВ. `List` повторяет заход, пока страница не наполнится ЛИБО\n")
	w("  кандидаты типа не кончатся. При доле доступных 0 %% страница не наполняется\n")
	w("  никогда, и ОДИН вызов просматривает ВЕСЬ тип. Колонка «заходов» — несущая.\n\n")
	w("  %-7s %-9s %8s %8s %10s %9s %9s %10s %12s\n",
		"стр.", "доступно", "заходов", "отдано", "осмотрено<=", "строк*", "тронуто*", "сверочная", "время вызова")
	for _, r := range axis {
		a := r.ask(scalegrid.AskAllow)
		if a.sweeps == 0 {
			a = r.ask(scalegrid.AskDenyLabel)
		}
		mark := ""
		if r.point.Seeded {
			mark = "*"
		}
		w("  %-7s %-9s %8d %8d %10d %9d %9d %10d %12s\n",
			fmt.Sprintf("%d%s", r.point.Pg, mark), fmt.Sprintf("%d%%", r.point.AllowedShare),
			a.sweeps, a.listed, a.scanned, a.rows, a.touched, a.tuples,
			a.p50.Round(time.Millisecond))
	}
	w("\n  «строк*» и «тронуто*» сняты с ПЕРВОГО захода: суммировать планы разных заходов\n")
	w("  нельзя — это разные исполнения. Стоимость ВЫЗОВА читается по «заходов» × «строк*».\n")
	w("  Колонка «осмотрено<=» — ВЕРХНЯЯ ОЦЕНКА (заходов × страница): последний заход\n")
	w("  бывает неполон, а числа осмотренных кандидатов `List` наружу не отдаёт вовсе.\n")
	w("  Точка 5000 помечена «*» и как СВЕРХ КОНТРАКТА: у `List` верхнего предела нет\n")
	w("  вовсе, а контрактный потолок 1000 живёт в другом месте — то есть край сегодня\n")
	w("  этот размер страницы не отвергает.\n")
}

// ratioText — отношение с честным отказом на нуле.
//
// Ноль в знаменателе не даёт бесконечности и не даёт единицы: он означает, что
// сравнивать не с чем, и это надо сказать, а не подставить величину.
func ratioText(hi, lo int64) string {
	if lo == 0 {
		return fmt.Sprintf("нижняя точка 0 — отношение не определено (верхняя %d)", hi)
	}
	return fmt.Sprintf("%.2f×", float64(hi)/float64(lo))
}

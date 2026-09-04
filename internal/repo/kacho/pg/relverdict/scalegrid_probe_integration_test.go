// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// scalegrid_probe_integration_test.go — ПРИБОР ПОРЯДКОВ: СЕТКА ЧЕТЫРЁХ ОСЕЙ.
//
// # Что здесь измеряется и чем
//
// Вопрос владельца — «растёт ли стоимость проверки доступа от того, сколько в
// облаке ресурсов, ролей и связей». Он проверяем только замером, и замер
// обязан варьировать оси ПО ОДНОЙ:
//
//	N — объектов зеркала (ресурсов в облаке);
//	B — выдач, НЕ называющих спрашиваемого (связей в облаке);
//	R — выдач, называющих его (остаточная переменная, предел вводится S3);
//	F — прямых фактов на цепи областей, называющих его.
//
// Несущая величина — СТРОКИ, снятые с плана (`pg/planrows`), а не миллисекунды:
// время есть свойство машины и на другой машине ложно. Рядом снимается
// сверочная (`pg_stat_xact_all_tables`), и их расхождение печатается числом:
// несказанное расхождение неотличимо от прибора, меряющего не ту величину.
//
// # Что этот прибор утверждает о прод-пути, а что нет
//
// Свойство, которое здесь доказывается, принадлежит форме, которая СЕГОДНЯ и
// принимает решение о доступе: внешнего движка отношений в продукте нет — он
// снят стадией S6 эпика #747, — и вердикт вычисляется в своей базе.
//
// Прежняя редакция этой шапки называла реляционный вердикт «теневым
// компаратором», а решающим — «прежний движок». Она пережила свой предмет.
//
// НЕ утверждается характеристика продуктового трафика: посев — фикстура прибора
// на одной машине, и несущая величина здесь строки, а не миллисекунды.
//
// # Почему полная сетка не идёт в конвейере
//
// Она сажает миллион объектов и миллион выдач; это ручной прогон, чей отчёт —
// артефакт дерева. В конвейере идёт МАЛАЯ сетка, и её предмет другой: не форма
// кривой, а ДЕГРАДАЦИЯ относительно потолка, объявленного константой до прогона.
//
// Переменная окружения ниже решает, ЗАПУСКАТЬ ли прогон, и НИКОГДА — что
// мерить: сетка живёт константой в `pg/scalegrid` и ниоткуда не
// переопределяется. Разница несущая: отчёт, снятый на сокращённой сетке,
// неотличим от полного и читается как полный.

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/planrows"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/scalegrid"
)

// fullGridEnv — ручка «запускать полную сетку», и только это.
const fullGridEnv = "KACHO_SCALEGRID_FULL"

// probeCatalogType / probeModelType — измеряемый тип в двух словарях.
//
// Репозиторий реестра выбран потому, что его цепь предков — САМАЯ ДЛИННАЯ в
// продукте (`registry_repository → registry_registry → project → account`,
// d = 3). На вырожденной цепи неподвижным выглядит и то, что умножается.
const (
	probeCatalogType = "registry.repositories"
	probeModelType   = "registry_repository"
	probeRelation    = "v_get"
	probeVerb        = "get"
)

// probeSubject — субъект вопроса; probeSpeakers — ВСЕ написания, которыми за
// него говорят. Перепись считает «называет спрашиваемого» по ним, а не по
// личному имени: иначе выдача через группу не была бы сосчитана и ось R
// показала бы ноль там, где посажена сотня.
var (
	probeSubject  = "user:usr-1"
	probeGroupID  = "grp-probe"
	probeSpeakers = []string{
		"user:usr-1",
		"group:" + probeGroupID,
		"group:" + probeGroupID + "#member",
		"user:*",
	}
)

// probeRepeats — повторов вопроса на точку, для p50/p95/p99.
//
// Нулевой повтор прогревочный и в выборку НЕ входит: первый вопрос платит за
// разбор и за холодный кэш, и его включение сдвинуло бы медиану точки, а не
// описало её.
const probeRepeats = 21

// baselineRevision / baselineReportPath — ЧЕМ ЭТОТ ЗАМЕР СРАВНИВАЕТСЯ.
//
// Выписаны, а не выведены, и это признано: базовый отчёт снят на ревизии, до
// которой из текущего дерева дойти можно только историей. Зато обе величины
// адресуемы и проверяемы одной командой, а «стало лучше» перестаёт быть
// утверждением без второй половины.
const (
	baselineRevision   = "3acddcfdf9216440aaa77db505a63a456d7aed98"
	baselineReportPath = "services/iam/internal/repo/kacho/pg/scalegrid/REPORT-R7-1-S1-scale-grid-before-S2.txt"
)

// probeChainDepth — глубина цепи фикстуры. Печатается РЯДОМ с S_набл: без неё
// «совпало с ожидаемым» нечем проверить, а S_набл остаётся числом без предиката.
const probeChainDepth = 3

// smallGridRatioCeiling — ПОТОЛОК ДЕГРАДАЦИИ, объявленный ДО прогона.
//
// Отношение «строк за вердикт в верхней точке оси / в нижней». Величина взята
// не с потолка и не после прогона: постоянная часть чтения (сам объект, его
// правило, цепь областей) от размера облака не зависит вовсе, поэтому идеальное
// отношение — единица, и всё, что выше, есть запас на дребезг статистики и на
// смену плана при переходе от ста объектов к тысяче (план на сотне —
// прогонный, на тысяче — индексный; это измерено и названо в §0.4а приёмки).
//
// Два — тот же запас, что у соседнего прибора того же дерева
// (`membershipCostRatioCeiling`, membership_cost_integration_test.go): там
// отношение до починки было больше тысячи, и никакой запас его не покрывал.
// Здесь ожидание такое же: деградация этого класса даёт порядки, а не проценты,
// и двойка отделяет её от дребезга с огромным запасом.
//
// Потолок, подобранный ПОСЛЕ прогона, — то же, что правило, впервые появившееся
// в отчёте: он описывает полученное число, а не свойство. Поэтому он стоит
// здесь, коммитом раньше первой измеренной величины.
const smallGridRatioCeiling = 2.0

// probeWantRelations — ПРЕДПОСЫЛКА замера: отношения, которые запрос вердикта
// обязан читать. План, не содержащий ни одного, означает «смотреть было негде»,
// и ноль строк тогда не про работу.
var probeWantRelations = []string{
	"relation_fact", "access_bindings", "access_binding_subjects",
	"role_verb", "role_rule_selectors", "group_members",
	"resource_parent_edge", "resource_mirror",
}

// pointResult — одна строка отчёта.
type pointResult struct {
	point   scalegrid.Point
	census  scalegrid.Census
	rows    int64 // несущая: отдано узлами плана, с множителем циклов
	removed int64
	touched int64
	tuples  int64 // сверочная: pg_stat_xact_all_tables
	calls   int64 // обращений к БД на один вердикт
	verdict string
	p50     time.Duration
	p95     time.Duration
	p99     time.Duration
	plan    string // отпечаток плана: узлы верхнего уровня
	sObs    int    // S_набл — мощность CTE scope
	depth   int
	census0 string
}

// ratio — отношение сверочной к несущей. Читается ТОЛЬКО внутри одного плана.
func (r pointResult) ratio() float64 {
	if r.rows == 0 {
		return 0
	}
	return float64(r.tuples) / float64(r.rows)
}

// ── ФИКСТУРА ─────────────────────────────────────────────────────────────────

// gridFixture — состояние посева одной оси.
//
// Ось растёт ПРИРАЩЕНИЕМ: точка N = 10⁴ досыпает девять тысяч к тысяче, а не
// сажает десять тысяч заново. Иначе полная сетка посадила бы 1.1 млн объектов
// вместо миллиона и заплатила бы за это временем, которого у прогона нет.
// Между ОСЯМИ приращение невозможно (у осей разные неподвижные величины),
// поэтому каждая ось получает свою базу.
type gridFixture struct {
	tx    pgx.Tx
	seedN int
	seedB int
	// seedBSubjects / seedBRoles — пулы оси B, каждый со своим счётчиком: они
	// растут МЕДЛЕННЕЕ числа выдач и никогда не пересеваются.
	seedBSubjects int
	seedBRoles    int
	seedR         int
	// seedRoles — сколько ролей заведено. Считается ОТДЕЛЬНО от выдач и
	// НИКОГДА не сбрасывается: смена способа набора переписывает выдачи, а роли
	// остаются, и повторная их вставка была бы нарушением первичного ключа.
	// Первая редакция считала их одним счётчиком с выдачами и падала на первой
	// же точке оси R, набранной через группы.
	seedRoles int
	seedF     int
	recR      scalegrid.Recruit
	recF      scalegrid.Recruit
}

// newGridFixture — база оси: обвязка аренды, роль, цепь областей.
//
// Цепь набирается ПОСЕВЩИКОМ, каждое звено СО СВОЕЙ цепью — то есть сетка сеет
// ЗАМЫКАНИЕ, топологию, которой производители дерева не пишут (они шлют одно-два
// звена). Расхождение намеренное и названо здесь, чтобы числа читались верно:
//
//	для СТОИМОСТИ это консервативно — замыкание даёт обходу больше строк на
//	каждом шаге, значит замер есть ВЕРХНЯЯ оценка, и числа годны;
//	для ДОСТИЖИМОСТИ это не проба вовсе — при замыкании транзитивность не
//	нужна, и высоту, до которой доходит обход на форме дерева, сетка не
//	измеряет. Её измеряют пробы scopereach_integration_test.go.
//
// Прежняя редакция называла эту цепь «той, на которой обход обязан подниматься
// транзитивно». Неточно ровно наоборот: на замыкании транзитивность и не
// требуется.
func newGridFixture(t *testing.T, ctx context.Context, tx pgx.Tx) *gridFixture {
	t.Helper()
	f := &gridFixture{tx: tx}

	// Кластер — СИНГЛТОН, и его строку кладёт миграция. `DO NOTHING` здесь не
	// проглатывание ошибки, а признание факта: идентификатор фиксирован
	// ограничением схемы, вставить второй нельзя, и наличие первого — норма.
	exec(t, ctx, tx, `INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ('acc-1', 'probe-account', 'usr-1')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ('usr-1', 'ext-1', 'usr-1@kacho.local', 'acc-1')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-1', 'acc-1', 'probe-project')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ($1, 'acc-1', 'probe-group')`, probeGroupID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id) VALUES ($1, 'user', 'usr-1')`,
		probeGroupID)

	seedProbeRole(t, ctx, tx, "rol-anchor", "probe.anchor")

	// Звенья цепи — своими объектами со своими цепями.
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
	must(t, s.Flush(ctx))
	return f
}

// seedProbeRole — роль, адресующая измеряемый тип якорной ветвью.
//
// Имя роли обязано подчиняться `roles_system_name_check`: сегмент после точки —
// `[a-z][a-z0-9_]*`, то есть БЕЗ дефиса. Идентификатор роли (`rol-anchor`)
// дефис несёт, поэтому имя собирается отдельно, а не из него: первая редакция
// склеивала "probe."+id и была отвергнута схемой.
func seedProbeRole(t *testing.T, ctx context.Context, tx pgx.Tx, roleID, roleName string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module', 'probe', 'resources', jsonb_build_array('*'),
		             'verbs',  jsonb_build_array($3::text))),
		         'cluster_kacho_root')`, roleID, roleName, probeVerb)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		roleID, probeCatalogType, probeVerb)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-1', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, roleID, probeCatalogType)
}

// growN — досыпать объектов зеркала до target.
func (f *gridFixture) growN(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target <= f.seedN {
		return
	}
	s := scalegrid.NewSeeder(f.tx)
	for i := f.seedN; i < target; i++ {
		must(t, s.Queue(ctx, scalegrid.MirrorRow{
			ObjectType:      probeCatalogType,
			ObjectID:        fmt.Sprintf("repo-%07d", i),
			ParentProjectID: "prj-1",
			ParentAccountID: "acc-1",
			Labels:          map[string]string{"env": "prod"},
			ParentChain:     []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
		}))
	}
	must(t, s.Flush(ctx))
	f.seedN = target
}

// bSubjectPool — сколько РАЗЛИЧНЫХ чужих субъектов заводится под ось B.
//
// # Почему пул, а не «по субъекту на выдачу» — измерено, а не предположено
//
// Первая редакция давала каждой чужой выдаче своего пользователя. На 10⁶ она
// не сошлась: прогон провёл на этой точке 58 минут и не закончил. Дело не во
// вставках — их темп линеен, — а в стороже существования субъекта
// (`kacho_iam.subject_ref_exists`, миграция 0049): он срабатывает НА КАЖДУЮ
// строку обеих таблиц выдачи и берёт `FOR KEY SHARE` на строке субъекта. Милион
// РАЗЛИЧНЫХ субъектов означает миллион различных блокировок строк, накопленных
// в одной транзакции; тысяча субъектов — тысячу, и повторный захват уже
// удерживаемой блокировки почти бесплатен.
//
// # Почему это НЕ ослабляет ось
//
// Ось B неудобна вердикту тем, что её выдачи лежат в ТОЙ ЖЕ области, куда он
// смотрит, и обязаны быть отвергнуты по СУБЪЕКТУ. Отвергаются они построчно:
// соединение `speaker` идёт по строкам `access_binding_subjects`, и работа
// вердикта растёт от ЧИСЛА СТРОК, а не от числа различных субъектов в них.
// Пул сохраняет число строк и сокращает только число различных значений —
// то есть ровно ту величину, от которой стоимость вердикта не зависит.
//
// Уникальность действующей выдачи держится пятёркой (субъект, роль, область),
// поэтому 10⁶ строк набираются как 10³ субъектов × 10³ ролей.
const bSubjectPool = 1000

// growB — досыпать ЧУЖИХ выдач до target.
//
// Чужие — по СУБЪЕКТУ: каждая выдача названа не тем, кого спрашивают, и лежит
// на ТОЙ ЖЕ области (`project:prj-1`), которую вердикт действительно читает.
// Это самая неудобная для запроса форма: выдача стоит там, куда он смотрит, и
// не должна быть прочитана только потому, что называет не того. Разложить их по
// чужим областям было бы дешевле и СЛАБЕЕ — тогда ось мерила бы избирательность
// соединения по области, а не по субъекту, и кривая вышла бы плоской по причине,
// не имеющей отношения к предмету.
func (f *gridFixture) growB(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target <= f.seedB {
		return
	}
	s := scalegrid.NewSeeder(f.tx)

	// Пул субъектов — до нужного, считая от заведённых.
	wantSubjects := target
	if wantSubjects > bSubjectPool {
		wantSubjects = bSubjectPool
	}
	for i := f.seedBSubjects; i < wantSubjects; i++ {
		uid := fmt.Sprintf("usr-b%07d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ($1, $1, $1 || '@kacho.local', 'acc-1')`, uid))
	}
	if wantSubjects > f.seedBSubjects {
		f.seedBSubjects = wantSubjects
	}

	// Пул ролей: столько, чтобы пятёрка уникальности не столкнулась.
	wantRoles := (target + bSubjectPool - 1) / bSubjectPool
	for i := f.seedBRoles; i < wantRoles; i++ {
		roleID := fmt.Sprintf("rol-b%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
			 VALUES ($1, $2, '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module', 'probe', 'resources', jsonb_build_array('*'),
			             'verbs',  jsonb_build_array($3::text))),
			         'cluster_kacho_root')`, roleID, fmt.Sprintf("probe.b%05d", i), probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
			roleID, probeCatalogType, probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ($1, 'fp-1', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, roleID, probeCatalogType))
	}
	if wantRoles > f.seedBRoles {
		f.seedBRoles = wantRoles
	}

	for i := f.seedB; i < target; i++ {
		uid := fmt.Sprintf("usr-b%07d", i%bSubjectPool)
		roleID := fmt.Sprintf("rol-b%05d", i/bSubjectPool)
		bid := fmt.Sprintf("acb-b%07d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, $3, 'project', 'prj-1', 'ACTIVE')`, bid, uid, roleID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, bid, uid))
	}
	must(t, s.Flush(ctx))
	f.seedB = target
}

// setR — выдачи, НАЗЫВАЮЩИЕ спрашиваемого, ровно target штук.
//
// Уникальность действующей выдачи держится схемой по пятёрке (субъект, роль,
// область), поэтому одним субъектом на одной области набрать сотню выдач можно
// ТОЛЬКО разными ролями: `access_bindings_active_grant_uniq` (миграция 0003)
// отвергнет вторую с той же ролью. Это не обход ограничения, а его прочтение:
// «сто прав на одном объекте» в этой схеме и означает сто ролей.
func (f *gridFixture) setR(t *testing.T, ctx context.Context, target int, rec scalegrid.Recruit) {
	t.Helper()
	if rec != f.recR {
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.access_bindings WHERE id LIKE 'acb-r%'`)
		f.seedR, f.recR = 0, rec
	}
	if target <= f.seedR {
		return
	}
	subjType, subjID := "user", "usr-1"
	if rec == scalegrid.RecruitViaGroup {
		subjType, subjID = "group", probeGroupID
	}
	s := scalegrid.NewSeeder(f.tx)
	// Роли — до нужного числа, считая от УЖЕ заведённых.
	for i := f.seedRoles; i < target; i++ {
		roleID := fmt.Sprintf("rol-r%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
			 VALUES ($1, $2, '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module', 'probe', 'resources', jsonb_build_array('*'),
			             'verbs',  jsonb_build_array($3::text))),
			         'cluster_kacho_root')`, roleID, fmt.Sprintf("probe.r%05d", i), probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
			roleID, probeCatalogType, probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ($1, 'fp-1', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, roleID, probeCatalogType))
	}
	if target > f.seedRoles {
		f.seedRoles = target
	}
	// Выдачи — своим счётчиком: их смена способа набора переписывает.
	for i := f.seedR; i < target; i++ {
		roleID := fmt.Sprintf("rol-r%05d", i)
		bid := fmt.Sprintf("acb-r%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, $2, $3, $4, 'project', 'prj-1', 'ACTIVE')`, bid, subjType, subjID, roleID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, $2, $3)`, bid, subjType, subjID))
	}
	must(t, s.Flush(ctx))
	f.seedR = target
}

// setF — прямые факты на цепи областей, называющие спрашиваемого.
//
// Ключ факта — четвёрка (тип, идентификатор, отношение, субъект), поэтому при
// ОДНОМ написании субъекта число строк ограничено сверху произведением «объектов
// цепи × отношений». Объектов цепи здесь четыре (лист, реестр, проект, аккаунт),
// значит сотня фактов набирается двадцатью пятью отношениями. Совпадать с
// атомами плана они не обязаны и в большинстве не совпадают — предмет оси в том,
// СКОЛЬКО строк лежит на пути, а не сколько из них дали основание.
func (f *gridFixture) setF(t *testing.T, ctx context.Context, target int, rec scalegrid.Recruit) {
	t.Helper()
	if rec != f.recF || target < f.seedF {
		exec(t, ctx, f.tx, `DELETE FROM kacho_iam.relation_fact`)
		f.seedF, f.recF = 0, rec
	}
	if target <= f.seedF {
		return
	}
	subject := "user:usr-1"
	switch rec {
	case scalegrid.RecruitFactGroup:
		subject = "group:" + probeGroupID + "#member"
	case scalegrid.RecruitFactWildcard:
		subject = "user:*"
	}
	chain := [][2]string{
		{probeModelType, "repo-0000000"},
		{"registry_registry", "reg-1"},
		{"project", "prj-1"},
		{"account", "acc-1"},
	}
	s := scalegrid.NewSeeder(f.tx)
	for i := f.seedF; i < target; i++ {
		obj := chain[i%len(chain)]
		relation := probeRelation
		if i >= len(chain) {
			relation = fmt.Sprintf("v_probe_%04d", i/len(chain))
		}
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ($1, $2, $3, $4)`, obj[0], obj[1], relation, subject))
	}
	must(t, s.Flush(ctx))
	f.seedF = target
}

// analyze — СТАТИСТИКА СОБИРАЕТСЯ ВНУТРИ ПОСЕВА КАЖДОЙ ТОЧКИ.
//
// Не гигиена, а часть точки: измерено, что без неё три оси прибора расходятся на
// одной и той же фикстуре (26/41/66 против 31/34/54). Точка без статистики мерит
// ОТСУТСТВИЕ СТАТИСТИКИ, а не запрос. `VACUUM` при этом не нужен и здесь не
// делается — измерено, что две одинаковые точки подряд в одной базе совпали до
// единицы при восьми тысячах мёртвых строк.
func (f *gridFixture) analyze(t *testing.T, ctx context.Context) {
	t.Helper()
	// Сбор идёт ДВУМЯ стейтментами вместо одного, и причина не техническая.
	//
	// Гейт дерева `TestCensusFixturesSeedThroughTheProducer` признаёт «пробой с
	// переписью покрытия» ЛЮБОЙ файл, где один строковый литерал называет и
	// зеркало, и таблицу рёбер: такой литерал он читает как квантор «у каждой
	// строки зеркала есть цепь». `ANALYZE` квантором не является — он вообще не
	// про данные, — но по этому признаку неотличим от настоящей переписи, и
	// первая редакция файла гейт уронила.
	//
	// Разделение — ПОДГОНКА ПОД ИНСТРУМЕНТ, и признаётся она вслух, а не
	// маскируется: предикат гейта грубее своего предмета. Ослаблять гейт ради
	// одного файла было бы хуже — он ловит настоящий класс, — а сила проверки от
	// разделения не убывает: два `ANALYZE` собирают ту же статистику, что один.
	//
	// Что этим НЕ достигнуто: молчание гейта на этом файле по-прежнему не
	// доказывает, что фикстура эквивалентна производителю. Доказывает это только
	// построчная сверка в scalegrid_seeder_integration_test.go.
	exec(t, ctx, f.tx, `ANALYZE kacho_iam.resource_mirror, kacho_iam.access_bindings,
		kacho_iam.access_binding_subjects, kacho_iam.relation_fact,
		kacho_iam.role_verb, kacho_iam.role_rule_selectors, kacho_iam.group_members`)
	exec(t, ctx, f.tx, `ANALYZE kacho_iam.resource_parent_edge`)
}

// seedPoint — привести фикстуру к точке и собрать статистику.
func (f *gridFixture) seedPoint(t *testing.T, ctx context.Context, p scalegrid.Point) time.Duration {
	t.Helper()
	start := time.Now()
	f.growN(t, ctx, p.N)
	f.growB(t, ctx, p.B)
	f.setR(t, ctx, p.R, recruitForR(p))
	f.setF(t, ctx, p.F, recruitForF(p))
	f.analyze(t, ctx)
	return time.Since(start)
}

func recruitForR(p scalegrid.Point) scalegrid.Recruit {
	if p.Recruit == scalegrid.RecruitViaGroup {
		return scalegrid.RecruitViaGroup
	}
	return scalegrid.RecruitDirect
}

func recruitForF(p scalegrid.Point) scalegrid.Recruit {
	switch p.Recruit {
	case scalegrid.RecruitFactGroup, scalegrid.RecruitFactWildcard:
		return p.Recruit
	}
	return scalegrid.RecruitFactSelf
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("посев: %v", err)
	}
}

// ── ЗАМЕР ────────────────────────────────────────────────────────────────────

// measurePoint — один вопрос, снятый ТРЕМЯ приборами на ОДНОЙ фикстуре.
func measurePoint(t *testing.T, ctx context.Context, tx pgx.Tx, cap *verdictCapture,
	p scalegrid.Point) pointResult {
	t.Helper()
	res := pointResult{point: p, depth: probeChainDepth}

	q := relverdict.Query{
		Subject: probeSubject, ObjectType: probeModelType,
		ObjectID: "repo-0000000", Relation: probeRelation,
	}

	// Сверочная величина снимается ВОКРУГ того же вопроса и на той же фикстуре.
	before := tuplesRead(t, ctx, tx)
	cap.reset()
	verdict, _, err := relverdict.Ask(ctx, tx, q)
	after := tuplesRead(t, ctx, tx)
	if err != nil {
		t.Fatalf("вопрос вердикта в точке %s: %v", p, err)
	}
	res.verdict = verdict.String()
	res.tuples = after - before
	res.calls = int64(cap.count())

	// Оператор берётся ЗАХВАТОМ у настоящего вызова, а не собирается пробой:
	// проба, собравшая девять параметров своей рукой, планировала бы ДРУГОЙ
	// запрос и молчала бы об этом.
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	stmts := cap.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("в точке %s захвачено %d операторов, тождественных запросу вердикта, ожидался один: "+
			"ноль означает, что продукт исполняет другой текст, больше одного — что точка мерит два вопроса",
			p, len(stmts))
	}
	stmt := stmts[0]

	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+stmt.sql, stmt.args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана в точке %s: %v", p, err)
	}
	m, err := planrows.Extract(raw, probeWantRelations)
	if err != nil {
		t.Fatalf("прибор отказал в точке %s: %v", p, err)
	}
	res.rows, res.removed, res.touched = m.Rows, m.Removed, m.Touched
	res.census0 = m.Census
	res.plan = planShape(raw)

	// Часы — третья единица, и она никогда не складывается с первыми двумя.
	// Нулевой повтор прогревочный и в выборку не входит.
	durs := make([]time.Duration, 0, probeRepeats-1)
	for i := 0; i < probeRepeats; i++ {
		t0 := time.Now()
		if _, _, err := relverdict.Ask(ctx, tx, q); err != nil {
			t.Fatalf("повтор вопроса в точке %s: %v", p, err)
		}
		if i > 0 {
			durs = append(durs, time.Since(t0))
		}
	}
	sort.Slice(durs, func(i, j int) bool { return durs[i] < durs[j] })
	res.p50, res.p95, res.p99 = quantile(durs, 0.50), quantile(durs, 0.95), quantile(durs, 0.99)

	res.sObs = observedScope(t, ctx, tx)

	census, err := scalegrid.TakeCensus(ctx, tx, probeSpeakers)
	if err != nil {
		t.Fatalf("перепись в точке %s: %v", p, err)
	}
	census.VerdictsAsked = int64(probeRepeats + 1)
	res.census = census
	if err := census.Verify(p); err != nil {
		t.Fatalf("%v", err)
	}
	return res
}

// observedScope — S_набл: МОЩНОСТЬ CTE `scope` в строках.
//
// Не число различных областей: форма обхода даёт больше строк, чем глубин, и
// разница видна только замером. Обе величины печатаются ПОРОЗНЬ именно затем,
// чтобы их больше нельзя было перепутать.
func observedScope(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var n int
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
		SELECT count(*)::int FROM scope`,
		probeModelType, "repo-0000000", 4).Scan(&n); err != nil {
		t.Fatalf("мощность цепи областей: %v", err)
	}
	return n
}

// distinctScope — число РАЗЛИЧНЫХ сущностей на цепи. Печатается рядом с S_набл.
func distinctScope(t *testing.T, ctx context.Context, tx pgx.Tx) int {
	t.Helper()
	var n int
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
		SELECT count(DISTINCT (s_type, s_id))::int FROM scope`,
		probeModelType, "repo-0000000", 4).Scan(&n); err != nil {
		t.Fatalf("различных областей на цепи: %v", err)
	}
	return n
}

// planShape — отпечаток плана: типы узлов верхнего уровня, по порядку.
//
// Печатается в отчёт, потому что отношение двух приборов читается ТОЛЬКО внутри
// одного плана: между точками с разными планами оно описывает смену плана, а не
// погрешность (измерено: 2.11 → 0.94 при перевороте).
func planShape(raw []byte) string {
	m, err := planrows.Extract(raw, probeWantRelations)
	if err != nil {
		return "план не разобран"
	}
	types := make([]string, 0, len(m.Accesses))
	seen := map[string]bool{}
	for _, a := range m.Accesses {
		key := a.NodeType + "→" + a.Relation
		if !seen[key] {
			seen[key] = true
			types = append(types, key)
		}
	}
	sort.Strings(types)
	return strings.Join(types, " ")
}

func quantile(sorted []time.Duration, q float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	i := int(float64(len(sorted)-1)*q + 0.5)
	return sorted[i]
}

// reset / count — счётчик обращений к БД вокруг ОДНОГО вердикта.
func (c *verdictCapture) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stmts = nil
}

func (c *verdictCapture) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.stmts)
}

// openProbeTx — база оси со своим пулом и трассировщиком.
func openProbeTx(t *testing.T, ctx context.Context) (pgx.Tx, *verdictCapture) {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения: %v", err)
	}
	cap := &verdictCapture{}
	cfg.ConnConfig.Tracer = cap
	// Одно соединение на ось: план снимается там же, где посеяна фикстура, и
	// второе соединение видело бы НЕЗАКОММИЧЕННЫЙ посев как пустую базу.
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx, cap
}

// runAxis — прогнать одну ось на СВОЕЙ базе.
//
// Своя база на ось, а не общая: оси держат РАЗНЫЕ величины неподвижными, и
// приращение между ними невозможно by construction. Внутри оси фикстура растёт
// приращением — иначе полная сетка посадила бы 1.11 млн объектов вместо
// миллиона.
func runAxis(t *testing.T, ctx context.Context, axis []scalegrid.Point) []pointResult {
	t.Helper()
	if len(axis) == 0 {
		return nil
	}
	tx, capture := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	out := make([]pointResult, 0, len(axis))
	for _, p := range axis {
		seedFor := f.seedPoint(t, ctx, p)
		r := measurePoint(t, ctx, tx, capture, p)
		t.Logf("точка %s: посев %s · строк(несущая) %d · тронуто %d · сверочная %d · "+
			"обращений %d · вердикт %s · p50 %s · S_набл %d (d=%d, различных %d) · план [%s]",
			p, seedFor.Round(time.Millisecond), r.rows, r.touched, r.tuples, r.calls,
			r.verdict, r.p50.Round(time.Microsecond), r.sObs, r.depth,
			distinctScope(t, ctx, tx), r.plan)
		out = append(out, r)
	}
	return out
}

// ── ПРОБА КОНВЕЙЕРА: МАЛАЯ СЕТКА, ДВУХОСЕВОЕ УТВЕРЖДЕНИЕ ────────────────────

// TestScaleGrid_SmallGridStaysFlatAndTheControlGrows — R7-1-06.
//
// Утверждение ДВУХОСЕВОЕ, и это обязательно: односторонняя проба «ничего не
// растёт» зеленеет на СЛОМАННОМ приборе, докладывающем ноль. Поэтому рядом с
// плоскостью по N и B стоит положительный контроль по R — он обязан РАСТИ.
func TestScaleGrid_SmallGridStaysFlatAndTheControlGrows(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	grid := scalegrid.Small()

	t.Logf("малая сетка (в конвейере), потолок деградации объявлен константой %.2f до прогона:\n%s",
		smallGridRatioCeiling, scalegrid.Describe(grid))

	results := make([][]pointResult, 0, len(grid))
	for _, axis := range grid {
		results = append(results, runAxis(t, ctx, axis))
	}

	points := 0
	verdicts := int64(0)
	for _, axis := range results {
		points += len(axis)
		for _, r := range axis {
			verdicts += r.census.VerdictsAsked
		}
	}
	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: осей %d, точек сетки %d, вердиктов задано %d",
		len(results), points, verdicts)
	if points == 0 {
		t.Fatalf("точек сетки ноль: проба беспредметна, и её молчание не является плоскостью")
	}

	for _, axis := range results {
		if len(axis) < 2 {
			t.Fatalf("ось %s принесла %d точек: отношение верхней к нижней не определено",
				axis[0].point.Axis, len(axis))
		}
		lo, hi := axis[0], axis[len(axis)-1]
		if lo.rows <= 0 || hi.rows <= 0 {
			t.Fatalf("ось %s: несущая величина %d → %d. Ноль означает, что прибор ничего не "+
				"сосчитал, и всякое суждение о росте на нём тождественно верно",
				lo.point.Axis, lo.rows, hi.rows)
		}
		ratio := float64(hi.rows) / float64(lo.rows)
		switch lo.point.Axis {
		case scalegrid.AxisN, scalegrid.AxisB:
			t.Logf("ось %s: %d → %d строк за вердикт при росте %d → %d, отношение %.2f (потолок %.2f)",
				lo.point.Axis, lo.rows, hi.rows, lo.point.Value(), hi.point.Value(),
				ratio, smallGridRatioCeiling)
			if ratio > smallGridRatioCeiling {
				t.Errorf("ось %s ДЕГРАДИРОВАЛА: строк за вердикт выросло в %.2f раза (потолок %.2f) "+
					"при росте оси в %d раз. Постоянная часть чтения от размера облака не зависит, "+
					"поэтому рост здесь означает, что вердикт начал читать то, чего читать не должен",
					lo.point.Axis, ratio, smallGridRatioCeiling,
					hi.point.Value()/max(lo.point.Value(), 1))
			}
		case scalegrid.AxisR:
			// НЕ КОНТРОЛЬ, и это перемерено, а не унаследовано. После R7-1-13
			// разрешённый вердикт отвечает первой же строкой ветви выдач,
			// поэтому число выдач, называющих спрашиваемого, его стоимости не
			// меняет: ось плоская ПО ПОСТРОЕНИЮ. Утверждение о росте здесь
			// краснело бы на верной правке, поэтому ось печатается как
			// наблюдение — величина остаётся предметом предела S3.
			t.Logf("ось %s (наблюдение, не контроль): %d → %d строк за вердикт при росте %d → %d, "+
				"отношение %.2f. Плоскость здесь ОЖИДАЕМА: разрешённый вердикт отвечает "+
				"первым основанием и остальные не читает",
				lo.point.Axis, lo.rows, hi.rows, lo.point.Value(), hi.point.Value(), ratio)
		case scalegrid.AxisF:
			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Условный факт безусловного основания не
			// даёт, отбор различных над фактами читает их все — стоимость расти
			// ОБЯЗАНА. Если и она плоская, прибор мерит не стоимость запроса, а
			// что-то своё, и плоскость по N и B ничего не значит.
			t.Logf("ось %s (положительный контроль): %d → %d строк за вердикт при росте %d → %d, "+
				"отношение %.2f — она обязана РАСТИ",
				lo.point.Axis, lo.rows, hi.rows, lo.point.Value(), hi.point.Value(), ratio)
			if hi.rows <= lo.rows {
				t.Errorf("ось %s НЕ ВЫРОСЛА (%d → %d при %d → %d фактах): положительный контроль "+
					"провален. Значит прибор не двигается на заведомо более дорогом вопросе, и "+
					"плоскость по N и B тождественно верна — она получена сломанным прибором, а не "+
					"свойством запроса",
					lo.point.Axis, lo.rows, hi.rows, lo.point.Value(), hi.point.Value())
			}
		}
	}
}

// ── СТАТИСТИКА — ЧАСТЬ ТОЧКИ, А НЕ ГИГИЕНА ──────────────────────────────────

// TestScaleGrid_StatisticsArePartOfThePointNotHygiene — пара «с ANALYZE / без»
// на ОДНОЙ фикстуре (условие 4 §0.4а приёмки).
//
// Совпадение пары — КРАСНОЕ: оно означает, что статистика собирается не та либо
// не тогда, и тогда каждая точка сетки мерит отсутствие статистики, а не запрос.
func TestScaleGrid_StatisticsArePartOfThePointNotHygiene(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, capture := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)

	p := scalegrid.Point{Axis: scalegrid.AxisN, N: 1000, B: 100, R: 9, F: 1,
		Recruit: scalegrid.RecruitDirect}

	// Сначала БЕЗ статистики: посев тот же, `ANALYZE` не зовётся.
	f.growN(t, ctx, p.N)
	f.growB(t, ctx, p.B)
	f.setR(t, ctx, p.R, scalegrid.RecruitDirect)
	f.setF(t, ctx, p.F, scalegrid.RecruitFactSelf)
	without := measurePoint(t, ctx, tx, capture, p)

	// Затем — та же фикстура, ничего не досыпано, только собрана статистика.
	f.analyze(t, ctx)
	with := measurePoint(t, ctx, tx, capture, p)

	t.Logf("одна фикстура, две точки:\n  без ANALYZE: строк %d, тронуто %d, сверочная %d, план [%s]\n"+
		"  с ANALYZE:   строк %d, тронуто %d, сверочная %d, план [%s]",
		without.rows, without.touched, without.tuples, without.plan,
		with.rows, with.touched, with.tuples, with.plan)

	if without.rows == with.rows && without.touched == with.touched && without.plan == with.plan {
		t.Errorf("пара «с ANALYZE / без» СОВПАЛА по всем трём осям (строк %d, тронуто %d, план тот же). "+
			"Значит статистика собирается не та либо не тогда — и каждая точка сетки мерит "+
			"ОТСУТСТВИЕ СТАТИСТИКИ, а не запрос. Совпадение здесь — красное, а не подтверждение",
			with.rows, with.touched)
	}
	// Положительный контроль прибора: он обязан что-то сосчитать на обеих
	// сторонах пары, иначе «разошлось» получено сравнением двух нулей.
	if without.rows <= 0 || with.rows <= 0 {
		t.Fatalf("прибор дал ноль на одной из сторон пары (%d / %d): расхождение получено "+
			"сравнением с нулём и ничего не означает", without.rows, with.rows)
	}
}

// ── ПОЛНАЯ СЕТКА: РУЧНОЙ ПРОГОН, ОТЧЁТ — АРТЕФАКТ ДЕРЕВА ────────────────────

// TestScaleGrid_FullGridReport — R7-1-03, R7-1-04, R7-1-05.
//
// Переменная окружения решает, ЗАПУСКАТЬ ли прогон, и НИКОГДА — что мерить:
// сетка живёт константой в `pg/scalegrid`. Разница несущая, и её уже платили в
// этом дереве: у соседнего прибора объём замера переопределялся окружением, и
// отчёт, снятый на сокращённом объёме, носил то же имя, что полный.
func TestScaleGrid_FullGridReport(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	if os.Getenv(fullGridEnv) == "" {
		t.Skipf("полная сетка идёт РУЧНЫМ прогоном: %s=1 go test ./services/iam/internal/repo/kacho/pg/relverdict/ "+
			"-run TestScaleGrid_FullGridReport -count=1 -v -timeout 120m", fullGridEnv)
	}
	ctx := context.Background()
	grid := scalegrid.Full()

	runCommand := fmt.Sprintf("%s=1 go test ./services/iam/internal/repo/kacho/pg/relverdict/ "+
		"-run TestScaleGrid_FullGridReport -count=1 -v -timeout 120m", fullGridEnv)
	prov := scalegrid.TakeProvenance(runCommand, grid)

	started := time.Now()
	results := make([][]pointResult, 0, len(grid))
	for _, axis := range grid {
		axisStart := time.Now()
		results = append(results, runAxis(t, ctx, axis))
		t.Logf("ось %s прогнана за %s", axis[0].Axis, time.Since(axisStart).Round(time.Second))
	}
	prov.Postgres = postgresVersion(t, ctx)

	// ЗАГОЛОВОК НАЗЫВАЕТ ОБЕ РЕВИЗИИ, а не только свою.
	//
	// Отчёт перезамера, не называющий базового, сравнивать не с чем: «стало
	// лучше» — утверждение о ПАРЕ, и вторая её половина обязана быть адресуема,
	// иначе читателю остаётся верить на слово. Базовый лежит рядом файлом, а не
	// только в истории: ссылка на коммит требует доступа к репозиторию, а
	// артефакт обязан читаться сам по себе.
	header, err := prov.Header("R7-1 · S2 — ПРИБОР ПОРЯДКОВ: СЕТКА ЧЕТЫРЁХ ОСЕЙ " +
		"(перезамер ПОСЛЕ правок S2)\n" +
		"БАЗОВЫЙ ЗАМЕР (ДО правок S2) — ревизия " + baselineRevision + ", файл " + baselineReportPath)
	if err != nil {
		t.Fatalf("шапка отчёта: %v", err)
	}
	body := renderReport(results, time.Since(started))
	path, err := scalegrid.ReportAbsPath()
	if err != nil {
		t.Fatalf("%v", err)
	}
	if err := os.WriteFile(path, []byte(header+body), 0o644); err != nil {
		t.Fatalf("запись отчёта: %v", err)
	}
	t.Logf("отчёт записан: %s\n\n%s%s", path, header, body)
}

// postgresVersion — версия сервера; замер без неё — число без сервера.
func postgresVersion(t *testing.T, ctx context.Context) string {
	t.Helper()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		return "не установлена"
	}
	// Закрытие — С ПРЕДЕЛОМ, а не `defer pool.Close()`: отложенное закрытие ждёт
	// соединение, которого проба, упавшая внутри открытой транзакции, не вернёт
	// никогда, — и уносит с собой вердикт всего пакета. Гейт дерева
	// `TestPoolCloseInTestsIsBounded` это и поймал: ведомость долга он хранит
	// числом, поэтому лишнее закрытие видно как превышение на единицу.
	pgtest.ClosePoolAtEnd(t, pool)
	var v string
	if err := pool.QueryRow(ctx, "SHOW server_version").Scan(&v); err != nil {
		return "не установлена"
	}
	return v
}

// renderReport — тело отчёта: строка на точку плюс перепись.
func renderReport(results [][]pointResult, wall time.Duration) string {
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("\nЧЕМ СНЯТА КАЖДАЯ КОЛОНКА (единицы не складываются между собой)\n")
	w("  строк(несущая)  — Actual Rows × Actual Loops листовых узлов плана\n")
	w("                    (EXPLAIN ANALYZE BUFFERS VERBOSE FORMAT JSON, pg/planrows)\n")
	w("  отброшено       — Rows Removed by Filter/Index Recheck/Join Filter, тем же прибором\n")
	w("  тронуто         — несущая + отброшено; вердикт о стоимости выносится по НЕЙ\n")
	w("  сверочная       — pg_stat_xact_all_tables (seq_tup_read + idx_tup_fetch), считает Postgres\n")
	w("  обращений       — круговых обращений к БД на один вердикт, трассировщиком pgx\n")
	w("  p50/p95/p99     — часы; нулевой повтор прогревочный и в выборку не входит\n")
	w("  S_набл          — мощность CTE scope в СТРОКАХ (не число различных областей)\n")
	w("\nРАСХОЖДЕНИЕ ДВУХ ПРИБОРОВ ЗАКОННО И ОЖИДАЕМО: счётчик считает строки, ТРОНУТЫЕ\n")
	w("сканом, план — ОТДАННЫЕ узлом после фильтра. Молчание о нём — нет: несказанное\n")
	w("расхождение неотличимо от прибора, меряющего не ту величину. Отношение читается\n")
	w("ТОЛЬКО внутри одного плана — между точками с разными планами оно описывает смену\n")
	w("плана, а не погрешность.\n")

	for _, axis := range results {
		if len(axis) == 0 {
			continue
		}
		w("\n\nОСЬ %s\n%s\n", axis[0].point.Axis, strings.Repeat("-", 78))
		w("%-10s %-22s %8s %9s %8s %10s %6s %9s %9s %6s\n",
			"значение", "способ набора", "строк", "отброш.", "тронуто", "сверочная",
			"обращ.", "p50", "p99", "S_набл")
		for _, r := range axis {
			w("%-10d %-22s %8d %9d %8d %10d %6d %9s %9s %6d\n",
				r.point.Value(), r.point.Recruit, r.rows, r.removed, r.touched, r.tuples,
				r.calls, r.p50.Round(time.Microsecond), r.p99.Round(time.Microsecond), r.sObs)
		}
		w("\n  отношение к нижней точке (несущая): ")
		base := axis[0].rows
		for _, r := range axis {
			if base > 0 {
				w("%d→%.2f  ", r.point.Value(), float64(r.rows)/float64(base))
			}
		}
		w("\n  отношение сверочная/несущая по точкам: ")
		for _, r := range axis {
			w("%d→%.2f  ", r.point.Value(), r.ratio())
		}
		w("\n  вердикт в каждой точке: ")
		for _, r := range axis {
			w("%d→%s  ", r.point.Value(), r.verdict)
		}
		w("\n  план по точкам:\n")
		for _, r := range axis {
			w("    %-10d [%s]\n", r.point.Value(), r.plan)
		}
		w("\n  ПЕРЕПИСЬ ПОСАЖЕННОГО в верхней точке (по каждой таблице порознь, счётом по факту):\n")
		w("%s", axis[len(axis)-1].census.String())
	}

	w("\n\nОБЪЁМ ОСМОТРЕННОГО\n")
	points, verdicts := 0, int64(0)
	for _, axis := range results {
		points += len(axis)
		for _, r := range axis {
			verdicts += r.census.VerdictsAsked
		}
	}
	w("  осей %d, точек сетки %d, вердиктов задано %d, настенное время прогона %s\n",
		len(results), points, verdicts, wall.Round(time.Second))
	w("\nПЕРЕПИСЬ ПРИБОРА В ВЕРХНЕЙ ТОЧКЕ ОСИ N (доля неотнесённого печатается всегда)\n")
	if len(results) > 0 && len(results[0]) > 0 {
		w("%s\n", results[0][len(results[0])-1].census0)
	}
	return b.String()
}

// ── S_набл: МОЩНОСТЬ ЦЕПИ ИЗМЕРЕНА, И РЯДОМ НАПЕЧАТАНА ГЛУБИНА ──────────────

// TestScaleGrid_ScopeCardinalityIsMeasuredNotAssumed — R7-1-09.
//
// Мощность CTE `scope` — это НЕ число различных областей: форма обхода даёт
// больше строк, чем глубин, и разница видна ТОЛЬКО замером. Обе величины
// печатаются порознь именно затем, чтобы их больше нельзя было перепутать.
//
// Проба границы НЕ устанавливает и не подтверждает: `S_гран` предъявляется
// схемой (глубина ограничена четырьмя), а `S_набл` — фикстурой. Замер верхней
// оценкой не бывает: он свидетельствует о своей фикстуре.
func TestScaleGrid_ScopeCardinalityIsMeasuredNotAssumed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, _ := openProbeTx(t, ctx)
	newGridFixture(t, ctx, tx)

	// Цепь глубины 3, каждое звено СО СВОЕЙ цепью (звенья положил newGridFixture).
	s := scalegrid.NewSeeder(tx)
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: probeCatalogType, ObjectID: "repo-0000000",
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		ParentChain: []string{"registry_registry:reg-1", "project:prj-1", "account:acc-1"},
	}))
	must(t, s.Flush(ctx))

	deep := observedScope(t, ctx, tx)
	deepDistinct := distinctScope(t, ctx, tx)

	// Замкнутая форма при согласованных замыканиях: 1 + d·(d+1)/2.
	//
	// Свести её к 1 + d одним чтением таблицы рёбер НЕЛЬЗЯ, и это перемерено, а
	// не предположено: таблица хранит цепь, ПРИСЛАННУЮ производителем, а не
	// замыкание, и производители дерева шлют короткую. Одно чтение схлопнуло бы
	// область до «объект + его непосредственный предок» — см.
	// TestScopeReachesTheRootOnTheChainProducersActuallyWrite.
	const d = probeChainDepth
	wantClosed := 1 + d*(d+1)/2
	t.Logf("цепь глубины d=%d: S_набл=%d (замкнутая форма 1+d(d+1)/2 = %d), "+
		"различных сущностей на цепи=%d (1+d = %d)",
		d, deep, wantClosed, deepDistinct, 1+d)

	if deep != wantClosed {
		t.Errorf("S_набл=%d, замкнутая форма даёт %d при d=%d. Расхождение означает, что форма "+
			"данных НЕ ТА, которую проба думала посадить, — и это красное осмысленное, а не "+
			"придирка к арифметике", deep, wantClosed, d)
	}
	if deepDistinct != 1+d {
		t.Errorf("различных сущностей на цепи %d, ожидалось %d (сам объект плюс d предков)",
			deepDistinct, 1+d)
	}
	// Граница схемы: глубина ограничена четырьмя (CHECK depth BETWEEN 1 AND 4),
	// значит S_гран = 1 + D(D+1)/2 = 11 при согласованных замыканиях.
	//
	// ПЛЕЧО, РАЗЛИЧАВШЕЕ ГРАНИЦУ И ВЫВОД «D + 1», ОСТАЁТСЯ ДЕЙСТВУЮЩИМ. Приёмка
	// снимала его вместе с переходом на ОДНО ЧТЕНИЕ — там 1 + D и D + 1
	// становятся одним выражением, и различать нечего. Перехода НА ОДНО ЧТЕНИЕ
	// не будет: предпосылка ложна (таблица не замыкание). Предикат возврата
	// плеча, названный приёмкой, сработал в обратную сторону — S_гран равна
	// 1 + D(D+1)/2, а не D + 1, и подстановка вывода вместо границы более чем
	// вдвое занизила бы потолок, из которого выбираются L и L_m.
	//
	// ФОРМУЛИРОВКА СУЖЕНА ДО ДОКАЗАННОГО (#811). Прежняя редакция говорила
	// «перехода не будет» — шире своего довода: к границе 1 + D ведёт не только
	// одно чтение, но и ОТБОР РАЗЛИЧНЫХ поверх обхода, к которому опровергнутая
	// предпосылка отношения не имеет. Он и сделан: армы вердикта, перечисления,
	// разбора и субъектов читают теперь scope_distinct.
	//
	// ЧИСЛА ЭТОЙ ПРОБЫ ОТ НЕГО НЕ ДВИГАЮТСЯ, и это надо сказать прямо, иначе
	// зелёное здесь прочтут как «дедупликации нет». S_набл — мощность САМОГО
	// ОБХОДА, а обход сохранён целиком; отбор различных стоит НАД ним и меняет
	// то, что читают армы (4 вместо 6 на цепи из двух звеньев), а не то, что
	// производит обход. Что читают армы, утверждает
	// scopedistinct_integration_test.go — на тексте, который исполняет продукт.
	const sGran = 11
	if deep > sGran {
		t.Errorf("S_набл=%d превысила ОБЪЯВЛЕННУЮ границу S_гран=%d: граница выведена из схемы "+
			"(глубина 1..4), и её превышение означает, что цепь длиннее, чем схема допускает",
			deep, sGran)
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на вырожденной цепи: при d = 1 обе величины равны 2,
	// то есть разница между ними НЕ НАБЛЮДАЕМА. Ради этого контроль и стоит:
	// он показывает, почему вырожденная фикстура не могла найти класс, и почему
	// требование «d ≥ 3, каждое звено со своей цепью» — не педантизм.
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: probeCatalogType, ObjectID: "repo-shallow",
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		ParentChain: []string{"account:acc-1"},
	}))
	must(t, s.Flush(ctx))

	var shallow, shallowDistinct int
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
		              LIMIT 4
		           ) e
		     WHERE s.depth < 4
		)
		SELECT count(*)::int, count(DISTINCT (s_type, s_id))::int FROM scope`,
		probeModelType, "repo-shallow").Scan(&shallow, &shallowDistinct); err != nil {
		t.Fatalf("мощность вырожденной цепи: %v", err)
	}
	t.Logf("вырожденная цепь d=1: S_набл=%d, различных=%d — на ней две величины СОВПАДАЮТ, "+
		"и потому фикстура глубины 1 не может найти их расхождение", shallow, shallowDistinct)
	if shallow != 2 || shallowDistinct != 2 {
		t.Errorf("на цепи d=1 ожидалось S_набл=2 и различных=2, получено %d и %d: контроль "+
			"не воспроизвёл вырожденный случай, и вывод «глубокая фикстура необходима» повисает",
			shallow, shallowDistinct)
	}
	if shallow == deep {
		t.Errorf("вырожденная цепь дала ту же мощность (%d), что глубокая: значит проба не "+
			"различает глубины вовсе, и её зелёное на глубокой фикстуре ничего не значит", shallow)
	}
}

// ── КОНСТРУИРУЕМОСТЬ ТОЧЕК: ОГРАНИЧЕНИЯ СХЕМЫ ЧИТАЮТСЯ, А НЕ ОБХОДЯТСЯ ──────

// TestScaleGrid_EveryRecruitVariantIsConstructible — оси R и F полной сетки
// целиком, со ВСЕМИ способами набора.
//
// # Зачем отдельная проба, если те же точки идут в полном прогоне
//
// Полный прогон стоит десятки минут и начинается с самых дорогих осей, поэтому
// неконструируемая точка на оси R обнаруживалась бы ПОСЛЕ них — то есть ценой
// всего прогона. Здесь те же точки берутся из ТОЙ ЖЕ константы сетки, но оси N
// и B стоят на своих неподвижных значениях (10³), и проба укладывается в
// секунды.
//
// # Что именно она утверждает
//
// Что каждая точка сетки СУЩЕСТВУЕТ как состояние базы. Схема этого не обещает:
//
//   - `access_binding_subjects_pk` и уникальность действующей выдачи по пятёрке
//     (субъект, роль, область) означают, что сто выдач одному субъекту на одной
//     области набираются только СТА РОЛЯМИ;
//   - `relation_fact_pkey` — четвёрка (тип, объект, отношение, субъект), поэтому
//     при одном написании субъекта число фактов ограничено сверху произведением
//     «объектов цепи × отношений»;
//   - смена способа набора переписывает выдачи, но НЕ роли: повторная вставка
//     роли была бы нарушением первичного ключа. Первая редакция фикстуры считала
//     их одним счётчиком и падала на первой же точке, набранной через группы, —
//     ровно этот класс проба и сторожит.
func TestScaleGrid_EveryRecruitVariantIsConstructible(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	full := scalegrid.Full()
	// Оси R и F берутся ИЗ ТОЙ ЖЕ константы, что и полный прогон: своя копия
	// точек была бы вторым объявлением сетки и разошлась бы с первым молча.
	var axes [][]scalegrid.Point
	for _, axis := range full {
		if len(axis) > 0 && (axis[0].Axis == scalegrid.AxisR || axis[0].Axis == scalegrid.AxisF) {
			axes = append(axes, axis)
		}
	}
	if len(axes) != 2 {
		t.Fatalf("в полной сетке найдено %d осей R/F, ожидалось 2: проба целится не туда", len(axes))
	}

	seenRecruits := map[scalegrid.Recruit]int{}
	pointsRun := 0
	for _, axis := range axes {
		tx, capture := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		for _, p := range axis {
			f.seedPoint(t, ctx, p)
			r := measurePoint(t, ctx, tx, capture, p)
			pointsRun++
			seenRecruits[p.Recruit]++
			t.Logf("точка %s: строк %d, тронуто %d, сверочная %d, вердикт %s, "+
				"выдач на субъекта по факту %d, фактов на субъекта по факту %d",
				p, r.rows, r.touched, r.tuples, r.verdict,
				r.census.BindingsNamingSubject, r.census.FactsNamingSubject)
		}
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: точек исполнено %d, способов набора различных %d",
		pointsRun, len(seenRecruits))
	if pointsRun == 0 {
		t.Fatalf("исполнено ноль точек: проба беспредметна")
	}
	for _, want := range []scalegrid.Recruit{
		scalegrid.RecruitDirect, scalegrid.RecruitViaGroup,
		scalegrid.RecruitFactSelf, scalegrid.RecruitFactGroup, scalegrid.RecruitFactWildcard,
	} {
		if seenRecruits[want] == 0 {
			t.Errorf("способ набора %q не исполнен ни разу: его конструируемость не проверена, "+
				"и полный прогон упрётся в него после самых дорогих осей", want)
		}
	}
}

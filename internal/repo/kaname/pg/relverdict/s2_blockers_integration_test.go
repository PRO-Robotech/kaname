// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// s2_blockers_integration_test.go — S2: ЧЕТЫРЕ БЛОКЕРА СОБСТВЕННОЙ КОНСТАНТЫ.
//
// Сценарии R7-1-10 · 12 · 13 · 14 · 18 приёмки R7-1. Здесь утверждается ИСХОД —
// СТРОК ПРОЧИТАНО, — а не форма плана. «В плане есть index scan» есть
// утверждение о выборе планировщика на данной статистике: оно зеленеет ровно
// тогда, когда статистика удобна, то есть в точности в том случае, ради
// которого проба и написана.
//
// Величина берётся ОБЪЯВЛЕННЫМ прибором (`pg/planrows`) с ЗАХВАЧЕННОГО у
// продукта оператора: проба, собирающая текст запроса своей рукой, планировала
// бы другой запрос и молчала бы об этом.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/planrows"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
)

// probeObjectID — объект, о котором задаётся вопрос во всех пробах файла.
const probeObjectID = "repo-0000000"

// askAndExplain — задать НАСТОЯЩИЙ вопрос вердикта и снять с него разложение.
//
// Оператор захватывается трассировщиком у вызова `Ask` и сверяется дословно с
// текстом продукта — иначе доказано было бы лишь то, что пакет что-то отправил.
func askAndExplain(t *testing.T, ctx context.Context, tx pgx.Tx, cap *verdictCapture,
	objectID string) (relverdict.Verdict, planrows.Measurement) {
	t.Helper()
	cap.reset()
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject:    probeSubject,
		ObjectType: probeModelType,
		ObjectID:   objectID,
		Relation:   probeRelation,
	})
	if err != nil {
		t.Fatalf("вопрос вердикта об %s: %v", objectID, err)
	}
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	stmts := cap.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("захвачено %d операторов, тождественных запросу вердикта, ожидался один: "+
			"ноль означает, что продукт исполняет другой текст, больше одного — что мерятся два вопроса",
			len(stmts))
	}
	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON) "+stmts[0].sql, stmts[0].args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана: %v", err)
	}
	m, err := planrows.Extract(raw, probeWantRelations)
	if err != nil {
		t.Fatalf("прибор отказал на живом плане: %v", err)
	}
	return v, m
}

// rowsOf — строк, отнесённых прибором к названному отношению.
func rowsOf(m planrows.Measurement, relation string) int64 {
	var n int64
	for _, a := range m.Accesses {
		if a.Relation == relation {
			n += a.Rows
		}
	}
	return n
}

// ── R7-1-18: ОБХОД ЦЕПИ ОБЛАСТЕЙ ПЕРЕСТАЁТ ПЕРЕВЫЧИСЛЯТЬ ЗАМЫКАНИЕ ──────────

// TestR7_1_18_ScopeWalkCostsTheRequestNotTheCloud — R7-1-18, задача #732.
//
// # Сценарий утверждал НЕ ТО, и предпосылка его была ложной
//
// R7-1-18 требовал свести обход цепи к ОДНОМУ обращению к таблице рёбер, считая
// её замыканием. Замыканием она не является: ключ (объект, глубина) и проверка
// глубины 1..4 допускают обе формы, а производители дерева шлют КОРОТКУЮ цепь —
// vpc, storage и compute по одному звену, реестр два, кластер никто. Проба
// `TestScopeReachesTheRootOnTheChainProducersActuallyWrite` показывает цену
// ошибки прямо: на одном чтении выдача на аккаунт и факт администратора облака
// на кластере перестают действовать.
//
// Поэтому обход остаётся, а утверждается то, что было настоящим дефектом и
// осталось исправимым: **обход не платит за размер облака**. Рекурсивная ветвь с
// обычным соединением давала планировщику право прочитать таблицу рёбер целиком
// на каждом шаге — 2412 строк за один вердикт при трёх рёбрах у объекта.
// Соединение вбок с пределом заставляет ходить указателем по ключу.
//
// Утверждается ИСХОД — строк прочитано, — и утверждается он ДВАЖДЫ: величина не
// растёт с числом объектов в облаке, и на каждом узле она не больше цепи самого
// объекта. Одного первого мало: плоскость выполнена и у прибора, дающего ноль.
//
// # Охват РАСШИРЕН под-фазой R7-4 (решение Р6, находка П14)
//
// Первое утверждение стояло здесь с отбором по ОДНОМУ имени и покрывало 1 из 10
// отношений плана, а после достройки цепи пяти собственным типам iam покрывало бы
// 1 из 14. Теперь оно ранжируется по КАЖДОМУ отношению, выведенному из плана
// (`assertWalkCostRankedByEveryRelation`), поэтому новая ветвь представления
// попадает под него сама. Предмет самой пробы — прежний; у́же он не становится.
func TestR7_1_18_ScopeWalkCostsTheRequestNotTheCloud(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Потолок роста и размеры облаков объявлены ДО прогона и живут в пакете
	// (`walkCeiling`, `walkCostFewCloud`/`walkCostManyCloud`, walkcost_relations_test.go):
	// их проверяют три утверждения, и второй экземпляр разошёлся бы с первым молча.
	const few, many = walkCostFewCloud, walkCostManyCloud

	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, few)
	f.setR(t, ctx, 1, scalegrid.RecruitDirect)
	f.analyze(t, ctx)

	// ПРЕДПОСЫЛКА: цепь объекта глубока и коротка по звеньям — то есть та самая,
	// на которой обход обязан подниматься транзитивно.
	var links int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)::int FROM kaname.resource_parent_edge
		 WHERE object_type = $1 AND object_id = $2`,
		probeModelType, probeObjectID).Scan(&links); err != nil {
		t.Fatalf("замыкание объекта: %v", err)
	}
	if links == 0 {
		t.Fatalf("у объекта ноль рёбер: обход мерил бы вырожденный случай")
	}

	vFew, mFew := askAndExplain(t, ctx, tx, cap, probeObjectID)
	edgeFew := rowsOf(mFew, "resource_parent_edge")

	f.growN(t, ctx, many)
	f.analyze(t, ctx)
	vMany, mMany := askAndExplain(t, ctx, tx, cap, probeObjectID)
	edgeMany := rowsOf(mMany, "resource_parent_edge")

	t.Logf("рёбер у объекта %d · объектов в облаке %d → строк из таблицы рёбер %d · "+
		"объектов %d → %d (перевычисляющая форма читала бы таблицу целиком: измерено 2412)",
		links, few, edgeFew, many, edgeMany)

	if vFew != relverdict.Allow || vMany != relverdict.Allow {
		t.Fatalf("вердикты %s и %s: мерилась бы стоимость неверного ответа", vFew, vMany)
	}
	if d := edgeMany - edgeFew; d > walkCeiling {
		t.Errorf("строк из таблицы рёбер за вердикт: %d при %d объектах против %d при %d, "+
			"прирост %d при потолке %d. Обход платит за размер облака — значит рекурсивная "+
			"ветвь достаёт таблицу обычным соединением, а не указателем по ключу",
			edgeMany, many, edgeFew, few, d, walkCeiling)
	}
	if edgeFew == 0 || edgeMany == 0 {
		t.Fatalf("из таблицы рёбер прочитано 0 строк при непустой цепи: прибор смотрел не туда, "+
			"и плоскость тождественно верна.\n%s", mMany.Census)
	}
	// ВТОРОЕ утверждение — ПО КАЖДОМУ отношению, которое назвал план, а не по
	// одному, названному по имени (Р6/П14 под-фазы R7-4). Перечень ВЫВОДИТСЯ из
	// плана, поэтому новая ветвь представления попадает под утверждение сама;
	// отношение, которое план назвал, а утверждение пропустило, — находка.
	assertWalkCostRankedByEveryRelation(t, mFew, mMany, everyRelationOfThePlan)

	// ТРЕТЬЕ утверждение — БОЛЕЕ СИЛЬНОЕ и потому намеренно об ОДНОМ отношении: на
	// каждом узле таблицы рёбер величина ограничена цепью САМОГО ОБЪЕКТА,
	// умноженной на число уровней обхода, — а не числом строк таблицы.
	//
	// По отношениям этот предел НЕ обобщается, и это измерено, а не предположено:
	// у relation_fact на этой же фикстуре 15 строк при 3 звеньях цепи и пределе
	// обхода 4, то есть 15 > 12. Растянуть его на все отношения значило бы
	// подобрать константу ПОСЛЕ прогона — описать полученное число вместо
	// свойства. Форму «не платим за размер облака» несёт утверждение выше, и оно
	// покрывает всё.
	edgeAccesses := accessesOf(mMany, "resource_parent_edge")
	if len(edgeAccesses) == 0 {
		t.Fatalf("в плане нет ни одного доступа к таблице рёбер: утверждение о пределе узла стало бы "+
			"тождественно верным.\n%s", mMany.Census)
	}
	for _, a := range edgeAccesses {
		t.Logf("  %s: строк %d, циклов %d", a.NodeType, a.Rows, a.Loops)
		if a.Rows > int64(links*relverdict.MaxAncestorDepth) {
			t.Errorf("узел %s отдал %d строк при %d рёбрах у объекта и пределе обхода %d: "+
				"чтение не привязано к предмету запроса", a.NodeType, a.Rows, links,
				relverdict.MaxAncestorDepth)
		}
	}
}

// ── R7-1-10: ЧУЖИЕ ВЫДАЧИ НЕ ВХОДЯТ В СТОИМОСТЬ ВЕРДИКТА ────────────────────

// foreignBindingsCeiling — потолок прироста строк за вердикт, объявленный ДО
// прогона.
//
// Стоимость вердикта складывается из постоянной части (сам объект, его правило,
// цепь областей) и из выдач, НАЗЫВАЮЩИХ спрашиваемого. Ни одна из них от числа
// ЧУЖИХ выдач не зависит, поэтому идеальный прирост — ноль. Потолок в 64 строки
// — запас на дребезг статистики и на смену плана при переходе от одной выдачи к
// десяти тысячам; деградация этого класса даёт порядки (замер S1: 183 → 1 001 049),
// и шестьдесят четыре отделяют её от дребезга с огромным запасом.
const foreignBindingsCeiling = 64

// TestR7_1_10_ForeignBindingsDoNotEnterVerdictCost — R7-1-10, ОБЕ стороны оси B.
//
// Ось имеет две стороны, и раскладка, проверяющая одну, зелена при сломанной
// другой:
//
//	сторона-1 — чужие выдачи в ЭТОЙ области (заход со стороны области читает их все);
//	сторона-2 — выдачи ЭТОМУ субъекту в ДРУГИХ областях (заход со стороны субъекта
//	            читает их все).
//
// Индекс по одному лишь субъекту закрывает первую и ОТКРЫВАЕТ вторую. Поэтому
// обе прогоняются против одной контрольной раскладки.
func TestR7_1_10_ForeignBindingsDoNotEnterVerdictCost(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	const foreign = 10000

	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 200)
	f.setR(t, ctx, 1, scalegrid.RecruitDirect)
	f.analyze(t, ctx)

	vCtl, mCtl := askAndExplain(t, ctx, tx, cap, probeObjectID)
	ctl := mCtl.Rows
	t.Logf("контрольная раскладка: одна выдача, называющая спрашиваемого · вердикт %s · строк %d",
		vCtl, ctl)

	// ── сторона-1: чужие выдачи НА ТОЙ ЖЕ области ────────────────────────────
	f.growB(t, ctx, foreign)
	f.analyze(t, ctx)
	v1, m1 := askAndExplain(t, ctx, tx, cap, probeObjectID)
	t.Logf("сторона-1 (%d чужих выдач на цепи областей): вердикт %s · строк %d · прирост %d",
		foreign, v1, m1.Rows, m1.Rows-ctl)

	// ── сторона-2: выдачи ТОМУ ЖЕ субъекту в ДРУГИХ областях ────────────────
	seedElsewhereBindings(t, ctx, tx, f, foreign)
	f.analyze(t, ctx)
	v2, m2 := askAndExplain(t, ctx, tx, cap, probeObjectID)
	t.Logf("сторона-2 (%d выдач спрашиваемому ВНЕ цепи областей): вердикт %s · строк %d · прирост %d",
		foreign, v2, m2.Rows, m2.Rows-ctl)

	// Ответ во всех трёх обязан совпасть — иначе замер сравнивает разные вопросы.
	if vCtl != v1 || vCtl != v2 {
		t.Fatalf("вердикты разошлись: контроль %s, сторона-1 %s, сторона-2 %s — "+
			"замер сравнивал бы разные вопросы", vCtl, v1, v2)
	}
	if vCtl != relverdict.Allow {
		t.Fatalf("контрольная раскладка дала %s: мерилась бы стоимость неверного ответа", vCtl)
	}

	for _, c := range []struct {
		name string
		got  int64
	}{{"сторона-1 (чужие выдачи в этой области)", m1.Rows},
		{"сторона-2 (выдачи этому субъекту вне этой области)", m2.Rows}} {
		if d := c.got - ctl; d > foreignBindingsCeiling {
			t.Errorf("%s: строк за вердикт %d против %d в контрольной, прирост %d при потолке %d. "+
				"Чужие выдачи входят в стоимость вердикта", c.name, c.got, ctl, d, foreignBindingsCeiling)
		}
	}
}

// seedElsewhereBindings — выдачи, называющие СПРАШИВАЕМОГО, в областях, которых
// НЕТ на цепи спрашиваемого объекта.
//
// Ровно та величина, на которую переезжает неограниченность, если субъект
// сделать единственным входом: проектов в облаке неограниченно, и у группы,
// используемой во многих проектах, их много и на практике.
func seedElsewhereBindings(t *testing.T, ctx context.Context, tx pgx.Tx, f *gridFixture, n int) {
	t.Helper()
	s := scalegrid.NewSeeder(tx)
	for i := 0; i < n; i++ {
		pid := fmt.Sprintf("prj-e%07d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, 'acc-1', $1)`, pid))
	}
	// Роли — своим пулом: действующая выдача уникальна по (субъект, роль, область),
	// а область здесь у каждой своя, поэтому хватает одной роли на все.
	for i := 0; i < n; i++ {
		bid := fmt.Sprintf("acb-e%07d", i)
		pid := fmt.Sprintf("prj-e%07d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', 'usr-1', 'rol-anchor', 'project', $2, 'ACTIVE')`, bid, pid))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', 'usr-1')`, bid))
	}
	must(t, s.Flush(ctx))
}

// ── R7-1-12: ИНДЕКС СУЩЕСТВУЕТ, ПРИМЕНЁН И ОБСЛУЖИВАЕТ ВЕРДИКТ ──────────────

// TestR7_1_12_SubjectAndScopeResolveOnOneIndex — R7-1-12.
//
// Утверждается СВОЙСТВО — «пара субъект + область разрешается одним индексом на
// одном отношении», — а не раскладка колонок: любая другая, дающая то же
// свойство, ему удовлетворяет, и пинить порядок значило бы краснеть на верной
// правке.
//
// Свойство предъявляется ИСХОДОМ и ИНЪЕКЦИЕЙ. Объявленный, но не применяемый
// индекс — тот же «объявленный и никем не читаемый страж»: проба обязана уметь
// отличить его от работающего, поэтому индекс снимается прямо в транзакции, и
// та же раскладка обязана стать дороже. Без этого плеча зелёное означало бы
// лишь «строк мало», а не «мало ИЗ-ЗА индекса».
func TestR7_1_12_SubjectAndScopeResolveOnOneIndex(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	const foreign = 10000

	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 200)
	f.setR(t, ctx, 1, scalegrid.RecruitDirect)
	f.growB(t, ctx, foreign)
	f.analyze(t, ctx)

	// ПРЕДПОСЫЛКА: оба предиката стоят на ОДНОМ отношении. Иначе одного индекса,
	// обслуживающего оба, не существует by construction, и «свойство есть»
	// означало бы «план сегодня удобен».
	var carried int
	if err := tx.QueryRow(ctx, `
		SELECT count(*)::int FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'access_binding_subjects'
		   AND column_name IN ('subject_type','subject_id','resource_type','resource_id')`).Scan(&carried); err != nil {
		t.Fatalf("состав колонок: %v", err)
	}
	if carried != 4 {
		t.Fatalf("на строке субъекта выдачи %d из четырёх колонок пары «субъект + область»: "+
			"предикаты стоят на разных отношениях, и утверждать свойство не о чем", carried)
	}

	vWith, mWith := askAndExplain(t, ctx, tx, cap, probeObjectID)
	if vWith != relverdict.Allow {
		t.Fatalf("вердикт %s: мерилась бы стоимость неверного ответа", vWith)
	}
	subjWith := rowsOf(mWith, "access_binding_subjects")
	t.Logf("с индексом: строк за вердикт %d, из них по строкам субъектов выдач %d "+
		"(в облаке %d чужих выдач)", mWith.Rows, subjWith, foreign)

	// ── ИНЪЕКЦИЯ: индекс снят, всё прочее не тронуто ─────────────────────────
	if _, err := tx.Exec(ctx,
		`DROP INDEX kaname.access_binding_subjects_subject_scope_idx`); err != nil {
		t.Fatalf("снятие индекса: имя изменилось или индекса нет — инъекция не воспроизводит "+
			"состояние «объявлен, но не применяется»: %v", err)
	}
	f.analyze(t, ctx)
	vNo, mNo := askAndExplain(t, ctx, tx, cap, probeObjectID)
	subjNo := rowsOf(mNo, "access_binding_subjects")
	t.Logf("без индекса: строк за вердикт %d, из них по строкам субъектов выдач %d", mNo.Rows, subjNo)

	// Ответ обязан совпасть: инъекция меняет СТОИМОСТЬ, а не смысл.
	if vNo != vWith {
		t.Errorf("снятие индекса изменило ответ (%s против %s): инъекция сравнивала бы "+
			"разные вопросы", vNo, vWith)
	}
	if subjNo <= subjWith {
		t.Errorf("без индекса по строкам субъектов выдач прочитано %d, с индексом %d — "+
			"инъекция не воспроизвела дефекта, и зелёное с индексом ничего не доказывает: "+
			"оно означало бы «строк мало», а не «мало ИЗ-ЗА индекса»", subjNo, subjWith)
	}
	if subjWith > foreignBindingsCeiling {
		t.Errorf("с индексом по строкам субъектов выдач прочитано %d при потолке %d: "+
			"индекс объявлен, но набор им не сужается", subjWith, foreignBindingsCeiling)
	}
}

// ── R7-1-13 / R7-1-14: РАННИЙ ВЫХОД И УСЕЧЕНИЕ ──────────────────────────────

// TestR7_1_13_EarlyExitIsObservable — R7-1-13.
//
// # Что утверждается и почему НЕ дословная формулировка сценария
//
// Сценарий требует: строк на разрешающем вопросе МЕНЬШЕ, чем на отказном при той
// же раскладке. Эта пара была осмысленной ДО починок 11–12, когда отказной
// вопрос обязан был прочитать все основания области. После них отказ сам стал
// дёшев — пара «субъект + область» отсекает чужие выдачи до чтения строк, — и
// сравнение двух дешёвых величин перестало говорить о замыкании: измерено 25
// против 19, причём меньшее принадлежит отказу просто потому, что до оснований
// он не доходит вовсе.
//
// Поэтому утверждается ПОСЛЕДСТВИЕ замыкания, наблюдаемое и не зависящее от
// того, какой из двух вопросов дешевле: стоимость РАЗРЕШЁННОГО вердикта не
// растёт с числом оснований, лежащих сверх первого. Пока над союзом стоял хоть
// один блокирующий узел — оконная функция по строкам до отбора различных, отбор
// различных над союзом, сортировка над ним же — она росла: измерено 1222 строки
// при трёхстах основаниях против 25 после починки.
//
// Отдельно названо то, чего эта проба НЕ утверждает: ветвь условных фактов
// исполняется внешним пределом независимо от того, что отдала ветвь выдач, —
// одним оператором «не спрашивать вторую ветвь, если первая ответила» не
// выражается. Пропустить её можно либо вторым обращением, либо повторением
// предиката выдач внутри ветви фактов (два места об одном предмете). Ни то ни
// другое здесь не сделано, и это записано как остаток, а не как сделанное.
func TestR7_1_13_EarlyExitIsObservable(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	// Потолок роста, объявленный ДО прогона. Постоянная часть вердикта от числа
	// оснований не зависит вовсе, поэтому идеальный рост — ноль; шестнадцать —
	// запас на дребезг статистики. Деградация этого класса даёт порядки
	// (измерено: 1222 против 25), и запас отделяет её от дребезга.
	const groundsCeiling = 16
	const few, many = 3, 300

	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 200)

	f.setR(t, ctx, few, scalegrid.RecruitDirect)
	f.analyze(t, ctx)
	vFew, mFew := askAndExplain(t, ctx, tx, cap, probeObjectID)

	f.setR(t, ctx, many, scalegrid.RecruitDirect)
	f.analyze(t, ctx)
	vMany, mMany := askAndExplain(t, ctx, tx, cap, probeObjectID)

	// Отказной вопрос при той же раскладке — печатается для сведения: он и есть
	// та величина, ради которой сценарий писал своё сравнение, и её изменение
	// после починок 11–12 надо видеть, а не выводить.
	cap.reset()
	vDeny, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: probeSubject, ObjectType: probeModelType, ObjectID: probeObjectID,
		Relation: "v_delete",
	})
	if err != nil {
		t.Fatalf("отказной вопрос: %v", err)
	}

	t.Logf("оснований %d → строк %d (%s); оснований %d → строк %d (%s); "+
		"отказной вопрос при той же раскладке — %s",
		few, mFew.Rows, vFew, many, mMany.Rows, vMany, vDeny)

	if vFew != relverdict.Allow || vMany != relverdict.Allow {
		t.Fatalf("раскладки дали %s и %s: сравнивались бы разные вопросы", vFew, vMany)
	}
	if vDeny != relverdict.Deny {
		t.Fatalf("отказная раскладка дала %s: контроль не воспроизвёл отказ", vDeny)
	}
	if d := mMany.Rows - mFew.Rows; d > groundsCeiling {
		t.Errorf("строк за РАЗРЕШЁННЫЙ вердикт: %d при %d основаниях против %d при %d, "+
			"прирост %d при потолке %d. Стоимость разрешения растёт с числом оснований, "+
			"лежащих сверх первого, — значит над союзом остался блокирующий узел либо "+
			"ветвь выдач читается целиком", mMany.Rows, many, mFew.Rows, few, d, groundsCeiling)
	}
}

// TestR7_1_14_TruncationIsStillARefusal — R7-1-14, в паре с 13.
//
// Короткое замыкание не смеет превратить усечение в разрешение, а усечение —
// остаться неотличимым от «мы перестали читать». Первое достаточное основание,
// найденное раньше переполнения набора, — законный исход; набор переполнился, а
// вердикт всё же выдан — дефект.
func TestR7_1_14_TruncationIsStillARefusal(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, _ := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 20)
	f.analyze(t, ctx)

	// (а) БЕЗУСЛОВНОЕ основание найдено рано, а оснований сверх него — сотни.
	// Ответ обязан быть разрешением, а НЕ ошибкой усечения.
	f.setR(t, ctx, relverdict.MaxConditionRowsForTest+64, scalegrid.RecruitDirect)
	v, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: probeSubject, ObjectType: probeModelType, ObjectID: probeObjectID,
		Relation: probeRelation,
	})
	if err != nil {
		t.Fatalf("оснований больше предела, но среди них есть безусловное — ожидалось "+
			"разрешение, получена ошибка: %v", err)
	}
	if v != relverdict.Allow {
		t.Errorf("оснований %d при пределе %d, первое из них безусловно: ожидалось разрешение, "+
			"получено %s", relverdict.MaxConditionRowsForTest+64, relverdict.MaxConditionRowsForTest, v)
	}
	t.Logf("(а) оснований %d при пределе %d, безусловное среди них: %s — усечение НЕ подменило "+
		"разрешения", relverdict.MaxConditionRowsForTest+64, relverdict.MaxConditionRowsForTest, v)

	// (б) РАЗЛИЧНЫХ УСЛОВИЙ больше предела, и безусловного среди них нет. Ответ
	// обязан быть ошибкой усечения, а не вердиктом по усечённому набору.
	seedConditionedFacts(t, ctx, tx, relverdict.MaxConditionRowsForTest+8)
	f.analyze(t, ctx)
	vTrunc, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: probeSubject, ObjectType: probeModelType, ObjectID: "repo-truncate",
		Relation: probeRelation,
	})
	if err == nil {
		t.Fatalf("различных условий больше предела, безусловного среди них нет — ожидалась "+
			"ошибка усечения, получен вердикт %s. Усечённый набор не даёт права судить", vTrunc)
	}
	if !strings.Contains(err.Error(), "усеч") {
		t.Errorf("ошибка не называет усечения: %v", err)
	}
	t.Logf("(б) различных условий больше предела, безусловного нет: %s", firstLineOf(err.Error()))
}

// seedConditionedFacts — объект, на который набирается n РАЗЛИЧНЫХ условий и ни
// одного безусловного основания.
//
// Условия приходят ПРЯМЫМИ ФАКТАМИ: выдача условия не несёт вовсе (роль раздаёт
// глаголы, а условие в модели стоит на отношениях, глаголами не являющихся),
// поэтому набрать усечение выдачами нельзя by construction.
//
// Ключ факта — четвёрка (тип, объект, отношение, субъект), а отношение обязано
// стоять в плане вопроса, иначе факт до вердикта не доедет. Различать строки
// остаётся СУБЪЕКТОМ, и он берётся тем же способом, каким его берёт продукт:
// вызывающий состоит в n группах, за каждую из которых говорит. Так фикстура
// не изображает состояния, которого схема не допускает.
func seedConditionedFacts(t *testing.T, ctx context.Context, tx pgx.Tx, n int) {
	t.Helper()
	s := scalegrid.NewSeeder(tx)
	// Свой проект, которого не покрывает НИ ОДНА выдача: иначе безусловное
	// основание находится раньше усечения — и это верный исход, а не дефект
	// (ровно та пара, ради которой сценарии 13 и 14 стоят рядом).
	must(t, s.QueueRaw(ctx,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-trunc', 'acc-1', 'prj-trunc')`))
	must(t, s.Flush(ctx))
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: probeCatalogType, ObjectID: "repo-truncate",
		ParentProjectID: "prj-trunc", ParentAccountID: "acc-1",
		ParentChain: []string{"project:prj-trunc", "account:acc-1"},
	}))
	must(t, s.Flush(ctx))
	for i := 0; i < n; i++ {
		gid := fmt.Sprintf("grp-t%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, 'acc-1', $1)`, gid))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.group_members (group_id, member_type, member_id)
			 VALUES ($1, 'user', 'usr-1')`, gid))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.relation_fact
			   (object_type, object_id, relation, subject, condition_name, condition_params)
			 VALUES ($1, 'repo-truncate', $2, $3, $4, '{}'::jsonb)`,
			probeModelType, probeRelation, "group:"+gid+"#member", fmt.Sprintf("cond_%04d", i)))
	}
	must(t, s.Flush(ctx))
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// ── R7-1-15: ГИПОТЕЗА И9 ПРОВЕРЕНА НА ОДНОЙ РЕВИЗИИ ─────────────────────────

// TestR7_1_15_LabelArmShareIsMeasuredNotAssumed — R7-1-15.
//
// Прежние числа удорожания сняты на РАЗНЫХ фикстурах и РАЗНЫХ ревизиях, поэтому
// «меточная ветвь дороже во столько-то раз» было гипотезой с предикатом, а не
// выводом. Предикат исполняется здесь: две фикстуры отличаются ТОЛЬКО ветвью
// правила, всё прочее — число объектов, ширина страницы, число субъектов,
// глаголов, роль и глубина цепи — совпадает, и обе меряются на ОДНОЙ ревизии
// одним прибором.
//
// Проба ничего не «улучшает» и порога не вводит: она отделяет долю, которую
// вносит ветвь, от доли, которую вносило различие фикстур. Число печатается
// вместе с тем, чем оно получено; порог, назначенный по полученному числу,
// описывал бы это число, а не свойство.
func TestR7_1_15_LabelArmShareIsMeasuredNotAssumed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()

	measure := func(arm string) (int64, relverdict.Verdict, int) {
		t.Helper()
		tx, cap := openProbeTx(t, ctx)
		f := newGridFixture(t, ctx, tx)
		f.growN(t, ctx, 200)

		// Роль отличается ТОЛЬКО ветвью правила: тот же тип, тот же глагол.
		must(t, execErr(ctx, tx,
			`UPDATE kaname.role_rule_selectors SET arm = $1,
			        match_labels = CASE WHEN $1 = 'labels' THEN '{"env":"prod"}'::jsonb ELSE '{}'::jsonb END
			  WHERE role_id = 'rol-anchor'`, arm))
		f.setR(t, ctx, 1, scalegrid.RecruitDirect)
		must(t, execErr(ctx, tx,
			`UPDATE kaname.role_rule_selectors SET arm = $1,
			        match_labels = CASE WHEN $1 = 'labels' THEN '{"env":"prod"}'::jsonb ELSE '{}'::jsonb END
			  WHERE role_id LIKE 'rol-r%'`, arm))
		f.analyze(t, ctx)

		v, m := askAndExplain(t, ctx, tx, cap, probeObjectID)
		var objects int
		if err := tx.QueryRow(ctx,
			`SELECT count(*)::int FROM kaname.resource_mirror`).Scan(&objects); err != nil {
			t.Fatalf("перепись объектов: %v", err)
		}
		return m.Rows, v, objects
	}

	anchorRows, anchorVerdict, anchorObjects := measure("anchor")
	labelRows, labelVerdict, labelObjects := measure("labels")

	// Фикстуры обязаны совпасть по всему, кроме ветви: иначе сравниваются не
	// ветви, а фикстуры — ровно та ошибка, ради которой сценарий и написан.
	if anchorObjects != labelObjects {
		t.Fatalf("фикстуры разошлись по числу объектов (%d против %d): сравнивались бы "+
			"не ветви правила, а фикстуры", anchorObjects, labelObjects)
	}
	if anchorVerdict != relverdict.Allow || labelVerdict != relverdict.Allow {
		t.Fatalf("ветвь якоря дала %s, ветвь меток — %s: сравнивалась бы стоимость "+
			"разных ответов", anchorVerdict, labelVerdict)
	}

	ratio := float64(labelRows) / float64(max64Rows(anchorRows, 1))
	t.Logf("И9 на ОДНОЙ ревизии, фикстуры различаются ТОЛЬКО ветвью правила "+
		"(объектов %d, субъект один, глагол один, роль одна, цепь d=%d):\n"+
		"  ветвь якоря  — строк за вердикт %d (%s)\n"+
		"  ветвь меток  — строк за вердикт %d (%s)\n"+
		"  отношение меток к якорю %.2f\n"+
		"  ВНИМАНИЕ: число описывает ЭТУ фикстуру на ЭТОЙ ревизии и верхней оценкой "+
		"не является. Прежние числа удорожания снимались на разных фикстурах и разных "+
		"ревизиях, поэтому сравнивать их с этим напрямую нельзя — сопоставима только "+
		"пара, снятая так же.",
		anchorObjects, probeChainDepth, anchorRows, anchorVerdict, labelRows, labelVerdict, ratio)

	if anchorRows <= 0 || labelRows <= 0 {
		t.Fatalf("прибор дал %d и %d строк: на нуле всякое суждение об отношении "+
			"тождественно верно", anchorRows, labelRows)
	}
}

func execErr(ctx context.Context, tx pgx.Tx, sql string, args ...any) error {
	_, err := tx.Exec(ctx, sql, args...)
	return err
}

func max64Rows(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// ── В3: ПОРЯДОК ВЕТВЕЙ ОБЪЯВЛЕН УСТРОЙСТВОМ — ЗНАЧИТ УТВЕРЖДАЕТСЯ ПРОБОЙ ────

// TestVerdictBindingArmIsBoundedAndRunsFirst — форма плана, и это ЕДИНСТВЕННОЕ
// место файла, где предмет утверждения — план, а не исход.
//
// # Почему здесь можно то, что везде нельзя
//
// Правило «утверждай исход, а не форму плана» защищает от подмены свойства
// продукта выбором планировщика на удобной статистике. Здесь предмет ОБРАТНЫЙ:
// раннее замыкание держится ровно тем, что узел объединения исполняет потомков
// ПО ПОРЯДКУ и что ветвь выдач ограничена одной строкой. SQL порядка не
// гарантирует, параллельная форма — тем более. При перестановке ветвей ответ
// останется верным, а стоимость — нет: заявленное «замыкание на сервере» тихо
// исчезнет, и ни одна проба исхода этого не заметит, потому что исход тот же.
//
// Комментарий запроса объявляет порядок частью устройства. Объявление, за
// которым не стоит проверки, переживает то, что им обозначалось.
func TestVerdictBindingArmIsBoundedAndRunsFirst(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, 200)
	f.setR(t, ctx, 50, scalegrid.RecruitDirect)
	f.analyze(t, ctx)

	cap.reset()
	if _, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: probeSubject, ObjectType: probeModelType, ObjectID: probeObjectID,
		Relation: probeRelation,
	}); err != nil {
		t.Fatalf("вопрос вердикта: %v", err)
	}
	axis, err := relverdict.LabelAxisForTest(probeCatalogType, probeModelType)
	if err != nil {
		t.Fatalf("ось меток: %v", err)
	}
	stmts := cap.matching(relverdict.VerdictQuerySQLForTest(axis))
	if len(stmts) != 1 {
		t.Fatalf("захвачено %d операторов, ожидался один", len(stmts))
	}

	var raw []byte
	if err := tx.QueryRow(ctx,
		"EXPLAIN (ANALYZE, VERBOSE, FORMAT JSON) "+stmts[0].sql, stmts[0].args...).Scan(&raw); err != nil {
		t.Fatalf("снятие плана: %v", err)
	}
	plan := string(raw)

	// (1) Ветвь выдач ограничена. Предел выражен в плане узлом Limit; его
	// отсутствие означает, что ветвь читается целиком.
	if !strings.Contains(plan, `"Node Type": "Limit"`) {
		t.Errorf("в плане нет узла предела: ветвь выдач читается целиком, и «замыкание на "+
			"сервере» перестало быть свойством запроса.\nПлан: %s", firstLineOf(plan))
	}

	// (2) Ветвь выдач исполняется ПЕРВОЙ. Порядок читается по позициям двух
	// отношений-дискриминаторов: строки субъектов выдач принадлежат только
	// первой ветви, прямые факты — второй.
	iBind := strings.Index(plan, "access_binding_subjects")
	iFact, nFact := factsArmPos(plan)
	if iBind < 0 || iFact < 0 {
		t.Fatalf("в плане нет одной из двух ветвей (выдачи %d, факты %d): порядок утверждать "+
			"не о чем", iBind, iFact)
	}
	// ПРЕДПОСЫЛКА ДИСКРИМИНАТОРА, названная числом. Пока предок проекта выводился
	// из `projects`, таблица прямых фактов читалась в запросе РОВНО ОДИН раз — в
	// ветви фактов, — и первое вхождение было её вхождением. С #781 цепь областей
	// читает ту же таблицу вторым читателем, поэтому первое вхождение принадлежит
	// ЦЕПИ, а не ветви (замер: цепь 9654, выдачи 31848, ветвь фактов 51018).
	//
	// Если читателей станет меньше двух, дискриминатор перестаёт различать ветви —
	// и гейт обязан сказать это вслух, а не молча взять не то вхождение.
	if nFact < 2 {
		t.Fatalf("таблица прямых фактов встречается в плане %d раз, ожидалось не меньше двух "+
			"(цепь областей и ветвь фактов). Предпосылка дискриминатора исчезла: последнее "+
			"вхождение больше не обязано принадлежать ветви фактов, и утверждение о порядке "+
			"стало бы утверждением ни о чём", nFact)
	}
	if iBind > iFact {
		t.Errorf("ветвь фактов стоит в плане РАНЬШЕ ветви выдач: раннее замыкание держится " +
			"тем, что первая же строка ветви выдач безусловна. Перестановка ответ не меняет, " +
			"а стоимость — меняет, и ни одна проба исхода этого не заметит")
	}
	t.Logf("порядок ветвей утверждён планом: выдачи на позиции %d, ветвь фактов на %d "+
		"(читателей таблицы фактов %d, ранние принадлежат цепи областей); предел ветви "+
		"выдач присутствует", iBind, iFact, nFact)
}

// factsArmPos — позиция чтения прямых фактов ВЕТВЬЮ ФАКТОВ и число читателей
// этой таблицы в плане.
//
// # Почему последнее вхождение, а не первое
//
// Читателей у таблицы прямых фактов в этом запросе два, и они разной природы.
// Цепь областей (`scope`) читает её, собирая предков объекта, и делает это ДО
// обеих ветвей ПО ПОСТРОЕНИЮ: пока цепь не собрана, к ней нечего присоединять.
// Ветвь фактов читает её последней из трёх. Поэтому вхождение ветви — последнее,
// а первое принадлежит цепи и о порядке ветвей не говорит ничего.
//
// Свойство, которое гейт держит, от этого не изменилось: перестановка ветвей
// сдвинет вхождение ветви фактов ВПЕРЁД позиции выдач, и сравнение это увидит —
// что и проверено инъекцией в `TestFactsArmPosDiscriminatesTheArmNotTheChain`.
func factsArmPos(plan string) (pos, count int) {
	pos = -1
	for i := 0; ; {
		j := strings.Index(plan[i:], "relation_fact")
		if j < 0 {
			break
		}
		pos = i + j
		count++
		i = i + j + len("relation_fact")
	}
	return pos, count
}

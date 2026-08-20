// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// walkcost_relations_test.go — S3: УТВЕРЖДЕНИЕ О СТОИМОСТИ РАНЖИРУЕТСЯ ПО ВСЕМ
// ОТНОШЕНИЯМ ПЛАНА, А НЕ ПО ОДНОМУ, НАЗВАННОМУ ПО ИМЕНИ.
//
// Сценарии R7-4-13 и R7-4-14 приёмки R7-4, решение Р6, гейт Г3.
//
// # Предмет — измерен, а не предположен
//
// Утверждение о стоимости обхода стояло в дереве с отбором по ОДНОМУ имени:
// `if a.Relation != "resource_parent_edge" { continue }`. Обход при этом трогает
// девять отношений (сама таблица рёбер, проекция журнала, аккаунты, кластеры и
// пять собственных таблиц iam), а весь запрос вердикта — четырнадцать. Перепись
// снята на этом дереве: до достройки план называл ДЕСЯТЬ отношений, после —
// ЧЕТЫРНАДЦАТЬ (прибавились users, groups, service_accounts, roles; привязки в
// плане уже стояли своей, невходной полосой). То есть покрытие было 1 из 10 и
// стало бы 1 из 14 — проверка, СУЖАЮЩАЯСЯ от каждой правки собственного
// предмета, есть форма без содержания.
//
// # Перечень отношений ВЫВОДИТСЯ, а не выписывается
//
// Выписанный перечень разошёлся бы с представлением на первой же новой ветви —
// тем самым классом, который здесь и чинится. Поэтому имена берутся из ПЛАНА
// исполнения настоящего вопроса (`planrows.Measurement.ByRelation`), а величины
// — существующим доступом пакета (`rowsOf`). Второго прибора не заводится: он
// разошёлся бы с первым молча.
//
// # ЧТО ИМЕННО утверждается о каждом отношении — и почему НЕ абсолютный предел
//
// Утверждается ПРИРОСТ: строк за вердикт на большом облаке минус на малом. Это
// и есть «чтение привязано к предмету запроса, а не к размеру облака», и это
// единственная форма, которая ранжируется по каждому отношению БЕЗ подобранной
// на отношение константы.
//
// Абсолютный предел вида «строк не больше цепи объекта, умноженной на глубину
// обхода» по отношениям НЕ обобщается, и это измерено, а не предположено: у
// `relation_fact` на той же фикстуре 15 строк при цепи из 3 звеньев и пределе
// обхода 4, то есть 15 > 12. Такой предел остаётся там, где он выводится из
// предмета запроса, — на таблице рёбер, отдельным и БОЛЕЕ СИЛЬНЫМ утверждением
// внутри R7-1-18, — а не размазывается по отношениям подобранным числом.
// Потолок, подобранный ПОСЛЕ прогона, описывает полученное число, а не свойство.
//
// # Чего эти пробы НЕ закрывают — сказано прямо
//
// Гейт судит ОТБОР, которым ранжирует утверждение, и делает это на живом плане.
// Он не может заметить утверждения о стоимости, написанного мимо общего
// механизма: такая проба просто не пройдёт через него. Это ограничение, а не
// свойство, и лечится оно обзором, а не этим файлом.

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/planrows"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/scalegrid"
)

// walkCeiling — ПОТОЛОК ПРИРОСТА, объявленный ДО прогона (R7-4-13).
//
// Цепь объекта от размера облака не зависит вовсе, поэтому идеальный прирост —
// ноль. Восемь — запас на дребезг статистики и на смену плана при переходе от
// двухсот объектов к двум тысячам.
//
// Тем же числом меряется и ЦЕНА САМОЙ ДОСТРОЙКИ, и это не переиспользование
// ради экономии: новые ветви представления выбирают строку СОБСТВЕННЫМ КЛЮЧОМ
// объекта, поэтому каждая отдаёт не больше одной строки на шаг обхода, а шагов
// не больше `MaxAncestorDepth`. Тот же порядок величины — тот же потолок.
//
// Константа живёт в пакете, а не в теле пробы, потому что её проверяют ТРИ
// утверждения (R7-1-18, R7-4-13 и гейт Г3); второй экземпляр разошёлся бы с
// первым молча.
const walkCeiling = 8

// walkCostFewCloud / walkCostManyCloud — два облака разного размера при одной и
// той же цепи у измеряемого объекта. Единственный источник обоих чисел: замер,
// сравнивающий РАЗНЫЕ размеры, обязан брать их из одного места.
const walkCostFewCloud, walkCostManyCloud = 200, 2000

// scopeChainBuildOutMigration — префикс миграции, ДОСТРАИВАЮЩЕЙ цепь пяти
// собственным типам iam. Назван префиксом, а не полным именем: имя миграции
// принадлежит её автору и может уточниться, номер — нет.
const scopeChainBuildOutMigration = "785001_*.sql"

// ── ОТБОР, КОТОРЫМ РАНЖИРУЕТ УТВЕРЖДЕНИЕ ────────────────────────────────────

// walkCostSelector — ЧТО ИМЕННО покрывает утверждение о стоимости.
//
// Отбор вынесен параметром не ради гибкости, а ради ИНЪЕКЦИИ: гейт обязан уметь
// вернуть в утверждение ровно тот отбор по имени, который стоял в дереве до этой
// правки, и увидеть находку. Отбор, зашитый в тело цикла, инъекции не поддаётся,
// и «покрывает всё» осталось бы объявлением.
type walkCostSelector func(relation string) bool

// everyRelationOfThePlan — производственный отбор: покрывается КАЖДОЕ отношение,
// которое назвал план. Перечень при этом не выписан нигде — он ВЫВОДИТСЯ, и
// новая ветвь представления попадает под утверждение сама, без правки проб.
func everyRelationOfThePlan(string) bool { return true }

// onlyRelationNamed — отбор, стоявший в дереве ДО этой правки (П14 приёмки).
// Живёт здесь ровно затем, чтобы гейт мог его вернуть и покраснеть.
func onlyRelationNamed(name string) walkCostSelector {
	return func(relation string) bool { return relation == name }
}

// ── РАНЖИРОВАНИЕ ────────────────────────────────────────────────────────────

// walkCostRanking — ИСХОД ранжирования, а не его объявление.
//
// `Ranked` записывается по ходу обхода перечня, а не заявляется до него:
// объявленное покрытие зеленеет при любом теле цикла.
type walkCostRanking struct {
	// Seen — отношения, которые НАЗВАЛ план. Объединение двух планов: отношение,
	// появившееся только на большом облаке, есть рост из ничего, и потерять его
	// нельзя.
	Seen []string
	// Ranked — отношения, по которым утверждение действительно ранжировано.
	Ranked []string
	// Uncovered — Seen без Ranked. НАХОДКА, называемая поимённо и числом.
	Uncovered []string

	Few    map[string]int64
	Many   map[string]int64
	Growth map[string]int64
}

// rankWalkCost — разложить стоимость по отношениям, ВЫВЕДЕННЫМ из плана.
//
// Чистая функция: у гейта и у его инъекций один и тот же предмет, и судить его
// надо без побочных действий, иначе инъекция «обязан покраснеть» роняла бы
// собственный прогон вместо того, чтобы предъявить находку.
func rankWalkCost(few, many planrows.Measurement, sel walkCostSelector) walkCostRanking {
	r := walkCostRanking{
		Few:    map[string]int64{},
		Many:   map[string]int64{},
		Growth: map[string]int64{},
	}
	seen := map[string]struct{}{}
	for _, m := range []planrows.Measurement{few, many} {
		for _, rc := range m.ByRelation {
			seen[rc.Relation] = struct{}{}
		}
	}
	for rel := range seen {
		r.Seen = append(r.Seen, rel)
	}
	sort.Strings(r.Seen)
	for _, rel := range r.Seen {
		r.Few[rel] = rowsOf(few, rel)
		r.Many[rel] = rowsOf(many, rel)
		r.Growth[rel] = r.Many[rel] - r.Few[rel]
		if sel(rel) {
			r.Ranked = append(r.Ranked, rel)
			continue
		}
		r.Uncovered = append(r.Uncovered, rel)
	}
	return r
}

// assertWalkCostRankedByEveryRelation — САМО утверждение о стоимости.
//
// Одно на три пробы: R7-1-18 (обход не платит за размер облака), R7-4-13 (замер
// до и после достройки) и гейт Г3. Второй экземпляр разошёлся бы с первым молча
// — и разошёлся бы ровно там, где расхождение не видно.
func assertWalkCostRankedByEveryRelation(t *testing.T, few, many planrows.Measurement,
	sel walkCostSelector) walkCostRanking {
	t.Helper()
	r := rankWalkCost(few, many, sel)

	// ПРЕДПОСЫЛКА (Г3): план, из которого не выведено ни одного отношения, делает
	// утверждение тождественно верным. Ноль здесь — ОТКАЗ, а не проход.
	if len(r.Seen) == 0 {
		t.Fatalf("из плана не выведено ни одного отношения: утверждение о стоимости стало бы "+
			"тождественно верным, а «ноль находок» — неотличимым от «ноль прочитанного».\n%s",
			many.Census)
	}
	// ОБЪЁМ ОСМОТРЕННОГО печатается ВСЕГДА, включая зелёный прогон (Г3).
	t.Logf("отношений названо планом %d, утверждение ранжировано по %d: %v",
		len(r.Seen), len(r.Ranked), r.Ranked)
	for _, rel := range r.Ranked {
		t.Logf("  %-24s строк за вердикт %d → %d, прирост %d при потолке %d",
			rel, r.Few[rel], r.Many[rel], r.Growth[rel], walkCeiling)
	}

	if len(r.Uncovered) > 0 {
		t.Errorf("утверждение о стоимости не покрывает %d отношений из %d, названных планом: %v. "+
			"Отношение, которое обход трогает, а утверждение не ранжирует, — НАХОДКА: проверка, "+
			"сужающаяся от каждой правки собственного предмета, есть форма без содержания (Р6, П14)",
			len(r.Uncovered), len(r.Seen), r.Uncovered)
	}
	for _, rel := range r.Ranked {
		if r.Growth[rel] > walkCeiling {
			t.Errorf("отношение %s: строк за вердикт %d при %d объектах против %d при %d, прирост %d "+
				"при потолке %d. Чтение платит за размер облака, а не за предмет запроса",
				rel, r.Many[rel], walkCostManyCloud, r.Few[rel], walkCostFewCloud,
				r.Growth[rel], walkCeiling)
		}
	}
	return r
}

// accessesOf — доступы плана к названному отношению.
//
// Нужен там, где утверждение НАМЕРЕННО об одном отношении и предел выводится из
// его устройства. Отбор вынесен в функцию, а не написан отсевом внутри цикла по
// всем доступам: отсев по имени в теле утверждения и есть та форма, которую
// чинит Р6, и следующий читатель не обязан разбирать по комментарию, какое из
// двух перед ним.
func accessesOf(m planrows.Measurement, relation string) []planrows.Access {
	var out []planrows.Access
	for _, a := range m.Accesses {
		if a.Relation == relation {
			out = append(out, a)
		}
	}
	return out
}

// ── ФИКСТУРА ЗАМЕРА ─────────────────────────────────────────────────────────

// walkCostProbe — облако, растущее от малого к большому при неизменной цепи у
// измеряемого объекта, и планы обоих размеров.
type walkCostProbe struct {
	tx  pgx.Tx
	cap *verdictCapture
	f   *gridFixture
}

// newWalkCostProbe — посеять фикстуру и довести её до малого облака.
func newWalkCostProbe(t *testing.T, ctx context.Context) *walkCostProbe {
	t.Helper()
	tx, cap := openProbeTx(t, ctx)
	f := newGridFixture(t, ctx, tx)
	f.growN(t, ctx, walkCostFewCloud)
	f.setR(t, ctx, 1, scalegrid.RecruitDirect)
	f.analyze(t, ctx)
	return &walkCostProbe{tx: tx, cap: cap, f: f}
}

// ask — задать НАСТОЯЩИЙ вопрос вердикта и снять план; вердикт сверяется, потому
// что стоимость неверного ответа мерить нечего.
func (p *walkCostProbe) ask(t *testing.T, ctx context.Context, what string) planrows.Measurement {
	t.Helper()
	v, m := askAndExplain(t, ctx, p.tx, p.cap, probeObjectID)
	if v != relverdict.Allow {
		t.Fatalf("вердикт %s (%s): мерилась бы стоимость неверного ответа", v, what)
	}
	return m
}

// grow — дорастить облако до большого.
func (p *walkCostProbe) grow(t *testing.T, ctx context.Context) {
	t.Helper()
	p.f.growN(t, ctx, walkCostManyCloud)
	p.f.analyze(t, ctx)
}

// ── R7-4-14 / Г3: ГЕЙТ ──────────────────────────────────────────────────────

// TestR7_4_14_CostClaimRanksByEveryRelationOfThePlan — R7-4-14, гейт Г3.
//
// Утверждение о стоимости обязано покрывать КАЖДОЕ отношение, названное планом,
// а не одно, названное по имени. Перечень выводится из плана; число осмотренных
// отношений печатается; отношение, которое план назвал, а утверждение не
// ранжирует, — находка.
func TestR7_4_14_CostClaimRanksByEveryRelationOfThePlan(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	p := newWalkCostProbe(t, ctx)
	mFew := p.ask(t, ctx, "малое облако")
	p.grow(t, ctx)
	mMany := p.ask(t, ctx, "большое облако")

	r := assertWalkCostRankedByEveryRelation(t, mFew, mMany, everyRelationOfThePlan)

	// ПРЕДПОСЫЛКА ГЕЙТА: план обязан содержать таблицу рёбер — иначе судился бы
	// вопрос, обхода не делающий, и покрытие «всего» ничего не означало бы.
	if _, ok := r.Growth["resource_parent_edge"]; !ok {
		t.Fatalf("план не назвал resource_parent_edge: судился бы вопрос без обхода цепи, "+
			"и покрытие плана ничего не утверждало бы.\n%s", mMany.Census)
	}
	if len(r.Ranked) != len(r.Seen) {
		t.Errorf("покрытие %d из %d: утверждение о стоимости у́же собственного предмета",
			len(r.Ranked), len(r.Seen))
	}
}

// ── R7-4-14: ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ ─────────────────────────────────────────

// TestR7_4_14_InjectionByNameFilterIsAFinding — ОБЯЗАН ПОКРАСНЕТЬ.
//
// В утверждение возвращается ровно тот отбор по имени, который стоял в дереве до
// этой правки (П14). Гейт обязан назвать находку И ЧИСЛО непокрытых, а не просто
// не согласиться: число — единственное, чем «стало у́же» отличимо от «нашли одно».
//
// Инъекция кормится ЖИВЫМ планом дерева, а не собранной рукой заготовкой:
// заготовка утверждала бы про свою копию.
func TestR7_4_14_InjectionByNameFilterIsAFinding(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	p := newWalkCostProbe(t, ctx)
	m := p.ask(t, ctx, "малое облако")

	const named = "resource_parent_edge"
	r := rankWalkCost(m, m, onlyRelationNamed(named))

	if len(r.Seen) == 0 {
		t.Fatalf("инъекция беспредметна: план не назвал ни одного отношения.\n%s", m.Census)
	}
	if len(r.Ranked) != 1 || r.Ranked[0] != named {
		t.Fatalf("отбор по имени ранжировал %v, ожидалось ровно [%s]: инъекция воспроизвела не тот дефект",
			r.Ranked, named)
	}
	if want := len(r.Seen) - 1; len(r.Uncovered) != want {
		t.Errorf("непокрытых %d, ожидалось %d при %d отношениях в плане: гейт не считает находки, "+
			"а значит «стало у́же» неотличимо от «нашли одно»",
			len(r.Uncovered), want, len(r.Seen))
	}
	for _, rel := range r.Uncovered {
		if rel == named {
			t.Errorf("отношение %s названо непокрытым, хотя отбор его пропускает: гейт считает не то", rel)
		}
	}
	t.Logf("инъекция «отбор по имени»: план назвал %d отношений, ранжировано 1, находок %d: %v",
		len(r.Seen), len(r.Uncovered), r.Uncovered)
}

// TestR7_4_14_InjectionRelationOutsideThePlanIsNotUncovered — ОБЯЗАН МОЛЧАТЬ.
//
// Законный близнец той же формы: отбор шире плана. Отношение, которого в плане
// НЕТ ВОВСЕ, непокрытым не считается — иначе гейт краснел бы на верной
// реализации, и первый же ложный срабат его отключил бы.
//
// Близнец привязан к `projects` НЕ случайно: это отношение обход читал до
// миграции 781001 и перестал читать после неё. Контроль при этом САМОИСТЕКАЕТ —
// если `projects` когда-нибудь вернётся в план, проба откажет и потребует
// выбрать другое отсутствующее отношение, вместо того чтобы тихо перестать быть
// контролем.
func TestR7_4_14_InjectionRelationOutsideThePlanIsNotUncovered(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx := context.Background()
	p := newWalkCostProbe(t, ctx)
	m := p.ask(t, ctx, "малое облако")

	const absent = "projects"
	r := rankWalkCost(m, m, func(rel string) bool { return rel == absent || everyRelationOfThePlan(rel) })

	for _, rel := range r.Seen {
		if rel == absent {
			t.Fatalf("контроль потерял предмет: отношение %s снова в плане, и близнец перестал быть "+
				"близнецом. Выбери отношение, которого план не называет", absent)
		}
	}
	if len(r.Uncovered) != 0 {
		t.Errorf("гейт назвал непокрытыми %v при отборе шире плана: непокрытым считается то, что план "+
			"назвал, а утверждение пропустило, — а не то, чего в плане нет вовсе", r.Uncovered)
	}
	for _, rel := range r.Ranked {
		if rel == absent {
			t.Errorf("отношение %s попало в ранжированные, хотя плана не касается: перечень выведен "+
				"не из плана", rel)
		}
	}
	t.Logf("контроль «отбор шире плана»: план назвал %d отношений, находок %d — %s в плане нет и "+
		"непокрытым он не считается", len(r.Seen), len(r.Uncovered), absent)
}

// ── R7-4-13: ЗАМЕР ДО И ПОСЛЕ ДОСТРОЙКИ, НА ОДНОМ ДЕРЕВЕ ────────────────────

// gooseBlocks — блоки Up и Down миграции, взятые ИЗ САМОЙ МИГРАЦИИ.
//
// Читается единственный источник, а не его копия: проба, переписавшая
// определение представления своей рукой, мерила бы СВОЮ копию и молчала бы о
// расхождении ровно там, где замер и делается.
//
// Форму, которую разбор не понимает, проба объявляет ОТКАЗОМ, а не пропускает:
// непрочитанный блок дал бы «до», тождественно равное «после», то есть сценарий,
// который нельзя провалить.
func gooseBlocks(t *testing.T, glob string) (up, down string) {
	t.Helper()
	names, err := fs.Glob(migrations.FS, glob)
	if err != nil {
		t.Fatalf("перебор миграций по образцу %s: %v", glob, err)
	}
	if len(names) != 1 {
		t.Fatalf("образцу %s отвечает %d миграций (%v), ожидалась одна: без неё «до» и «после» "+
			"совпадут, и сценарий станет тождественно верным", glob, len(names), names)
	}
	b, err := migrations.FS.ReadFile(names[0])
	if err != nil {
		t.Fatalf("чтение миграции %s: %v", names[0], err)
	}
	txt := string(b)
	if strings.Contains(txt, "+goose StatementBegin") {
		t.Fatalf("миграция %s размечена StatementBegin/End: разбор блоков этой формы не понимает, "+
			"а молчаливый пропуск дал бы «до», равное «после»", names[0])
	}
	const upMark, downMark = "-- +goose Up", "-- +goose Down"
	i, j := strings.Index(txt, upMark), strings.Index(txt, downMark)
	if i < 0 || j <= i {
		t.Fatalf("в миграции %s не найдены оба блока (Up на %d, Down на %d)", names[0], i, j)
	}
	return strings.TrimSpace(txt[i+len(upMark) : j]), strings.TrimSpace(txt[j+len(downMark):])
}

// setScopeChainDefinition — установить определение цепи областей ВНУТРИ пробной
// транзакции.
//
// Транзакция пробы снимается откатом, поэтому подмена определения не переживает
// пробу и соседних баз не касается. Так «до» и «после» оказываются снятыми НА
// ОДНОМ ДЕРЕВЕ и в одном прогоне — а не на двух ревизиях, между которыми могло
// поменяться что угодно ещё.
func setScopeChainDefinition(t *testing.T, ctx context.Context, tx pgx.Tx, sql, what string) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql); err != nil {
		t.Fatalf("установка определения цепи областей (%s): %v", what, err)
	}
}

// TestR7_4_13_WalkCostRankedByEveryRelationBeforeAndAfterTheBuildOut — R7-4-13.
//
// # Что здесь утверждается, и почему это НЕ было верно до работы
//
// Плоскость «обход не платит за размер облака» проверяется ДВАЖДЫ на одном
// дереве: на цепи ДО достройки (положительный контроль — прибор работает и
// свойство держалось) и на цепи ПОСЛЕ (предмет). Обе величины называются.
//
// Односторонний замер здесь не годится вдвойне. Без «до» нечем отличить «новые
// ветви ничего не стоят» от «прибор смотрит не туда»; без «после» нечего
// утверждать вовсе. И ровно эта пара делает сценарий провалимым: пять новых
// ветвей выбирают строку собственным ключом объекта, но ветвь, потерявшая ключ
// или отбор `NOT EXISTS`, читала бы свою таблицу целиком на каждом шаге обхода —
// «до» осталось бы зелёным, «после» покраснело бы.
//
// «До» берётся блоком Down ТОЙ ЖЕ миграции, а не переписанным определением: два
// места об одном предмете разошлись бы молча.
func TestR7_4_13_WalkCostRankedByEveryRelationBeforeAndAfterTheBuildOut(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	up, down := gooseBlocks(t, scopeChainBuildOutMigration)

	ctx := context.Background()
	p := newWalkCostProbe(t, ctx)

	setScopeChainDefinition(t, ctx, p.tx, down, "до достройки")
	beforeFew := p.ask(t, ctx, "до достройки, малое облако")
	setScopeChainDefinition(t, ctx, p.tx, up, "после достройки")
	afterFew := p.ask(t, ctx, "после достройки, малое облако")

	p.grow(t, ctx)

	setScopeChainDefinition(t, ctx, p.tx, down, "до достройки")
	beforeMany := p.ask(t, ctx, "до достройки, большое облако")
	setScopeChainDefinition(t, ctx, p.tx, up, "после достройки")
	afterMany := p.ask(t, ctx, "после достройки, большое облако")

	t.Log("── ДО достройки (положительный контроль) ──")
	before := assertWalkCostRankedByEveryRelation(t, beforeFew, beforeMany, everyRelationOfThePlan)
	t.Log("── ПОСЛЕ достройки (предмет) ──")
	after := assertWalkCostRankedByEveryRelation(t, afterFew, afterMany, everyRelationOfThePlan)

	// ПРЕДПОСЫЛКА: «до» и «после» обязаны РАЗЛИЧАТЬСЯ. Совпади они — подмена
	// определения не подействовала бы, и весь замер стал бы одним замером,
	// названным двумя именами.
	if len(after.Seen) <= len(before.Seen) {
		t.Fatalf("отношений в плане до достройки %d, после %d: подмена определения цепи не "+
			"подействовала, и «до» с «после» — один и тот же замер под двумя именами.\nдо: %v\nпосле: %v",
			len(before.Seen), len(after.Seen), before.Seen, after.Seen)
	}

	// ОБЕ ВЕЛИЧИНЫ НАЗВАНЫ (R7-4-13).
	t.Logf("стоимость вердикта на одном дереве: ДО достройки отношений %d, строк %d → %d · "+
		"ПОСЛЕ отношений %d, строк %d → %d · прибавились %v",
		len(before.Seen), beforeFew.Rows, beforeMany.Rows,
		len(after.Seen), afterFew.Rows, afterMany.Rows,
		addedRelations(before.Seen, after.Seen))

	// ПРОЧИТАНО НЕ НОЛЬ (R7-4-13): прибор, дающий ноль, делает плоскость
	// тождественно верной — и делает это одинаково на исправном и на сломанном.
	for _, c := range []struct {
		what string
		m    planrows.Measurement
	}{
		{"до достройки, малое облако", beforeFew},
		{"до достройки, большое облако", beforeMany},
		{"после достройки, малое облако", afterFew},
		{"после достройки, большое облако", afterMany},
	} {
		if c.m.Rows == 0 {
			t.Fatalf("%s: прочитано 0 строк при непустой цепи — прибор смотрел не туда, "+
				"и плоскость тождественно верна.\n%s", c.what, c.m.Census)
		}
	}

	// ЦЕНА САМОЙ ДОСТРОЙКИ: пять новых ветвей выбирают строку собственным ключом
	// объекта, поэтому идеальная прибавка — ноль, а потолок тот же (см. godoc
	// walkCeiling).
	if d := afterMany.Rows - beforeMany.Rows; d > walkCeiling {
		t.Errorf("достройка прибавила %d строк за вердикт (%d против %d) при потолке %d: ветвь, "+
			"потерявшая ключ объекта или отбор NOT EXISTS, читает свою таблицу на каждом шаге обхода",
			d, afterMany.Rows, beforeMany.Rows, walkCeiling)
	}
}

// addedRelations — что план стал называть после достройки и не называл до неё.
// Печатается рядом с числами: два числа без состава не дают проверить, ЧТО
// именно прибавилось.
func addedRelations(before, after []string) []string {
	was := map[string]struct{}{}
	for _, rel := range before {
		was[rel] = struct{}{}
	}
	var added []string
	for _, rel := range after {
		if _, ok := was[rel]; !ok {
			added = append(added, rel)
		}
	}
	return added
}

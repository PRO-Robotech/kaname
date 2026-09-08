// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package planrows_test

// extract_test.go — САМОПРОВЕРКИ ПРИБОРА: проверяется он сам, а не то, что он мерит.
//
// # Предмет
//
// Прибор порядков (R7-1, стадия S1) снимает несущую величину — строки, отданные
// узлами плана, с множителем числа циклов. Величина, снятая неверно, двигается
// ровно так же, как верная, поэтому проба на подвижность зелена при любом из
// разобранных дефектов. Здесь проверяется другое: что прибор мерит ИМЕННО ТУ
// величину, которую назвал.
//
// # Форма каждой пробы — пара, а не одно утверждение
//
// У каждого класса стоят оба плеча: положительное (прибор ловит) и отрицательное
// (законный близнец, на котором он обязан молчать). Одно плечо без второго
// неотличимо от проверки, которая ловит форму: множитель, применённый ко всему
// подряд, ловит `loops = 2` и завышает `loops = 1`; схлопывание по имени убирает
// задвоение bitmap-пары и теряет вторую ветвь `UNION`.
//
// # Почему на синтетике, а не только на живом плане
//
// Синтетика даёт вход, которого на живом плане СЕГОДНЯ нет: `Gather` не появился
// ни на одной точке замера, узел с неизвестным типом не появится вовсе, а
// `Bitmap Index Scan` без предка встречается не на каждом плане. Проба, стоящая
// только на живом, была бы зелёной всегда — и именно там, где утверждение важнее
// всего. Живой план проверяется отдельно и в своём месте (пакет `relverdict`):
// там предмет другой — что текст запроса берётся у продукта, а не переписан.

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/planrows"
)

// verdictRelations — отношения, которые читает запрос вердикта.
//
// Это ПРЕДПОСЫЛКА замера, а не перечень для разложения: разложение прибор берёт
// из плана. Здесь набор нужен затем, чтобы отказ «в плане нет ни одного из
// ожидаемых отношений» вообще имел с чем сравниваться.
var verdictRelations = []string{
	"relation_fact", "access_bindings", "access_binding_subjects",
	"role_verb", "role_rule_selectors", "group_members",
	"resource_parent_edge", "resource_mirror",
}

func mustExtract(t *testing.T, plan string) planrows.Measurement {
	t.Helper()
	m, err := planrows.Extract([]byte(plan), verdictRelations)
	if err != nil {
		t.Fatalf("прибор отказал на плане, где предпосылка выполнена: %v", err)
	}
	return m
}

func rowsOf(t *testing.T, m planrows.Measurement, relation string) int64 {
	t.Helper()
	for _, r := range m.ByRelation {
		if r.Relation == relation {
			return r.Rows
		}
	}
	t.Fatalf("отношения %q нет в разложении: %s", relation, m.Census)
	return 0
}

func accessesOf(t *testing.T, m planrows.Measurement, relation string) int {
	t.Helper()
	for _, r := range m.ByRelation {
		if r.Relation == relation {
			return r.Accesses
		}
	}
	t.Fatalf("отношения %q нет в разложении: %s", relation, m.Census)
	return 0
}

// ── 1. МНОЖИТЕЛЬ ЧИСЛА ЦИКЛОВ ────────────────────────────────────────────────

// TestExtract_LoopsMultiplierCountsEveryCycle — положительное плечо.
//
// `Actual Rows` в JSON плана — среднее НА ОДИН ЦИКЛ, а не итог узла. Рекурсивный
// обход идёт с `loops = 2` на каждой точке замера, поэтому без множителя величина
// занижается ровно вдвое — и занижается тем сильнее, чем дороже запрос, то есть в
// удобную сторону: кривая по любой оси выходит тем площе, чем хуже дело.
func TestExtract_LoopsMultiplierCountsEveryCycle(t *testing.T) {
	m := mustExtract(t, loopsTwoPlan)

	const wantEdge = 4 // 2 строки × 2 цикла
	if got := rowsOf(t, m, "resource_parent_edge"); got != wantEdge {
		t.Fatalf("узел с двумя циклами учтён как один: у resource_parent_edge %d строк, ожидалось %d "+
			"(Actual Rows = 2, Actual Loops = 2).\nПерепись:\n%s", got, wantEdge, m.Census)
	}
	// Неотнесённое считается по тому же правилу: `WorkTable Scan` идёт с двумя
	// циклами и его вклад тоже удваивается.
	const wantUnattributed = 1*1 + 1*2 // Result + WorkTable Scan
	if m.UnattributedRows != wantUnattributed {
		t.Fatalf("множитель применён к отнесённым и не применён к неотнесённым: %d против %d.\nПерепись:\n%s",
			m.UnattributedRows, wantUnattributed, m.Census)
	}
}

// TestExtract_LoopsMultiplierLeavesSingleCycleAlone — отрицательное плечо.
//
// Законный близнец: тот же план с `loops = 1`. Множитель, применённый «на всякий
// случай», прошёл бы положительное плечо и завысил бы здесь — то есть завысил бы
// КАЖДУЮ точку сетки, где циклов нет.
func TestExtract_LoopsMultiplierLeavesSingleCycleAlone(t *testing.T) {
	one := mustExtract(t, loopsOnePlan)
	two := mustExtract(t, loopsTwoPlan)

	const wantEdge = 2 // 2 строки × 1 цикл
	if got := rowsOf(t, one, "resource_parent_edge"); got != wantEdge {
		t.Fatalf("на плане без циклов величина изменилась: %d вместо %d.\nПерепись:\n%s",
			got, wantEdge, one.Census)
	}
	if rowsOf(t, two, "resource_parent_edge") != 2*rowsOf(t, one, "resource_parent_edge") {
		t.Fatalf("множитель не различает планы: с двумя циклами %d, с одним %d — "+
			"отношение обязано быть ровно двойкой",
			rowsOf(t, two, "resource_parent_edge"), rowsOf(t, one, "resource_parent_edge"))
	}
}

// ── 2. СХЛОПЫВАНИЕ BITMAP-ПАРЫ ПО РОДСТВУ ────────────────────────────────────

// TestExtract_BitmapPairCollapsesByKinship — положительное плечо.
//
// `Bitmap Heap Scan` (родитель) несёт `Relation Name`, `Bitmap Index Scan`
// (ребёнок) — только `Index Name`. Наивная сумма листьев задваивает отношение:
// наблюдалось 4 против 2 на `role_rule_selectors`.
func TestExtract_BitmapPairCollapsesByKinship(t *testing.T) {
	m := mustExtract(t, fullPlan)

	const want = 2
	if got := rowsOf(t, m, "role_rule_selectors"); got != want {
		t.Fatalf("bitmap-пара сосчитана дважды либо потеряна: у role_rule_selectors %d строк, "+
			"ожидалось %d (родитель 2, ребёнок — его вход, а не отдельная работа).\nПерепись:\n%s",
			got, want, m.Census)
	}
	if got := accessesOf(t, m, "role_rule_selectors"); got != 1 {
		t.Fatalf("bitmap-пара обязана дать ОДИН доступ, а не %d.\nПерепись:\n%s", got, m.Census)
	}
	// Ребёнок остаётся ОТНЕСЁННЫМ и видимым: он не выпадает из переписи, у него
	// лишь не берутся строки. Иначе «не отнесено» росло бы от каждой bitmap-пары.
	var collapsed int
	for _, a := range m.Accesses {
		if a.Collapsed {
			collapsed++
			if a.Relation != "role_rule_selectors" {
				t.Fatalf("схлопнут не тот узел: %+v", a)
			}
		}
	}
	if collapsed != 1 {
		t.Fatalf("схлопнутых узлов %d, ожидался ровно один.\nПерепись:\n%s", collapsed, m.Census)
	}
}

// TestExtract_TwoIndexScansOnOneRelationStayTwo — отрицательное плечо, и оно
// измерено, а не придумано.
//
// `group_members` даёт ДВА `Index Scan` — это две ветви `UNION` внутри CTE
// `speaker` (голая форма `group:<id>` и каноническая `group:<id>#member`), а не
// дубль. Схлопывание по ИМЕНИ отношения прошло бы положительное плечо выше и
// потеряло бы здесь половину настоящего доступа.
func TestExtract_TwoIndexScansOnOneRelationStayTwo(t *testing.T) {
	m := mustExtract(t, fullPlan)

	if got := accessesOf(t, m, "group_members"); got != 2 {
		t.Fatalf("две ветви UNION по group_members схлопнуты в %d доступ(а): схлопывание идёт "+
			"по ИМЕНИ отношения вместо родства, и настоящий доступ потерян.\nПерепись:\n%s",
			got, m.Census)
	}
	if got := rowsOf(t, m, "group_members"); got != 2 {
		t.Fatalf("у group_members %d строк, ожидалось 2 (по одной на ветвь).\nПерепись:\n%s",
			got, m.Census)
	}
}

// ── 3. ДВА КЛЮЧА ОТНЕСЕНИЯ И КОРЗИНА НЕОТНЕСЁННОГО ──────────────────────────

// TestExtract_IndexNameWithoutRelationNameIsResolvedThroughThePlanDictionary —
// положительное плечо второго ключа.
//
// Справочник «индекс → отношение» собирается ИЗ ЭТОГО ЖЕ ПЛАНА по узлам, несущим
// оба ключа. Выписанный в коде прибора справочник — ровно тот класс, что
// «рукописный перечень разошёлся с деревом»: он не двигается от нового отношения
// в запросе и продолжает печатать нули по своим.
func TestExtract_IndexNameWithoutRelationNameIsResolvedThroughThePlanDictionary(t *testing.T) {
	m := mustExtract(t, dictionaryPlan)

	if got := accessesOf(t, m, "access_bindings"); got != 2 {
		t.Fatalf("узел с одним лишь Index Name не отнесён: доступов к access_bindings %d, "+
			"ожидалось 2.\nПерепись:\n%s", got, m.Census)
	}
	const want = 4 + 6
	if got := rowsOf(t, m, "access_bindings"); got != want {
		t.Fatalf("у access_bindings %d строк, ожидалось %d: узел без предка Bitmap Heap Scan "+
			"схлопывать не с чем, и его строки — отдельная работа.\nПерепись:\n%s",
			got, want, m.Census)
	}
	if m.Unattributed != 1 { // один Nested Loop
		t.Fatalf("не отнесено %d узлов, ожидался ровно Nested Loop.\nПерепись:\n%s",
			m.Unattributed, m.Census)
	}
}

// TestExtract_NodeWithNeitherKeyIsUnattributedAndStillCounted — отрицательное
// плечо: узел, у которого нет ни одного ключа, обязан попасть в корзину «не
// отнесено» И БЫТЬ ПОСЧИТАННЫМ.
//
// Молча выпасть он не вправе: «отнесено всё» читалось бы из молчания, а молчание
// здесь означает три четверти узлов — на снятых планах к отношению не отнесено
// 76–78 %.
func TestExtract_NodeWithNeitherKeyIsUnattributedAndStillCounted(t *testing.T) {
	m := mustExtract(t, neitherKeyPlan)

	if m.Unattributed != 2 { // Nested Loop + Function Scan
		t.Fatalf("не отнесено %d узлов, ожидалось 2 (Nested Loop и Function Scan).\nПерепись:\n%s",
			m.Unattributed, m.Census)
	}
	const wantUnattributedRows = 9 + 3
	if m.UnattributedRows != wantUnattributedRows {
		t.Fatalf("строки неотнесённых узлов потеряны: %d вместо %d.\nПерепись:\n%s",
			m.UnattributedRows, wantUnattributedRows, m.Census)
	}
	// Положительный контроль в той же фикстуре: рядом стоит законное отношение,
	// иначе «не отнесено 2» было бы неотличимо от «прибор не отнёс ничего».
	if got := rowsOf(t, m, "relation_fact"); got != 5 {
		t.Fatalf("соседнее законное отношение не отнесено: у relation_fact %d строк.\nПерепись:\n%s",
			got, m.Census)
	}
	if m.Nodes != m.Attributed+m.Unattributed {
		t.Fatalf("перепись не сходится: узлов %d, отнесено %d, не отнесено %d — "+
			"разница означает узел, выпавший молча", m.Nodes, m.Attributed, m.Unattributed)
	}
}

// ── 4. ОТКАЗ ВМЕСТО НУЛЯ ─────────────────────────────────────────────────────

// TestExtract_RefusesWhenPlanHasNoneOfTheExpectedRelations — положительное плечо.
//
// «Ноль строк» на плане, где смотреть было негде, означает «не нашли, где
// смотреть», а не «работы не было». Разница — весь смысл замера: первое обязано
// быть исходом «не выполнилось» с текстом, второе — числом.
func TestExtract_RefusesWhenPlanHasNoneOfTheExpectedRelations(t *testing.T) {
	_, err := planrows.Extract([]byte(singleScanPlan), []string{"accounts", "users"})
	if err == nil {
		t.Fatal("прибор отдал число по плану, где нет ни одного ожидаемого отношения: " +
			"ноль в этом случае неотличим от «работы не было»")
	}
	if !errors.Is(err, planrows.ErrPreconditionNotMet) {
		t.Fatalf("отказ обязан быть исходом «условие не создано», а не ошибкой разбора: %v", err)
	}
	if !strings.Contains(err.Error(), "accounts") {
		t.Fatalf("отказ не называет, чего искали: %v", err)
	}
}

// TestExtract_FullPlanYieldsANumber — отрицательное плечо.
//
// Прибор, отказывающий всегда, прошёл бы плечо выше и не измерил бы ни одной
// точки сетки.
func TestExtract_FullPlanYieldsANumber(t *testing.T) {
	m := mustExtract(t, fullPlan)

	// 2 (rrs) + 1 + 1 (gm) + 4 (edge) + 3 (ab) + 5 (rf)
	const wantRows = 16
	if m.Rows != wantRows {
		t.Fatalf("несущая величина %d, ожидалось %d.\nПерепись:\n%s", m.Rows, wantRows, m.Census)
	}
	if len(m.ByRelation) != 5 {
		t.Fatalf("отношений в разложении %d, ожидалось 5.\nПерепись:\n%s", len(m.ByRelation), m.Census)
	}
}

// ── 5. КОРЗИНА НЕИЗВЕСТНОГО ТИПА ─────────────────────────────────────────────

// TestExtract_UnknownNodeTypeGoesToItsOwnBucketWithACount — положительное плечо.
func TestExtract_UnknownNodeTypeGoesToItsOwnBucketWithACount(t *testing.T) {
	m := mustExtract(t, unknownTypePlan)

	if len(m.UnknownTypes) != 1 {
		t.Fatalf("незнакомых типов в корзине %d, ожидался один (Custom Scan).\nПерепись:\n%s",
			len(m.UnknownTypes), m.Census)
	}
	got := m.UnknownTypes[0]
	if got.NodeType != "Custom Scan" || got.Nodes != 1 || got.Rows != 11 {
		t.Fatalf("корзина неизвестного типа: %+v, ожидалось {Custom Scan 1 11}.\nПерепись:\n%s",
			got, m.Census)
	}
	// Из суммы он при этом НЕ выпадает: тип неизвестен, но строки прочитаны.
	if m.UnattributedRows != 2+11 {
		t.Fatalf("строки узла неизвестного типа выпали из суммы: не отнесено %d, ожидалось %d.\n"+
			"Перепись:\n%s", m.UnattributedRows, 2+11, m.Census)
	}
	if !strings.Contains(m.Census, "Custom Scan") {
		t.Fatalf("перепись молчит о незнакомом типе:\n%s", m.Census)
	}
}

// TestExtract_KnownNodeTypesStayOutOfTheUnknownBucket — отрицательное плечо.
//
// Корзина, в которую попадает всё подряд, прошла бы плечо выше и объявляла бы
// незнакомым каждый узел каждого плана — то есть не сообщала бы ничего.
func TestExtract_KnownNodeTypesStayOutOfTheUnknownBucket(t *testing.T) {
	m := mustExtract(t, fullPlan)

	if len(m.UnknownTypes) != 0 {
		t.Fatalf("знакомые типы попали в корзину незнакомых: %+v.\nПерепись:\n%s",
			m.UnknownTypes, m.Census)
	}
}

// ── 6. ПЕРЕПИСЬ ПЕЧАТАЕТСЯ ВСЕГДА ────────────────────────────────────────────

// TestExtract_CensusIsPrintedEvenWhenNothingIsUnattributed.
//
// «Не отнесено 0» — это ЦЕЛЬ, а не поломка. Проба, падающая на достижении своей
// цели, толкает держать неотнесённый узел ради зелёного; перепись поэтому
// печатается и здесь, и объём осмотренного объявляется числом.
func TestExtract_CensusIsPrintedEvenWhenNothingIsUnattributed(t *testing.T) {
	m := mustExtract(t, singleScanPlan)

	if m.Unattributed != 0 {
		t.Fatalf("на плане из одного скана не отнесено %d узлов.\nПерепись:\n%s",
			m.Unattributed, m.Census)
	}
	for _, want := range []string{
		"узлов разобрано 1", "отнесено 1", "не отнесено 0", "отношений 1",
	} {
		if !strings.Contains(m.Census, want) {
			t.Fatalf("перепись не печатает %q — «ноль находок» неотличимо от «ноль прочитанного»:\n%s",
				want, m.Census)
		}
	}
	if !strings.Contains(m.Census, "0.0 %") && !strings.Contains(m.Census, "0 %") {
		t.Fatalf("перепись не печатает ДОЛЮ неотнесённого:\n%s", m.Census)
	}
}

// TestExtract_CensusNamesTheShareOfUnattributedNodes — доля печатается и тогда,
// когда она велика: на снятых планах не отнесено 76–78 % узлов, и без этой строки
// «отнесено всё» читается из молчания.
func TestExtract_CensusNamesTheShareOfUnattributedNodes(t *testing.T) {
	m := mustExtract(t, fullPlan)

	if m.Unattributed == 0 {
		t.Fatalf("фикстура выродилась: на полном плане обязаны быть неотнесённые узлы.\n%s", m.Census)
	}
	share := float64(m.Unattributed) / float64(m.Nodes) * 100
	if m.UnattributedShare < share-0.05 || m.UnattributedShare > share+0.05 {
		t.Fatalf("доля неотнесённого %.1f %% расходится со счётом %d/%d",
			m.UnattributedShare, m.Unattributed, m.Nodes)
	}
	if !strings.Contains(m.Census, "%") {
		t.Fatalf("перепись не печатает долю неотнесённого:\n%s", m.Census)
	}
}

// ── 7. ОТБРОШЕННОЕ, ДОСТАВАНИЕ ИЗ КУЧИ, РАБОТНИКИ ────────────────────────────

// TestExtract_JoinFilterIsReadByNodeAndHeapFetchesAndWorkersArePrinted.
//
// Отброшенное соединением берётся УЗЛАМИ, а не отношениями: у `Nested Loop`
// `Relation Name` нет вовсе, относить его не к чему. Ось «отброшенное по четырём
// отношениям пути вердикта» измерена ТОЖДЕСТВЕННО НУЛЁМ при рабочем извлекателе
// (положительный контроль дал 2999 на заведомо отбрасывающем запросе) — поэтому
// проба, утверждающая движение той величины, зелёной не станет никогда, и её
// здесь нет намеренно.
func TestExtract_JoinFilterIsReadByNodeAndHeapFetchesAndWorkersArePrinted(t *testing.T) {
	m := mustExtract(t, fullPlan)

	if m.JoinFilterRemoved != 12 {
		t.Fatalf("отброшенное соединением %d, ожидалось 12.\nПерепись:\n%s",
			m.JoinFilterRemoved, m.Census)
	}
	if len(m.JoinFilters) != 1 || m.JoinFilters[0].NodeType != "Nested Loop" {
		t.Fatalf("отброшенное соединением обязано быть отнесено к УЗЛУ: %+v.\nПерепись:\n%s",
			m.JoinFilters, m.Census)
	}
	if m.HeapFetches != 1 {
		t.Fatalf("Heap Fetches %d, ожидалась 1 (наблюдалась на широкой оси).\nПерепись:\n%s",
			m.HeapFetches, m.Census)
	}
	// Отброшенное фильтром входит в `Touched`, а `Actual Rows` остаётся видимым
	// порознь: их РАЗНОСТЬ и есть то, что прячет неисправленный индекс.
	if m.Removed != 20+12+3 {
		t.Fatalf("сумма отброшенного %d, ожидалось %d (фильтр 20 + соединение 12 + перепроверка 3).\n"+
			"Перепись:\n%s", m.Removed, 35, m.Census)
	}
	// Отброшенное схлопыванию НЕ подлежит: перепроверка снята на предке
	// bitmap-пары, и её три строки — не те же самые, что отдал ребёнок, а другие.
	// Снять их заодно со схлопыванием значило бы спрятать работу, ради видимости
	// которой отброшенное и печатается.
	var rrsRemoved int64
	for _, rc := range m.ByRelation {
		if rc.Relation == "role_rule_selectors" {
			rrsRemoved = rc.Removed
		}
	}
	if rrsRemoved != 3 {
		t.Fatalf("отброшенное перепроверкой на bitmap-паре потеряно: у role_rule_selectors %d, "+
			"ожидалось 3.\nПерепись:\n%s", rrsRemoved, m.Census)
	}
	// Слагаемые ПОРОЗНЬ: слитое число не различает «нужен индекс» (фильтр) и
	// «не хватило памяти под bitmap» (перепроверка), а лечится это по-разному.
	if m.RemovedByFilter != 20 || m.RemovedByRecheck != 3 {
		t.Fatalf("слагаемые отброшенного слиты: фильтром %d (ожидалось 20), "+
			"перепроверкой %d (ожидалось 3).\nПерепись:\n%s",
			m.RemovedByFilter, m.RemovedByRecheck, m.Census)
	}
	if m.RemovedByFilter+m.RemovedByRecheck+m.JoinFilterRemoved != m.Removed {
		t.Fatalf("слагаемые не сходятся с суммой: %d + %d + %d != %d",
			m.RemovedByFilter, m.RemovedByRecheck, m.JoinFilterRemoved, m.Removed)
	}
	if m.Touched != m.Rows+m.Removed {
		t.Fatalf("тронутое %d не равно отданному %d плюс отброшенному %d",
			m.Touched, m.Rows, m.Removed)
	}
	if m.WorkersLaunched != 0 {
		t.Fatalf("на плане без Gather запущено работников %d.\nПерепись:\n%s",
			m.WorkersLaunched, m.Census)
	}
}

// TestExtract_WorkersLaunchedIsReadWhenTheePlanIsParallel — отрицательное плечо к
// предыдущему: величина читается, когда она есть.
//
// Плечо про множитель на ЭТОТ план не опирается намеренно: `Gather` на
// естественном плане не появился ни разу, включая N = 10⁵, при обеих несущих
// таблицах выше порога параллельного скана. Условие обосновано рекурсивным
// обходом и вложенным циклом, которые наблюдаются на КАЖДОЙ точке.
func TestExtract_WorkersLaunchedIsReadWhenTheePlanIsParallel(t *testing.T) {
	m := mustExtract(t, gatherPlan)

	if m.WorkersLaunched != 2 {
		t.Fatalf("запущено работников %d, ожидалось 2.\nПерепись:\n%s", m.WorkersLaunched, m.Census)
	}
	// 4 строки × 3 цикла — вот во что обходится отсутствие множителя под Gather:
	// без него сумма занижается в 1.6× (26 против 42 на принудительном прогоне).
	if got := rowsOf(t, m, "relation_fact"); got != 12 {
		t.Fatalf("под Gather величина занижена: %d вместо 12 (4 × 3).\nПерепись:\n%s", got, m.Census)
	}
}

// ── 8. ПРАВИЛО ОТНЕСЕНИЯ ОБЪЯВЛЕНО ДО ПРОГОНА ────────────────────────────────

// TestExtract_AttributionRuleIsDeclaredInCodeAndPrintedVerbatim.
//
// Правило, впервые появившееся в отчёте, неотличимо от правила, подобранного под
// полученные числа. Поэтому оно живёт в коде прибора, приезжает своим коммитом
// раньше первой измеренной величины и печатается ДОСЛОВНО отсюда — так, что
// расхождение между объявленным и напечатанным невозможно.
func TestExtract_AttributionRuleIsDeclaredInCodeAndPrintedVerbatim(t *testing.T) {
	if strings.TrimSpace(planrows.AttributionRule) == "" {
		t.Fatal("правило отнесения не объявлено")
	}
	m := mustExtract(t, fullPlan)
	if !strings.Contains(m.Census, strings.TrimSpace(planrows.AttributionRule)) {
		t.Fatalf("перепись печатает не то правило, что объявлено в коде:\n%s", m.Census)
	}
}

// TestExtract_RefusesWhenExpectationIsEmpty — предпосылка обязана быть названа.
//
// Пустой перечень ожидаемого делает отказ пункта 4 невозможным by construction:
// пересечение с пустым множеством пусто всегда, и «не нашли, где смотреть»
// перестало бы отличаться от чего бы то ни было.
func TestExtract_RefusesWhenExpectationIsEmpty(t *testing.T) {
	if _, err := planrows.Extract([]byte(fullPlan), nil); !errors.Is(err, planrows.ErrPreconditionNotMet) {
		t.Fatalf("прибор принял замер без объявленной предпосылки: %v", err)
	}
}

// TestExtract_MalformedPlanIsAnErrorNotAZero — разбор, не сумевший прочитать
// план, обязан отказать, а не отдать ноль.
func TestExtract_MalformedPlanIsAnErrorNotAZero(t *testing.T) {
	for _, tc := range []struct{ name, plan string }{
		{"не JSON", "не план вовсе"},
		{"пустой массив", "[]"},
		{"нет ключа Plan", `[{"Execution Time": 1.0}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := planrows.Extract([]byte(tc.plan), verdictRelations); err == nil {
				t.Fatal("прибор отдал число по плану, который не прочитан")
			}
		})
	}
}

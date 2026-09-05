// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package planrows — прибор порядков: несущая величина замера снимается с ПЛАНА
// запроса, а не с часов, не со счётчика страниц и не с числа отданных клиенту
// строк.
//
// # Почему план, а не что-нибудь дешевле
//
// Вопрос, ради которого прибор существует, звучит «растёт ли РАБОТА от размера
// облака». Отданные клиенту строки на него не отвечают вовсе: внешний запрос
// вердикта несёт `LIMIT`, поэтому их число ограничено сверху ТОЖДЕСТВЕННО — на
// любом дереве, включая сломанное. Страницы буферного кэша — наблюдение о машине
// и о том, что в кэш попало. Миллисекунды — о машине. План говорит ровно про
// работу и ни про что другое.
//
// # Прибор живёт РЯДОМ С ЖИВЫМ и обязан с ним сверяться
//
// Вторая, СВЕРОЧНАЯ величина — `pg_stat_xact_all_tables`
// (`relverdict/list_page_cost_integration_test.go`): её считает сам Postgres.
// Две величины расходятся by construction — счётчик считает строки, ТРОНУТЫЕ
// сканом, а `Actual Rows` — ОТДАННЫЕ узлом после фильтра, — и величина этого
// расхождения есть ровно то, что прячет неисправленный индекс. Расхождение
// законно; молчание о нём — нет: несказанное расхождение неотличимо от прибора,
// меряющего не ту величину. Сверка при этом читается ТОЛЬКО внутри одного плана:
// между точками, где план сменился, отношение двух величин описывает смену
// плана, а не погрешность (измерено: 2.11 → 0.94 при перевороте плана).
//
// # Чего прибор НЕ делает
//
// Он не решает, хорошо ли число. Он не сравнивает точки между собой. Он не
// знает про сетку. Его предмет — одна величина с одного плана, и объём
// осмотренного при этом объявлен числом, а не подразумевается.
//
// # Почему пакет лежит ЗДЕСЬ — четыре причины, и каждая проверяема
//
//  1. РЯДОМ СО СВЕРОЧНЫМ. Второй прибор живёт в соседнем каталоге
//     (`relverdict`), и снимать обе величины на одной фикстуре надо в одном
//     прогоне. Дальше — значит через границу пакета, то есть через копию
//     фикстуры.
//  2. УЖЕ В ОТБОРЕ. Путь содержит `/internal/repo/`, поэтому интеграционная
//     джоба берёт пакет ПО ПУТИ, без правки Makefile и `ci.yaml`. Ни
//     `PG_OUTSIDE_SELECTION_PKGS`, ни перепись `shortgatedselection_test.go`
//     этим изменением не задеваются: пробы пакета под кратким режимом не
//     пропускаются вовсе — они не поднимают контейнер и потому исполняются
//     ОБЕИМИ волнами.
//  3. НЕ ВНУТРИ `relverdict`. Отпечаток предмета замера выводится по
//     НЕ-ТЕСТОВЫМ файлам каталога `relverdict/`; прибор, положенный туда, делал
//     бы правку САМОГО СЕБЯ неотличимой от правки измеряемого — и отчёт
//     объявлялся бы устаревшим при починке опечатки в приборе.
//  4. КОНТЕЙНЕРА НЕ ПОДНИМАЕТ. Разбор JSON базы не требует, поэтому к шарду iam
//     (398 проб) пакет добавляет миллисекунды разбора, а не старт Postgres.
//     Живая точка ставится в УЖЕ существующий контейнер `relverdict`, а не
//     заводит свой.
package planrows

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

// ErrPreconditionNotMet — условие замера не создано.
//
// Отдельная категория исхода, никогда не сворачиваемая ни в «зелено», ни в
// «красно». «Ноль строк» по плану, где смотреть было негде, означает «не нашли,
// где смотреть», а не «работы не было», и разница между этими двумя — весь смысл
// замера: первое обязано быть отказом с текстом, второе — числом.
var ErrPreconditionNotMet = errors.New("planrows: условие замера не создано")

// AttributionRule — правило отнесения, объявленное ДО прогона.
//
// Оно живёт В КОДЕ прибора, а не в прозе отчёта, ровно по одной причине: отчёт
// пишется после прогона, и правило, впервые появившееся в нём, неотличимо от
// правила, подобранного под полученные числа. Отсюда оно печатается в перепись
// ДОСЛОВНО — так, что расхождение между объявленным и напечатанным невозможно.
//
// Каждый пункт выведен из НАБЛЮДЁННОГО плана запроса вердикта, а не из общих
// соображений; где именно наблюдался — сказано в пункте.
const AttributionRule = `ПРАВИЛО ОТНЕСЕНИЯ (объявлено до прогона; перепись печатает его дословно из кода)

1. ЕДИНИЦА. Строки, ОТДАННЫЕ узлом, помноженные на число циклов:
   Actual Rows × max(Actual Loops, 1). "Actual Rows" в JSON плана — среднее НА
   ОДИН ЦИКЛ, а не итог узла. Множитель обязателен: рекурсивный обход идёт с
   loops = 2 на каждой точке, вложенный цикл — по числу строк внешней стороны,
   параллельный план — по числу работников. Без множителя величина занижается
   тем сильнее, чем дороже запрос.

2. ОТНЕСЕНИЕ УЗЛА К ОТНОШЕНИЮ — ДВА КЛЮЧА, В ЭТОМ ПОРЯДКЕ:
   ключ 1 — "Relation Name";
   ключ 2 — при пустом "Relation Name" берётся "Index Name" и разрешается
            в отношение: сперва по справочнику "индекс → отношение", СОБРАННОМУ
            ИЗ ЭТОГО ЖЕ ПЛАНА (узлы, несущие оба ключа), затем по ближайшему
            предку "Bitmap Heap Scan". Справочник выводится из плана, а не
            выписывается в коде: выписанный не двигается от нового отношения в
            запросе и продолжает печатать нули по своим.

3. УСТРАНЕНИЕ ДВОЙНОГО СЧЁТА — ПО РОДСТВУ, НИКОГДА ПО ИМЕНИ.
   "Bitmap Index Scan", у которого есть предок "Bitmap Heap Scan", даёт вход
   этого предка, а не отдельную работу: узел остаётся ОТНЕСЁННЫМ и видимым, но
   его ОТДАННЫЕ строки в сумму не входят. Схлопывание по ИМЕНИ отношения
   запрещено: два "Index Scan" по одному отношению бывают двумя ветвями UNION,
   и такое схлопывание потеряло бы половину настоящего доступа.
   ОТБРОШЕННОЕ схлопыванию НЕ подлежит: отброшенное предком и отброшенное
   ребёнком — РАЗНЫЕ строки, а не одни и те же, посчитанные дважды. Снимать их
   заодно значило бы прятать работу, ради видимости которой пункт 4 и написан.

4. ОТБРОШЕННОЕ ПЕЧАТАЕТСЯ РЯДОМ С ОТДАННЫМ, А НЕ ВМЕСТО.
   "Rows Removed by Filter" и "Rows Removed by Index Recheck" — по отношениям;
   "Rows Removed by Join Filter" — ПО УЗЛАМ, потому что у соединения
   "Relation Name" нет вовсе и относить его не к чему. Фильтр применяется ВНУТРИ
   узла, поэтому скан, прочитавший пол-таблицы ради пятидесяти строк, честно
   отчитывается пятьюдесятью; его настоящая цена лежит в отброшенном.
   Все три — величины НА ЦИКЛ и умножаются на число циклов.
   "Heap Fetches" и "Workers Launched" — величины итоговые и НЕ умножаются.

5. НЕОТНЕСЁННОЕ И НЕЗНАКОМОЕ НЕ ИСЧЕЗАЮТ.
   Узел, не отнесённый ни одним ключом, попадает в корзину "не отнесено" — с
   числом узлов, их долей и их строками. Узел, чей тип прибору неизвестен,
   попадает СВЕРХ ТОГО в отдельную корзину с числом. Из счёта ни тот, ни другой
   не выпадают: "отнесено всё" читалось бы из молчания, а молчание здесь
   означает три четверти узлов.`

// knownNodeTypes — типы узлов, ПРОТИВ КОТОРЫХ учёт строк проверен.
//
// Это не перечень «всех типов Postgres» и не должен им быть. Смысл словаря —
// отличить «прибор знает, как считать этот узел» от «прибор видит его впервые»;
// второе обязано быть НАЗВАНО числом, а не растворено в сумме.
//
// "Custom Scan" и "Foreign Scan" сюда НЕ входят намеренно, и это не пропуск:
// их `Actual Rows` производит расширение либо обёртка чужого источника по
// СВОИМ правилам, о которых прибор ничего не знает. Встретив такой узел, он
// обязан сказать об этом вслух, а не сделать вид, что сосчитал.
var knownNodeTypes = map[string]bool{
	"Aggregate": true, "Append": true, "BitmapAnd": true, "BitmapOr": true,
	"Bitmap Heap Scan": true, "Bitmap Index Scan": true, "CTE Scan": true,
	"Function Scan": true, "Gather": true, "Gather Merge": true, "Group": true,
	"Hash": true, "Hash Join": true, "Incremental Sort": true,
	"Index Only Scan": true, "Index Scan": true, "Limit": true, "LockRows": true,
	"Materialize": true, "Memoize": true, "Merge Append": true, "Merge Join": true,
	"ModifyTable": true, "Named Tuplestore Scan": true, "Nested Loop": true,
	"ProjectSet": true, "Recursive Union": true, "Result": true, "Sample Scan": true,
	"Seq Scan": true, "SetOp": true, "Sort": true, "Subquery Scan": true,
	"Table Function Scan": true, "Tid Range Scan": true, "Tid Scan": true,
	"Unique": true, "Values Scan": true, "WindowAgg": true, "WorkTable Scan": true,
}

// Access — один доступ к отношению, как его увидел прибор.
type Access struct {
	// Relation — отношение, к которому узел отнесён.
	Relation string
	// NodeType — тип узла, дословно из плана.
	NodeType string
	// IndexName — индекс, если узел его назвал.
	IndexName string
	// Key — каким ключом узел отнесён: "Relation Name", "Index Name (справочник
	// плана)" либо "Index Name (предок Bitmap Heap Scan)". Печатается затем,
	// чтобы отнесение можно было ОСПОРИТЬ, а не только прочитать.
	Key string
	// Loops — число циклов узла.
	Loops int
	// Rows — Actual Rows × Loops. У схлопнутого узла величина СНЯТА и видима,
	// но в сумму отношения не входит.
	Rows int64
	// Removed — отброшенное этим узлом, × Loops: сумма двух ниже.
	Removed int64
	// RemovedByFilter / RemovedByRecheck — те же строки ПОРОЗНЬ, потому что
	// означают они разное: фильтр — предикат, который индекс не обслуживает;
	// перепроверка — потерявший точность bitmap. Слитое число не различает
	// «нужен индекс» и «не хватило памяти под bitmap», а лечится это по-разному.
	RemovedByFilter  int64
	RemovedByRecheck int64
	// Collapsed — узел даёт вход своему предку, а не отдельную работу.
	Collapsed bool
}

// RelationCost — разложение величины по отношению.
type RelationCost struct {
	Relation string
	// Accesses — сколько РАЗНЫХ доступов к этому отношению в плане. Два — это
	// нормально и часто означает две ветви UNION, а не дубль.
	Accesses int
	Rows     int64
	Removed  int64
}

// JoinFilter — отброшенное соединением, отнесённое к УЗЛУ.
//
// К отношению его отнести не к чему: у "Nested Loop" "Relation Name"
// отсутствует вовсе. Измерено, что именно здесь отброшенное и живёт: по четырём
// отношениям пути вердикта "Rows Removed by Filter" равен нулю на всех
// фикстурах при доказанно рабочем извлекателе.
type JoinFilter struct {
	NodeType string
	Removed  int64
}

// TypeCount — корзина узлов одного типа.
type TypeCount struct {
	NodeType string
	Nodes    int
	Rows     int64
}

// Measurement — снятая величина ВМЕСТЕ с объёмом осмотренного.
//
// Объём осмотренного — не украшение отчёта: без него «ноль находок» неотличимо
// от «ноль прочитанного», а доля неотнесённого на снятых планах составляет три
// четверти узлов.
type Measurement struct {
	// Rows — НЕСУЩАЯ величина: сумма по отнесённым доступам, без схлопнутых.
	Rows int64
	// Removed — сумма отброшенного: фильтр, перепроверка, соединение.
	Removed int64
	// RemovedByFilter / RemovedByRecheck — слагаемые Removed порознь. Третье
	// слагаемое — JoinFilterRemoved: оно живёт на узлах, а не на отношениях.
	RemovedByFilter  int64
	RemovedByRecheck int64
	// Touched — Rows + Removed. Вердикт о стоимости выносится по ней.
	Touched int64
	// AllRows — сумма по ВСЕМ узлам плана, включая необтесённые. Третья ось
	// замера; вердикта не выносит, но её расхождение с Rows показывает, сколько
	// работы лежит вне отношений.
	AllRows int64

	ByRelation []RelationCost
	Accesses   []Access

	Nodes             int
	Attributed        int
	Unattributed      int
	UnattributedRows  int64
	UnattributedShare float64

	UnknownTypes      []TypeCount
	JoinFilters       []JoinFilter
	JoinFilterRemoved int64
	HeapFetches       int64
	WorkersLaunched   int

	// Census — перепись, печатаемая ВСЕГДА, включая случай «не отнесено 0».
	Census string
}

// rawNode — узел плана в том виде, в каком его печатает Postgres.
//
// Имена полей — дословно из JSON: разбор по позиции молча измерял бы другой
// узел, потому что позиция меняется вместе с выбором плана.
type rawNode struct {
	NodeType                  string    `json:"Node Type"`
	ParallelAware             bool      `json:"Parallel Aware"`
	RelationName              string    `json:"Relation Name"`
	Alias                     string    `json:"Alias"`
	IndexName                 string    `json:"Index Name"`
	CTEName                   string    `json:"CTE Name"`
	ActualRows                float64   `json:"Actual Rows"`
	ActualLoops               float64   `json:"Actual Loops"`
	RowsRemovedByFilter       float64   `json:"Rows Removed by Filter"`
	RowsRemovedByIndexRecheck float64   `json:"Rows Removed by Index Recheck"`
	RowsRemovedByJoinFilter   float64   `json:"Rows Removed by Join Filter"`
	HeapFetches               float64   `json:"Heap Fetches"`
	WorkersLaunched           float64   `json:"Workers Launched"`
	Plans                     []rawNode `json:"Plans"`
}

// loops — число циклов узла, приведённое к единице снизу.
//
// План БЕЗ ANALYZE счётчиков не несёт вовсе, и нулевой множитель обнулил бы
// величину молча — то есть отдал бы ноль там, где счёт не производился.
func (n *rawNode) loops() int {
	if n.ActualLoops < 1 {
		return 1
	}
	return int(math.Round(n.ActualLoops))
}

func (n *rawNode) rows() int64 { return int64(math.Round(n.ActualRows)) * int64(n.loops()) }

// Extract снимает величину с вывода `EXPLAIN (ANALYZE, BUFFERS, VERBOSE, FORMAT JSON)`.
//
// `want` — ПРЕДПОСЫЛКА замера: отношения, которые запрос обязан читать. Она не
// является перечнем для разложения — разложение берётся из плана, — и нужна
// ровно затем, чтобы отличить «работы не было» от «смотрели не туда». Пустая
// предпосылка отвергается: пересечение с пустым множеством пусто ВСЕГДА, и
// отказ перестал бы что-либо означать.
func Extract(planJSON []byte, want []string) (Measurement, error) {
	var m Measurement

	if len(want) == 0 {
		return m, fmt.Errorf("%w: предпосылка не объявлена — отношения, которые запрос обязан "+
			"читать, названы не были, и отказ «смотрели не туда» стал бы невозможен by construction",
			ErrPreconditionNotMet)
	}

	var top []struct {
		Plan *rawNode `json:"Plan"`
	}
	if err := json.Unmarshal(planJSON, &top); err != nil {
		return m, fmt.Errorf("planrows: разбор плана: %w", err)
	}
	if len(top) == 0 || top[0].Plan == nil || top[0].Plan.NodeType == "" {
		return m, fmt.Errorf("planrows: в выводе EXPLAIN нет плана — читать нечего, "+
			"и ноль здесь означал бы, что план прочитан, а он не прочитан (получено %d байт)",
			len(planJSON))
	}
	root := top[0].Plan

	// Первый проход: справочник «индекс → отношение», собранный ИЗ ЭТОГО ЖЕ
	// плана. Собирается ДО отнесения, потому что узел, разрешаемый по индексу,
	// может стоять в плане РАНЬШЕ того, который даёт разгадку.
	indexOwner := map[string]string{}
	var collect func(n *rawNode)
	collect = func(n *rawNode) {
		if n.RelationName != "" && n.IndexName != "" {
			indexOwner[n.IndexName] = n.RelationName
		}
		for i := range n.Plans {
			collect(&n.Plans[i])
		}
	}
	collect(root)

	byRelation := map[string]*RelationCost{}
	unknown := map[string]*TypeCount{}

	// Второй проход: отнесение. `bitmapHeapAncestor` — ближайший предок
	// "Bitmap Heap Scan"; он передаётся вниз, поэтому родство держится и через
	// "BitmapAnd"/"BitmapOr", стоящие между парой.
	var walk func(n *rawNode, bitmapHeapAncestor string)
	walk = func(n *rawNode, bitmapHeapAncestor string) {
		m.Nodes++
		rows := n.rows()
		loops := n.loops()
		m.AllRows += rows

		// Итоговые величины — не на цикл, поэтому без множителя.
		m.HeapFetches += int64(math.Round(n.HeapFetches))
		m.WorkersLaunched += int(math.Round(n.WorkersLaunched))

		if !knownNodeTypes[n.NodeType] {
			t := unknown[n.NodeType]
			if t == nil {
				t = &TypeCount{NodeType: n.NodeType}
				unknown[n.NodeType] = t
			}
			t.Nodes++
			t.Rows += rows
		}

		if jf := int64(math.Round(n.RowsRemovedByJoinFilter)) * int64(loops); jf > 0 {
			m.JoinFilters = append(m.JoinFilters, JoinFilter{NodeType: n.NodeType, Removed: jf})
			m.JoinFilterRemoved += jf
			m.Removed += jf
		}
		removedByFilter := int64(math.Round(n.RowsRemovedByFilter)) * int64(loops)
		removedByRecheck := int64(math.Round(n.RowsRemovedByIndexRecheck)) * int64(loops)
		removed := removedByFilter + removedByRecheck

		// Отброшенное учитывается БЕЗУСЛОВНО и до всякого разбора: оно не
		// участвует в схлопывании (см. пункт 3 правила) и не зависит от того,
		// удалось ли отнести узел к отношению. Условная ветка здесь означала бы
		// работу, исчезающую тем тише, чем труднее узел разобрать.
		m.Removed += removed
		m.RemovedByFilter += removedByFilter
		m.RemovedByRecheck += removedByRecheck

		relation, key := attribute(n, indexOwner, bitmapHeapAncestor)
		switch {
		case relation != "":
			m.Attributed++
			// Схлопывание — ПО РОДСТВУ: ребёнок bitmap-пары даёт вход своему
			// предку, а не отдельную работу. По имени схлопывать нельзя: два
			// доступа к одному отношению бывают двумя ветвями UNION.
			collapsed := n.NodeType == "Bitmap Index Scan" && bitmapHeapAncestor != ""
			m.Accesses = append(m.Accesses, Access{
				Relation: relation, NodeType: n.NodeType, IndexName: n.IndexName,
				Key: key, Loops: loops, Rows: rows, Removed: removed,
				RemovedByFilter: removedByFilter, RemovedByRecheck: removedByRecheck,
				Collapsed: collapsed,
			})
			rc := byRelation[relation]
			if rc == nil {
				rc = &RelationCost{Relation: relation}
				byRelation[relation] = rc
			}
			rc.Removed += removed
			if !collapsed {
				rc.Accesses++
				rc.Rows += rows
				m.Rows += rows
			}
		default:
			m.Unattributed++
			m.UnattributedRows += rows
		}

		down := bitmapHeapAncestor
		if n.NodeType == "Bitmap Heap Scan" && n.RelationName != "" {
			down = n.RelationName
		}
		for i := range n.Plans {
			walk(&n.Plans[i], down)
		}
	}
	walk(root, "")

	for _, rc := range byRelation {
		m.ByRelation = append(m.ByRelation, *rc)
	}
	sort.Slice(m.ByRelation, func(i, j int) bool {
		return m.ByRelation[i].Relation < m.ByRelation[j].Relation
	})
	for _, t := range unknown {
		m.UnknownTypes = append(m.UnknownTypes, *t)
	}
	sort.Slice(m.UnknownTypes, func(i, j int) bool {
		return m.UnknownTypes[i].NodeType < m.UnknownTypes[j].NodeType
	})

	m.Touched = m.Rows + m.Removed
	if m.Nodes > 0 {
		m.UnattributedShare = float64(m.Unattributed) / float64(m.Nodes) * 100
	}

	// Перепись собирается ДО проверки предпосылки: отказ обязан её печатать,
	// иначе «смотрели не туда» невозможно разобрать — не видно, куда смотрели.
	m.Census = census(m, want)

	var missing []string
	var found bool
	for _, w := range want {
		if _, ok := byRelation[w]; ok {
			found = true
		} else {
			missing = append(missing, w)
		}
	}
	if !found {
		return m, fmt.Errorf("%w: в плане нет НИ ОДНОГО из ожидаемых отношений %v — "+
			"ноль здесь означает «не нашли, где смотреть», а не «работы не было».\n%s",
			ErrPreconditionNotMet, missing, m.Census)
	}
	return m, nil
}

// attribute относит узел к отношению по правилу, объявленному в AttributionRule.
//
// Возвращает второй величиной КЛЮЧ, которым отнесение сделано: без него
// «отнесено» нельзя оспорить, а разбор отнесения — единственный способ отличить
// объявленное правило от подобранного.
func attribute(n *rawNode, indexOwner map[string]string, bitmapHeapAncestor string) (string, string) {
	if n.RelationName != "" {
		return n.RelationName, "Relation Name"
	}
	if n.IndexName != "" {
		if owner, ok := indexOwner[n.IndexName]; ok {
			return owner, "Index Name (справочник плана)"
		}
		if bitmapHeapAncestor != "" {
			return bitmapHeapAncestor, "Index Name (предок Bitmap Heap Scan)"
		}
	}
	return "", ""
}

// census — объём осмотренного, печатаемый ВСЕГДА.
//
// Печатается и тогда, когда не отнесено ноль: «не отнесено 0» — это ЦЕЛЬ, а не
// поломка, и проба, падающая на достижении своей цели, толкает держать
// неотнесённый узел ради зелёного.
func census(m Measurement, want []string) string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	p("%s\n\n", strings.TrimSpace(AttributionRule))
	p("ОБЪЁМ ОСМОТРЕННОГО\n")
	p("  узлов разобрано %d, отнесено %d, не отнесено %d (%.1f %%), отношений %d\n",
		m.Nodes, m.Attributed, m.Unattributed, m.UnattributedShare, len(m.ByRelation))
	p("  предпосылка (ожидаемые отношения): %s\n", strings.Join(want, ", "))

	p("\nВЕЛИЧИНЫ\n")
	p("  отдано узлами (несущая, с множителем циклов)   %d\n", m.Rows)
	p("  отброшено всего                                %d\n", m.Removed)
	p("    из них фильтром                              %d\n", m.RemovedByFilter)
	p("    из них перепроверкой потерявшего точность bitmap %d\n", m.RemovedByRecheck)
	p("    из них соединением (по узлам)                %d\n", m.JoinFilterRemoved)
	p("  тронуто (отдано + отброшено)                   %d\n", m.Touched)
	p("  по всем узлам плана, включая неотнесённые      %d\n", m.AllRows)
	p("  строк на неотнесённых узлах                    %d\n", m.UnattributedRows)
	p("  Heap Fetches                                   %d\n", m.HeapFetches)
	p("  Workers Launched                               %d\n", m.WorkersLaunched)

	p("\nРАЗЛОЖЕНИЕ ПО ОТНОШЕНИЯМ (взято из плана, не выписано в коде)\n")
	if len(m.ByRelation) == 0 {
		p("  ни одного отношения не отнесено\n")
	}
	for _, rc := range m.ByRelation {
		p("  %-24s доступов %d, отдано %d, отброшено %d\n",
			rc.Relation, rc.Accesses, rc.Rows, rc.Removed)
	}

	p("\nДОСТУПЫ ПООБЪЕКТНО (ключ отнесения назван, чтобы его можно было оспорить)\n")
	for _, a := range m.Accesses {
		note := ""
		if a.Collapsed {
			note = "  [схлопнут по родству: вход предка, не отдельная работа]"
		}
		p("  %-24s %-20s циклов %d, отдано %d, отброшено %d (фильтр %d, перепроверка %d), ключ: %s%s\n",
			a.Relation, a.NodeType, a.Loops, a.Rows, a.Removed,
			a.RemovedByFilter, a.RemovedByRecheck, a.Key, note)
	}

	p("\nОТБРОШЕНО СОЕДИНЕНИЕМ — ПО УЗЛАМ (относить к отношению не к чему)\n")
	if len(m.JoinFilters) == 0 {
		p("  нет\n")
	}
	for _, jf := range m.JoinFilters {
		p("  %-20s отброшено %d\n", jf.NodeType, jf.Removed)
	}

	p("\nУЗЛЫ НЕИЗВЕСТНОГО ПРИБОРУ ТИПА\n")
	if len(m.UnknownTypes) == 0 {
		p("  нет (все %d узлов — знакомых типов)\n", m.Nodes)
	}
	for _, t := range m.UnknownTypes {
		p("  %-24s узлов %d, строк %d — учёт этого типа прибором НЕ проверен\n",
			t.NodeType, t.Nodes, t.Rows)
	}
	return b.String()
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// drain_order_declared.go — РАСПОЗНАВАТЕЛЬ очередей службы: чем каждая
// дренится и по какому ключу выбирается (kacho#2485).
//
// # ПРЕДМЕТ
//
// Дренаж очереди, чей поток несёт две противоположные половины про одну
// единицу состояния (поставить и снять), обязан брать строки так, чтобы
// снятие не применилось раньше постановки. Иначе снятое ВОССТАНАВЛИВАЕТСЯ и
// убрать его уже нечем: событий про него в очереди не осталось. Решается это
// на уровне ВЫБОРКИ — строка не берётся, пока в её партиции есть доставляемый
// предшественник, — либо не решается вовсе, если поток КОММУТАТИВЕН и
// переставлять в нём нечего.
//
// Оба исхода законны; незаконно ТРЕТЬЕ — когда решение не принято, а принято
// ли, посмотреть негде.
//
// # ПОЧЕМУ РАСПОЗНАВАТЕЛЬ, А НЕ ОДИН ПРЕДИКАТ
//
// Дренаж объявляется в этом дереве ДВУМЯ формами, и знать надо обе:
//
//	ПРОВОДКА           — литерал настроек чужой машинерии очередей
//	                     (`drainer.Config`, `audit.ShipperConfig`): очередь
//	                     названа полем `Table`, ключ порядка — полем
//	                     `PartitionColumn`;
//	СОБСТВЕННЫЙ ОПЕРАТОР — очередь движет СВОЙ код: он сам клеймит неотправленные
//	                     строки и сам помечает их отправленными. Ни одного поля
//	                     настроек у него нет — очередь и ключ порядка видны
//	                     только в его запросах.
//
// Форма, о которой распознаватель не знает, не даёт ни красного, ни зелёного —
// она МОЛЧИТ, и всё записанное в ней оказывается вне наблюдения. Ровно это и
// произошло: гейт порядка монорепо знал первую форму и не знал второй, поэтому
// очередь сверки прав стояла у него в переписи сканеров и отсутствовала в
// переписи дренируемых. Одно число («дренируемых 9») читалось как «все».
//
// # ТРЕТЬЯ ОСЬ: ОЧЕРЕДИ СХЕМЫ
//
// Двух форм мало: обе отвечают на вопрос «что я УВИДЕЛ», и ни одна — на вопрос
// «сколько их всего». Поэтому очереди берутся ещё и у СХЕМЫ (`QueuesOfSchema`),
// и вердикт выносится по каждой: она либо дренится одной из форм, либо объявлена
// недренируемой с причиной. Очередь, которую не увидела ни одна форма и о
// которой не объявлено ничего, — находка, а не молчание.
//
// # ЧЕГО РАСПОЗНАВАТЕЛЬ НЕ ДЕЛАЕТ
//
// Он не судит ИСТИННОСТЬ обоснования коммутативности: правдивость прозы машинно
// непроверяема. Он судит наличие решения, его единственный экземпляр и то, что
// у обоснования есть предмет.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// QueueTableSuffix — приставка имени очереди в схеме службы.
//
// Признак ИМЕНИ, а не единственный: рядом работает признак КОЛОНКИ
// (`DeliveryMarkerColumn`), и перепись печатает оба числа. Два признака об одном
// предмете заведены нарочно — расхождение между ними означает, что один из них
// разъехался с деревом, и это видно, а не молчит.
const QueueTableSuffix = "_outbox"

// DeliveryMarkerColumn — колонка, которой в этом дереве помечают доставленную
// строку.
//
// Словарь у признака ОДИН, и это замер, а не допущение: по всем миграциям
// службы колонок-признаков доставки ровно одна форма записи
// (`grep -ohE '\b(sent_at|delivered_at|processed_at|dispatched_at)\b'
// internal/migrations/*.sql | sort -u` → `sent_at`). Появится вторая — очередь,
// названная ею, выпадет из признака КОЛОНКИ, но останется в признаке ИМЕНИ, и
// расхождение двух чисел переписи это покажет.
const DeliveryMarkerColumn = "sent_at"

// DrainForm — форма, которой объявлен дренаж очереди.
type DrainForm string

const (
	// DrainFormWiring — литерал настроек чужой машинерии очередей.
	DrainFormWiring DrainForm = "проводка"
	// DrainFormOperator — собственный оператор движения строк.
	DrainFormOperator DrainForm = "собственный оператор"
)

// DrainSite — одна дренируемая очередь: чем движется и по какому ключу
// выбирается.
type DrainSite struct {
	// Table — очередь, схема и имя.
	Table string
	// Form — форма объявления дренажа.
	Form DrainForm
	// Where — координаты мест, объявивших дренаж.
	Where []string
	// OrderKey — ключ порядка выборки; пустой означает «порядка нет».
	OrderKey string
	// RosterNamed — обоснование в точке решения СОСЛАЛОСЬ на роспись ЭТОГО
	// дерева.
	RosterNamed bool
	// ForeignRoster — координаты обоснований, назвавших роспись ЧУЖОГО
	// репозитория (`<пакет>.commutativeDrainExempt`). Отдельно от RosterNamed,
	// потому что это не «сослался», а «сослался в никуда»: роспись монорепо
	// после выноса службы записей её очередей не несёт, и читатель в точке
	// решения попадает туда, где про его очередь не написано ничего.
	ForeignRoster []string
}

// QueueInventory — перепись очередей дерева.
type QueueInventory struct {
	// Drained — дренируемые очереди по имени таблицы.
	Drained map[string]*DrainSite
	// Roles — сколько мест каждой роли машинерии очередей осмотрено
	// («дренаж», «сканер», «возврат», «уборка»). Перепись форм: расширение
	// распознавателя обязано менять её, иначе оно холостое.
	Roles map[string]int
	// Unclassified — литерал настроек из пространства машинерии очередей, чья
	// роль не объявлена. Неизвестный вход — ЯВНЫЙ ОТКАЗ, а не молчание.
	Unclassified []string
	// Ambiguous — имя константы, которым два прод-файла назвали РАЗНЫЕ таблицы:
	// резолв неоднозначен, и угадывать нельзя.
	Ambiguous []string
	// FilesRead — прочитано файлов Go.
	FilesRead int
	// LiteralsRead — осмотрено строковых литералов (объём обхода формы
	// «собственный оператор»).
	LiteralsRead int
	// CommentsSeen — осмотрено комментариев внутри областей объявления дренажа.
	// Ноль означал бы, что разбор идёт БЕЗ комментариев и любое молчание проверки
	// делегирования ничего не доказывает.
	CommentsSeen int

	// referenced — имена констант, которыми литералы настроек НАЗВАЛИ очередь
	// либо ключ порядка. Неоднозначность объявляется только по ним: совпадение
	// имён в двух чужих пакетах вердикта о дренаже не меняет, а объявленное
	// вхолостую делает перечень нечитаемым.
	referenced map[string]bool
}

// queueMachineryRoles — роль литерала настроек по ПОЛНОМУ имени типа.
//
// Ключ — путь импорта плюс имя типа, а не имя пакета: имя пакета есть псевдоним
// места вызова, и чужой пакет с тем же именем прошёл бы за свой.
//
// Роль «дренаж» означает, что место ДВИГАЕТ строки: клеймит, отдаёт и помечает
// отправленными. Вывоз журнала (`audit.ShipperConfig`) — дренаж наравне с
// общим: не признать его им значило бы оставить очередь под записью
// «наблюдается, но не дренится» при живой доставке.
var queueMachineryRoles = map[string]string{
	"github.com/PRO-Robotech/corelib/outbox/drainer.Config":          "дренаж",
	"github.com/PRO-Robotech/corelib/audit.ShipperConfig":            "дренаж",
	"github.com/PRO-Robotech/corelib/outbox/metrics.CollectorConfig": "сканер",
	"github.com/PRO-Robotech/corelib/outbox/reconciler.Config":       "возврат",
	"github.com/PRO-Robotech/corelib/outbox.QueueRetentionConfig":    "уборка",
}

// queueMachinerySubtree — поддерево библиотеки очередей.
//
// Пространство отказа ВЫВОДИТСЯ, а не выписывается: пакет, уже давший хоть одну
// объявленную роль, входит в него сам (см. `queueMachineryPackages`), плюс любой
// пакет этого поддерева. Тип с полем `Table` оттуда, чья роль не объявлена, —
// находка: это новая форма, и её обязан классифицировать человек.
const queueMachinerySubtree = "github.com/PRO-Robotech/corelib/outbox"

// queueMachineryPackages — пакеты, чьи роли уже объявлены. Выводится из росписи
// ролей, чтобы два места об одном предмете не завелись.
func queueMachineryPackages() map[string]bool {
	out := map[string]bool{}
	for full := range queueMachineryRoles {
		if path := importPathOf(full); path != "" {
			out[path] = true
		}
	}
	return out
}

// importPathOf — путь импорта из полного имени типа `<путь>.<Тип>`.
//
// Точка ищется ПОСЛЕ последней косой черты, а не в конце строки: в пути импорта
// точек хватает и своих (`github.com`), и отсчёт от конца дал бы путь, урезанный
// по домену.
func importPathOf(full string) string {
	slash := strings.LastIndex(full, "/")
	dot := strings.Index(full[slash+1:], ".")
	if dot < 0 {
		return ""
	}
	return full[:slash+1+dot]
}

// tableFieldName — поле, которым литерал настроек называет свою очередь.
const tableFieldName = "Table"

// partitionFieldName — поле, которым литерал настроек называет ключ порядка.
const partitionFieldName = "PartitionColumn"

// SchemaQueues — очереди ЖИВОЙ схемы: заведённые миграциями и не снятые ими.
type SchemaQueues struct {
	// ByName — очереди, опознанные по приставке имени.
	ByName []string
	// ByMarker — очереди, опознанные по колонке-признаку доставки.
	ByMarker []string
	// Dropped — таблицы, снятые более поздней миграцией.
	Dropped []string
	// FilesRead — прочитано файлов миграций.
	FilesRead int
	// TablesRead — осмотрено объявлений таблиц.
	TablesRead int
}

// Live — очереди живой схемы: объединение обоих признаков, без снятых.
func (q SchemaQueues) Live() []string {
	seen := map[string]bool{}
	for _, t := range q.ByName {
		seen[t] = true
	}
	for _, t := range q.ByMarker {
		seen[t] = true
	}
	for _, t := range q.Dropped {
		delete(seen, t)
	}
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

var (
	createTableRe = regexp.MustCompile(`(?is)\bCREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([A-Za-z_][\w."]*)\s*\(`)
	dropTableRe   = regexp.MustCompile(`(?is)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?([A-Za-z_][\w."]*)`)
	markerColRe   = regexp.MustCompile(`(?i)\b` + DeliveryMarkerColumn + `\b`)
)

// QueuesOfSchema — очереди схемы по корпусу миграций.
//
// Признака ДВА и оба печатаются: приставка имени и колонка доставки. Один
// признак скрыл бы ровно тот случай, ради которого перепись и ведётся, —
// очередь, названную иначе либо помечающую доставку иной колонкой.
//
// Снятые таблицы вычитаются: текстовый предикат по миграциям иначе считает живой
// ту, чей предмет убрала более поздняя миграция, а ложная находка выключает
// проверку быстрее, чем её чинят.
func QueuesOfSchema(migrations TreeCorpus) (SchemaQueues, error) {
	out := SchemaQueues{}
	if len(migrations) == 0 {
		return out, fmt.Errorf("%w: корпус миграций пуст — о схеме не прочитано ничего",
			ErrEmptyTraversal)
	}
	byName, byMarker := map[string]bool{}, map[string]bool{}
	for _, rel := range migrations.Rels() {
		out.FilesRead++
		// Комментарий снимается ДО разбора, и снимает его ОБЩИЙ помощник
		// пакета (`catalog_seed_parity.go`), а не своя копия: копия разошлась бы
		// с ним молча. Миграции этого дерева объясняют форму сноса ЦИТАТОЙ
		// самого оператора, и предикат по тексту счёл бы объяснение объявлением
		// — тот же класс, что «гейт читает исполняемую часть, а не текст».
		body := stripSQLComments(migrations[rel])
		for _, m := range createTableRe.FindAllStringSubmatchIndex(body, -1) {
			out.TablesRead++
			name := normalizeSQLName(body[m[2]:m[3]])
			if strings.HasSuffix(name, QueueTableSuffix) {
				byName[name] = true
			}
			if markerColRe.MatchString(tableBodyAt(body, m[1])) {
				byMarker[name] = true
			}
		}
		for _, m := range dropTableRe.FindAllStringSubmatch(body, -1) {
			out.Dropped = append(out.Dropped, normalizeSQLName(m[1]))
		}
	}
	out.ByName, out.ByMarker = sortedSet(byName), sortedSet(byMarker)
	sort.Strings(out.Dropped)
	if out.TablesRead == 0 {
		return out, fmt.Errorf("%w: в %d файлах миграций не опознано ни одного объявления "+
			"таблицы — признак разъехался со схемой", ErrEmptyTraversal, out.FilesRead)
	}
	return out, nil
}

// tableBodyAt — тело объявления таблицы от открывающей скобки до парной ей.
func tableBodyAt(body string, open int) string {
	depth := 1
	for i := open; i < len(body); i++ {
		switch body[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return body[open:i]
			}
		}
	}
	return body[open:]
}

// normalizeSQLName — имя таблицы без кавычек и лишнего регистра.
func normalizeSQLName(s string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(s), `";`))
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DrainInventoryOf — перепись дренажа по корпусу прод-файлов Go.
//
// `queues` — очереди схемы: форма «собственный оператор» опознаётся ТОЛЬКО на
// них. Сужение не удобство: без него распознаватель считал бы очередью всякое
// имя, попавшее в строку с признаком доставки, — включая образцы в собственном
// исходнике проверок.
func DrainInventoryOf(corpus TreeCorpus, queues []string) (QueueInventory, error) {
	inv := QueueInventory{
		Drained:    map[string]*DrainSite{},
		Roles:      map[string]int{},
		referenced: map[string]bool{},
	}
	if len(corpus) == 0 {
		return inv, fmt.Errorf("%w: корпус прод-файлов Go пуст — о дренаже не прочитано ничего",
			ErrEmptyTraversal)
	}
	known := map[string]bool{}
	for _, q := range queues {
		known[q] = true
	}

	consts, clash, err := stringConstantsOf(corpus)
	if err != nil {
		return inv, err
	}

	fset := token.NewFileSet()
	for _, rel := range corpus.Rels() {
		// ParseComments — не роскошь: обоснование ОТСУТСТВУЮЩЕГО ключа порядка
		// живёт только в комментарии, и без флага разбор его не видит вовсе.
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.ParseComments)
		if perr != nil {
			return inv, fmt.Errorf("разбор %s: %w — гейт не вправе судить файл, "+
				"который он не разобрал", rel, perr)
		}
		inv.FilesRead++
		scanWiringForm(fset, file, rel, consts, &inv)
		scanOperatorForm(fset, file, rel, known, &inv)
	}
	for name := range inv.referenced {
		if clash[name] {
			inv.Ambiguous = append(inv.Ambiguous, name)
		}
	}
	sort.Strings(inv.Ambiguous)
	return inv, nil
}

// scanWiringForm — форма «проводка»: литерал настроек чужой машинерии очередей.
func scanWiringForm(fset *token.FileSet, file *ast.File, rel string, consts map[string]string, inv *QueueInventory) {
	imports := importAliases(file)
	pkgs := queueMachineryPackages()

	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		alias, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		path, known := imports[alias.Name]
		if !known {
			return true
		}
		full := path + "." + sel.Sel.Name
		role, classified := queueMachineryRoles[full]
		inMachinery := pkgs[path] || strings.HasPrefix(path, queueMachinerySubtree)
		if !classified {
			// Неизвестный вход — явный отказ, а не молчание: тип с полем
			// `Table` из пространства машинерии очередей есть НОВАЯ ФОРМА, и
			// пропустить её значило бы вывести её предмет из наблюдения.
			if inMachinery && litHasField(lit, tableFieldName) {
				inv.Unclassified = append(inv.Unclassified,
					fmt.Sprintf("%s:%d — %s", rel, fset.Position(lit.Pos()).Line, full))
			}
			return true
		}
		inv.Roles[role]++
		if role != "дренаж" {
			return true
		}
		table := resolveFieldString(lit, tableFieldName, consts, inv.referenced)
		if table == "" {
			return true
		}
		site := siteOf(inv, table, DrainFormWiring)
		site.Where = append(site.Where, fmt.Sprintf("%s:%d", rel, fset.Position(lit.Pos()).Line))
		if key := resolveFieldString(lit, partitionFieldName, consts, inv.referenced); key != "" {
			site.OrderKey = key
		}
		seen, named, foreign := commentsWithin(fset, file, rel, lit.Pos(), lit.End())
		inv.CommentsSeen += seen
		site.RosterNamed = site.RosterNamed || named
		site.ForeignRoster = append(site.ForeignRoster, foreign...)
		return true
	})
}

// claimRe — клейм неотправленных строк: выборка по признаку доставки.
// markSentRe — пометка строки отправленной.
//
// Оба образца нечувствительны к регистру и к переносам строк: SQL в этом дереве
// пишется многострочным литералом с отступами, и образец, требующий одной
// строки, не нашёл бы ни одного запроса.
var (
	claimRe = regexp.MustCompile(`(?is)\bFROM\s+([A-Za-z_][\w.]*)\b.*?\b` +
		DeliveryMarkerColumn + `\s+IS\s+NULL\b`)
	markSentRe = regexp.MustCompile(`(?is)\bUPDATE\s+([A-Za-z_][\w.]*)\b.*?\bSET\b.*?\b` +
		DeliveryMarkerColumn + `\s*=`)
	orderByRe = regexp.MustCompile(`(?is)\bORDER\s+BY\s+([^)]*?)(?:\bLIMIT\b|\bFOR\b|\bFETCH\b|$)`)
)

// machineryColumns — колонки самой машинерии очереди: они задают порядок
// ПОВТОРА, а не партицию. Ключом порядка не являются ни одна.
var machineryColumns = map[string]bool{
	"id": true, "attempt_count": true, "created_at": true, DeliveryMarkerColumn: true,
}

// scanOperatorForm — форма «собственный оператор»: код сам клеймит
// неотправленные строки и сам помечает их отправленными.
//
// Очередь считается дренируемой этой формой, когда в дереве есть ОБЕ половины:
// клейм и пометка. Одной мало — уборка доставленных строк тоже читает признак
// доставки, а дренажем не является: она ничего не применяет и ничего не
// помечает.
func scanOperatorForm(fset *token.FileSet, file *ast.File, rel string, queues map[string]bool, inv *QueueInventory) {
	claims := map[string]string{}   // таблица → координата клейма
	claimSQL := map[string]string{} // таблица → текст клейма
	marks := map[string]string{}    // таблица → координата пометки
	decls := map[string]*ast.FuncDecl{}

	ast.Inspect(file, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			return true
		}
		ast.Inspect(fn.Body, func(m ast.Node) bool {
			bl, ok := m.(*ast.BasicLit)
			if !ok || bl.Kind != token.STRING {
				return true
			}
			sql, uerr := strconv.Unquote(bl.Value)
			if uerr != nil {
				return true
			}
			inv.LiteralsRead++
			coord := fmt.Sprintf("%s:%d", rel, fset.Position(bl.Pos()).Line)
			if g := claimRe.FindStringSubmatch(sql); g != nil {
				if t := normalizeSQLName(g[1]); queues[t] && strings.Contains(strings.ToUpper(sql), "ORDER BY") {
					claims[t], claimSQL[t], decls[t] = coord, sql, fn
				}
			}
			if g := markSentRe.FindStringSubmatch(sql); g != nil {
				if t := normalizeSQLName(g[1]); queues[t] {
					marks[t] = coord
				}
			}
			return true
		})
		return true
	})

	for table, claim := range claims {
		if _, moved := marks[table]; !moved {
			continue
		}
		site := siteOf(inv, table, DrainFormOperator)
		site.Where = append(site.Where, claim+" (клейм) + "+marks[table]+" (пометка)")
		site.OrderKey = orderKeyOf(claimSQL[table])
		if fn := decls[table]; fn != nil {
			// Область объявления начинается с ШАПКИ функции, а не с её тела:
			// читатель решает вопрос о порядке там, где написано, что делает
			// клейм, и обоснование принадлежит туда же. Требуй его только внутри
			// тела — и оно уедет от глаз в середину запроса.
			from := fn.Pos()
			if fn.Doc != nil {
				from = fn.Doc.Pos()
			}
			seen, named, foreign := commentsWithin(fset, file, rel, from, fn.End())
			inv.CommentsSeen += seen
			site.RosterNamed = site.RosterNamed || named
			site.ForeignRoster = append(site.ForeignRoster, foreign...)
		}
	}
}

// orderKeyOf — ключ порядка выборки: первая колонка `ORDER BY`, не
// принадлежащая машинерии очереди.
//
// `id` и `attempt_count` ключом партиции не являются: первый задаёт порядок
// внутри очереди, второй — порядок ПОВТОРА и есть ровно та колонка, из-за
// которой отложенная строка уезжает за свежую.
func orderKeyOf(sql string) string {
	g := orderByRe.FindStringSubmatch(sql)
	if g == nil {
		return ""
	}
	for _, col := range strings.Split(g[1], ",") {
		name := strings.ToLower(strings.TrimSpace(col))
		name = strings.TrimSuffix(strings.TrimSuffix(name, " asc"), " desc")
		name = strings.TrimSpace(name)
		if name == "" || machineryColumns[name] {
			continue
		}
		return name
	}
	return ""
}

// siteOf — запись очереди в переписи; форма фиксируется первой найденной.
func siteOf(inv *QueueInventory, table string, form DrainForm) *DrainSite {
	if s, ok := inv.Drained[table]; ok {
		return s
	}
	s := &DrainSite{Table: table, Form: form}
	inv.Drained[table] = s
	return s
}

// DrainRosterName — имя росписи освобождений, на которое обязано сослаться
// обоснование в точке решения.
//
// Константой, а не литералом в теле проверки: переименуют роспись — поправят
// здесь же, и два места об одном имени не заведутся.
const DrainRosterName = "commutativeDrainExempt"

// foreignRosterRe — ссылка на роспись, КВАЛИФИЦИРОВАННУЮ чужим пакетом.
//
// Квалификатор несущий, а не косметика: `repohygiene.commutativeDrainExempt` —
// роспись ДРУГОГО репозитория, и после выноса службы записей её очередей она не
// несёт. Проверка, довольная одним лишь совпадением имени, приняла бы такую
// ссылку за исполненное делегирование — то есть зеленела бы ровно на том
// дефекте, ради которого заведена.
var foreignRosterRe = regexp.MustCompile(`\b([A-Za-z_]\w*)\.` + DrainRosterName + `\b`)

// commentsWithin — сколько комментариев лежит в области объявления, назвал ли
// хоть один роспись ЭТОГО дерева и какие назвали чужую.
func commentsWithin(fset *token.FileSet, file *ast.File, rel string, from, to token.Pos) (seen int, named bool, foreign []string) {
	for _, grp := range file.Comments {
		if grp.Pos() < from || grp.End() > to {
			continue
		}
		seen++
		text := grp.Text()
		if !strings.Contains(text, DrainRosterName) {
			continue
		}
		own := true
		for _, m := range foreignRosterRe.FindAllStringSubmatch(text, -1) {
			if m[1] != ownRosterQualifier {
				own = false
				foreign = append(foreign,
					fmt.Sprintf("%s:%d — %s.%s", rel, fset.Position(grp.Pos()).Line, m[1], DrainRosterName))
			}
		}
		if own {
			named = true
		}
	}
	return seen, named, foreign
}

// ownRosterQualifier — единственный законный квалификатор росписи: пакет этого
// дерева, в котором она объявлена.
const ownRosterQualifier = "check"

// litHasField — есть ли у литерала настроек названное поле.
func litHasField(lit *ast.CompositeLit, field string) bool {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if k, ok := kv.Key.(*ast.Ident); ok && k.Name == field {
			return true
		}
	}
	return false
}

// resolveFieldString — значение строкового поля литерала настроек.
//
// Законных форм записи ДВЕ, и обе распознаются: литерал и ИМЯ КОНСТАНТЫ
// (`clients.InviteMailTable`, `auditOutboxTable`). Форма, о которой разбор не
// знает, дала бы не красное и не зелёное, а молчание — очередь выпала бы из
// переписи вместе со своим решением о порядке.
func resolveFieldString(lit *ast.CompositeLit, field string, consts map[string]string, seen map[string]bool) string {
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		k, ok := kv.Key.(*ast.Ident)
		if !ok || k.Name != field {
			continue
		}
		switch v := kv.Value.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				s, err := strconv.Unquote(v.Value)
				if err == nil {
					return normalizeSQLName(s)
				}
			}
		case *ast.Ident:
			seen[v.Name] = true
			return normalizeSQLName(consts[v.Name])
		case *ast.SelectorExpr:
			seen[v.Sel.Name] = true
			return normalizeSQLName(consts[v.Sel.Name])
		}
	}
	return ""
}

// importAliases — псевдоним пакета в этом файле → путь импорта.
func importAliases(file *ast.File) map[string]string {
	out := map[string]string{}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := path
		if i := strings.LastIndex(path, "/"); i >= 0 {
			name = path[i+1:]
		}
		if imp.Name != nil {
			name = imp.Name.Name
		}
		out[name] = path
	}
	return out
}

// stringConstantsOf — строковые константы корпуса: имя → значение.
//
// Имя берётся БЕЗ приставки пакета, потому что место вызова называет константу
// хвостом селектора. Два прод-файла, назвавшие одним именем РАЗНЫЕ значения,
// дают неоднозначность: она возвращается отдельным перечнем, а не разрешается
// угадыванием — угаданное имя таблицы означало бы вердикт о чужой очереди.
func stringConstantsOf(corpus TreeCorpus) (map[string]string, map[string]bool, error) {
	out := map[string]string{}
	clash := map[string]bool{}
	fset := token.NewFileSet()
	for _, rel := range corpus.Rels() {
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.SkipObjectResolution)
		if perr != nil {
			return nil, nil, fmt.Errorf("разбор констант %s: %w", rel, perr)
		}
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					bl, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || bl.Kind != token.STRING {
						continue
					}
					val, uerr := strconv.Unquote(bl.Value)
					if uerr != nil {
						continue
					}
					if prev, seen := out[name.Name]; seen && prev != val {
						clash[name.Name] = true
					}
					out[name.Name] = val
				}
			}
		}
	}
	return out, clash, nil
}

// DrainSiteCorpus — прод-файлы Go дерева: и проводка, и собственный оператор
// живут только в них.
//
// Отдельным семейством, а не вызовом отбора в теле гейта: обход обязан
// приходить параметром, чтобы инъекция подала ему пустое дерево и премиса
// «прочитано ноль» была доказана исполнением, а не чтением (задача #17).
func DrainSiteCorpus(tree *treecorpus.Tree) (TreeCorpus, error) {
	return CorpusFrom(tree, ProductionGoFile)
}

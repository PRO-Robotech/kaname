// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// scopeedgesource_gate_test.go — Г2 (#785): ЗВЕНО, ЧЕЙ ИСТОЧНИК РАЗОШЁЛСЯ СО
// СВОИМ ЭТАЛОНОМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДЕРЖИТ ГЕЙТ И ПОЧЕМУ ОН ВООБЩЕ НУЖЕН
//
// Цепь областей читается SQL ВНУТРИ ПРЕДСТАВЛЕНИЯ, а containment материализации
// живёт КАРТОЙ В GO. Прочитать карту из SQL нельзя, значит совпадение двух
// записей удержать «одним источником» НЕВОЗМОЖНО — их будет две, и разойдутся
// они молча, при первой же правке любой из сторон. Цена названа и уплачена; гейт
// и есть плата: расхождение обязано КРАСНЕТЬ, а не обнаруживаться прогоном на
// стенде.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЭТАЛОН НАЗЫВАЕТСЯ ПОСВОЙСТВЕННО, А НЕ ОДНИМ ИСТОЧНИКОМ НА ВСЁ
//
// Прежде чем звать что-либо эталоном, надо ПОСЧИТАТЬ эталоны. Их в дереве ТРИ:
//
//	(1) материализация      — pg.IAMDirectContainments (план чтения реконсайлера);
//	(2) запасной путь       — domain.AccessBinding.StructuralParent и
//	                          domain.AccountScopedStructuralFact;
//	(3) модель прав         — какие отношения-указатели у типа объявлены вообще.
//
// Попарно они НЕ совпадают, и расходятся в двух местах (см. LegalDifferences
// ниже). Гейт, сверяющий цепь с ОДНИМ эталоном дословно, красен на ВЕРНОЙ
// реализации минимум по двум типам из семи — и второй исход хуже первого:
// читатель «приведёт стороны в согласие», правя материализацию, то есть
// поведение авторизации, объявленное вне предмета этой под-фазы.
//
// Поэтому «обязан молчать» здесь перечислен ПОИМЁННО, а не описан признаком: у
// признака нет способа отличить законное различие от нового расхождения.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ЗАКРЫВАЕТ — СКАЗАНО ПРЯМО
//
// Он сверяет КООРДИНАТЫ ИСТОЧНИКА (таблица, колонка, закрытый набор), а не то,
// что из них получается. Правильность содержания звена держат пробы группы B
// (scopechain_iamtypes_integration_test.go): они спрашивают ИСХОД вопроса о
// доступе, а не наличие строки в представлении.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// scopeEdgeMigrationDir — каталог миграций сервиса.
//
// Именно файлы, а не живая база: гейт обязан краснеть в конвейере, где базы нет,
// иначе он сторожит только тех, кто поднял стенд.
const scopeEdgeMigrationDir = "services/iam/internal/migrations"

// scopeEdgeViewAnchor — по чему опознаётся миграция, ОБЪЯВЛЯЮЩАЯ представление.
// Анкер на глаголе, а не на имени: имя встречается в каждой ветви и в шапке.
var scopeEdgeViewAnchor = regexp.MustCompile(`CREATE\s+(OR\s+REPLACE\s+)?VIEW\s+kacho_iam\.resource_scope_edge\b`)

// actingScopeEdgeMigration — файл с НАИБОЛЬШИМ номером, чей блок `Up` объявляет
// представление. Он и есть действующее определение: goose применяет по числу, и
// последнее объявление переживает все предыдущие.
//
// ВЫВОДИТСЯ ИЗ ДЕРЕВА, А НЕ ВЫПИСЫВАЕТСЯ, и это не стиль. Прежняя редакция
// называла файл константой — и с первой же миграцией, пересоздавшей
// представление, гейт продолжал бы сверять УСТАРЕВШЕЕ определение, объявляя
// согласие источников, которого больше нет. Расхождение было бы тихим ровно
// потому, что гейт зелен: он читает файл, который никто не менял.
func actingScopeEdgeMigration(t *testing.T) (name, body string) {
	t.Helper()
	root := scopeEdgeRepoRoot(t)
	dir := filepath.Join(root, scopeEdgeMigrationDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("каталог миграций не прочитан (%v): источник, который гейт не смог "+
			"прочитать, — ОТКАЗ, а не пропуск", err)
	}
	bestVersion := int64(-1)
	seen := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		seen++
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- in-repo migrations dir
		if rerr != nil {
			t.Fatalf("миграция %s не прочитана (%v): отказ чтения — не пропуск", e.Name(), rerr)
		}
		up, uerr := upBlock(string(raw))
		if uerr != nil || !scopeEdgeViewAnchor.MatchString(up) {
			continue
		}
		v, verr := strconv.ParseInt(strings.SplitN(e.Name(), "_", 2)[0], 10, 64)
		if verr != nil {
			t.Fatalf("номер миграции %s не разобран (%v): порядок применения неизвестен, "+
				"и «действующее определение» выбрать не из чего", e.Name(), verr)
		}
		if v > bestVersion {
			bestVersion, name, body = v, e.Name(), string(raw)
		}
	}
	if seen == 0 {
		t.Fatal("в каталоге миграций НОЛЬ файлов .sql: предпосылка гейта ложна, и его " +
			"молчание означало бы «ничего не прочитано», а не «источники согласны»")
	}
	if name == "" {
		t.Fatalf("среди %d миграций ни одна не объявляет kacho_iam.resource_scope_edge: "+
			"либо анкер устарел, либо представление снято — в обоих случаях это ОТКАЗ", seen)
	}
	t.Logf("осмотрено миграций %d; действующее определение цепи — %s (версия %d)",
		seen, name, bestVersion)
	return name, body
}

// scopeEdgeBranch — одна ветвь представления, разобранная из SQL.
type scopeEdgeBranch struct {
	ObjectType string // тип объекта в словаре МОДЕЛИ
	Table      string // из какой таблицы читается ПОД ПСЕВДОНИМОМ `o` (форма «колонка своей строки»)
	// SourceTable — таблица ветви ПРИ ЛЮБОМ псевдониме. Отдельно от Table
	// потому, что ветвь личности выбирает из таблицы СВЯЗИ под псевдонимом `m`
	// (#944): для посвойственной сверки колонки она не годится, а для вопроса
	// «из какой таблицы взят предок» — единственно годится.
	SourceTable string
	ParentType  string // тип предка: литерал либо выражение над колонкой
	ParentCol   string // колонка-указатель (без псевдонима)
	ScopeSet    string // закрытый набор областей из отбора ветви, если он там есть
}

// legalDifference — законное различие цепи с containment'ом материализации.
//
// Каждая запись несёт ПРИЧИНУ и ЭТАЛОН, который здесь главнее материализации.
// Запись без причины через полгода неотличима от забытого послабления.
type legalDifference struct {
	ObjectType string
	Why        string
}

// legalDifferences — ПОИМЁННЫЙ перечень мест, где цепь законно расходится с
// планом чтения материализации.
//
// Их пять, и ни одно не является дефектом:
var legalDifferences = []legalDifference{
	{"project", "звено взято из ПРОЕКЦИИ ЖУРНАЛА (781001): у проекта журнал полон по " +
		"построению, а таблица состояния наблюдаемо нет. Containment материализации " +
		"называет проект своим же родителем (parentProjectExpr = o.id) — это ответ на " +
		"другой вопрос («что содержит объект»), не на вопрос о предке"},
	{"account", "предок аккаунта — синглтон кластера (740001), а не колонка строки. " +
		"Containment называет аккаунт своим же родителем (parentAccountExpr = o.id) — " +
		"снова ответ на другой вопрос"},
	{"iam_access_binding", "у привязки с областью «кластер» containment предка НЕ ДАЁТ " +
		"(оба его выражения на такой строке пусты, его собственный комментарий это " +
		"оговаривает), а цепь даёт. Эталон здесь — ЗАПАСНОЙ СТРУКТУРНЫЙ ПУТЬ " +
		"(domain.StructuralParent), и модель на его стороне: у типа объявлены все три " +
		"области"},
	{"iam_user", "обе стороны читают kacho_iam.memberships (#944 — цепь, #1172 — " +
		"материализация), и это ПРОВЕРЯЕТСЯ отдельным утверждением ниже (источник 4), а не " +
		"пропускается. Здесь пропущена только ПОСВОЙСТВЕННАЯ сверка колонки-указателя: у " +
		"личности аккаунт не является свойством её собственной строки, поэтому ветвь цепи " +
		"выбирает не из `o`, а из `m` (таблицы связи), и колонки СВОЕЙ строки у звена нет " +
		"вовсе. Сверять её здесь дословно было бы нечем: у материализации на этом " +
		"месте стоит выражение-НАБОР (аккаунтов у человека столько, сколько членств), а не " +
		"колонка. Что набор действительно читается связью — держит поведенческая проба " +
		"reconcile_person_membership_scope_integration_test.go, а не эта запись"},
	{"iam_role", "у роли с областью «проект» containment добирает аккаунт СОЕДИНЕНИЕМ с " +
		"таблицей проектов, а цепь берёт колонку самой роли и поднимается к аккаунту " +
		"ОБХОДОМ. Величина та же, путь разный: требовать тождества значило бы требовать " +
		"от цепи повторить соединение, которое обход делает сам"},
}

// exactSourceTypes — типы, у которых таблица и колонка-указатель обязаны
// совпасть с containment'ом материализации ДОСЛОВНО.
//
// Это те, у кого выражение containment'а — простая колонка своей строки. Там,
// где оно составное (соединение, CASE, ссылка на себя), эталоном служит другой
// источник, и тип стоит в legalDifferences.
var exactSourceTypes = map[string]string{
	"iam_group":           "o.account_id",
	"iam_service_account": "o.account_id",
}

func scopeEdgeRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): гейту негде искать миграцию, и его "+
			"молчание не означало бы согласия источников", err)
	}
	return strings.TrimSpace(string(out))
}

// upBlock возвращает исполняемый блок `Up` БЕЗ строк комментария.
//
// Обе очистки обязательны и по разным причинам. Блок — потому что строка,
// восстанавливающая прежнее определение, лежит в `Down`, и предикат без
// разделения по блокам прочитал бы её как действительность (эта ловушка стоила
// приёмке отдельного раунда). Комментарии — потому что шапка этой же миграции
// называет все пять типов и все пять таблиц ДЕСЯТКИ раз, объясняя их: гейт по
// подстроке зеленел бы на собственном объяснении.
func upBlock(body string) (string, error) {
	up := strings.Index(body, "-- +goose Up")
	down := strings.Index(body, "-- +goose Down")
	if up < 0 || down < 0 || down < up {
		return "", fmt.Errorf("в миграции не найдены оба блока goose (Up=%d, Down=%d): гейт "+
			"читал бы неизвестно что и его вердикт не относился бы к действующему определению",
			up, down)
	}
	var kept []string
	for _, line := range strings.Split(body[up:down], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		kept = append(kept, line)
	}
	return strings.Join(kept, "\n"), nil
}

// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР SQL: ДВЕ ЗАКОННЫЕ ФОРМЫ ЗАПИСИ ОДНОГО ПРЕДМЕТА
//
// Представление записывается в дереве ДВУМЯ формами, и обе законны:
//
//	РУКОПИСНАЯ — `SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1`
//	             и `lower(o.resource_type) IN ('project', 'account', 'cluster')`;
//	ФОРМА СВОДА — `pg_dump` пишет тот же смысл иначе: каждый элемент выборки на
//	             своей строке и с псевдонимом (`AS object_type`), а членство в
//	             закрытом наборе — через `= ANY (ARRAY[…])`.
//
// Распознаватель, знающий ОДНУ форму, на второй не краснеет и не зеленеет — он
// МОЛЧИТ: ветвь просто не разбирается, тип выходит из-под сверки, и «источники
// согласны» становится неотличимо от «ничего не прочитано». Поэтому список
// выборки разбирается ПОЗИЦИОННО (режется по запятым вне скобок и вне строковых
// литералов, псевдоним снимается), а не образцом под одну форму; закрытый набор
// областей ищется в обеих записях. Каждая форма доказана своей инъекцией.

var (
	reObjectType = regexp.MustCompile(`SELECT\s+'([a-z_]+)'::text`)
	// reObjectTypeLiteral — тот же литерал как ЦЕЛЫЙ элемент выборки: разбор
	// позиционный, поэтому тип берётся из первого элемента, а не откуда придётся.
	reObjectTypeLiteral = regexp.MustCompile(`^'([a-z_]+)'::text$`)
	// reFromTableAlias — таблица ветви и её ПСЕВДОНИМ. Псевдоним нужен целиком:
	// по нему отличается «колонка своей строки» (`o`) от таблицы связи (`m`).
	// Открывающая скобка допускается: свод пишет соединение как `FROM (a CROSS JOIN b)`.
	reFromTableAlias = regexp.MustCompile(`\(?\s*(kacho_iam\.[a-z_]+)\s+(?:AS\s+)?([a-z][a-z0-9_]*)\b`)
	// reColumnAlias — псевдоним элемента выборки (`… AS parent_id`), который
	// пишет свод и не пишет рука.
	reColumnAlias = regexp.MustCompile(`(?i)\s+AS\s+[a-z_][a-z0-9_]*$`)
	// reScopeSetIn / reScopeSetAny — ЗАКРЫТЫЙ НАБОР областей берётся из отбора
	// ветви, а не из списка выборки: в списке стоит `lower(o.resource_type)` —
	// ВЫРАЖЕНИЕ, а не перечень. Гейт, прочитавший выражение вместо набора,
	// объявил бы расхождение по каждой законной области сразу — то есть
	// покраснел бы на верной реализации, ровно тем способом, который сам и ловит.
	//
	// Форм две, и обе обязаны быть здесь: рукописная (`IN (…)`) и форма свода
	// (`= ANY (ARRAY[…])`). Знать одну значило бы не судить набор ВОВСЕ на
	// дереве, записанном другой, — при этом гейт отказывает («набор не
	// разобран»), а не молчит, и именно поэтому его отказ читается как поломка
	// самого гейта, а не как находка.
	reScopeSetIn  = regexp.MustCompile(`lower\(o\.resource_type\)\s+IN\s*\(([^)]*)\)`)
	reScopeSetAny = regexp.MustCompile(`lower\(o\.resource_type\)\s*=\s*ANY\s*\(\s*ARRAY\[([^\]]*)\]\s*\)`)
)

// isSQLWordByte — байт, который может стоять ВНУТРИ имени или ключевого слова.
func isSQLWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// sqlTopLevel — позиции запятых и первых вхождений названных лексем НА НУЛЕВОЙ
// ГЛУБИНЕ скобок и ВНЕ строковых литералов.
//
// Кавычки учитываются не для аккуратности: `POSITION((':'::text) IN (f.subject))`
// несёт двоеточие внутри литерала, а закрытый набор областей — запятые; разбор,
// считающий их наравне с остальными, режет выражение посередине.
func sqlTopLevel(s string, lexemes ...string) (commas []int, at map[string]int) {
	at = map[string]int{}
	depth := 0
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if c == '\'' {
				if i+1 < len(s) && s[i+1] == '\'' {
					i++
					continue
				}
				inQuote = false
			}
			continue
		}
		switch c {
		case '\'':
			inQuote = true
			continue
		case '(':
			depth++
			continue
		case ')':
			depth--
			continue
		case ',':
			if depth == 0 {
				commas = append(commas, i)
			}
			continue
		}
		if depth != 0 {
			continue
		}
		for _, w := range lexemes {
			if _, seen := at[w]; seen {
				continue
			}
			if !strings.HasPrefix(s[i:], w) {
				continue
			}
			// Граница слова спрашивается только у СЛОВА: точка с запятой стоит
			// вплотную к скобке, и требовать от неё границы значило бы не найти
			// её никогда.
			if isSQLWordByte(w[0]) {
				if i > 0 && isSQLWordByte(s[i-1]) {
					continue
				}
				if j := i + len(w); j < len(s) && isSQLWordByte(s[j]) {
					continue
				}
			}
			at[w] = i
		}
	}
	return commas, at
}

// splitSelectList режет список выборки на элементы и снимает псевдонимы.
func splitSelectList(list string) []string {
	commas, _ := sqlTopLevel(list)
	var items []string
	prev := 0
	for _, cut := range append(commas, len(list)) {
		item := strings.TrimSpace(list[prev:cut])
		items = append(items, strings.TrimSpace(reColumnAlias.ReplaceAllString(item, "")))
		prev = cut + 1
	}
	return items
}

// scopeEdgeViewBody — ТЕЛО объявления представления: от глагола до его
// собственной точки с запятой.
//
// Референт сужен до тела НАМЕРЕННО, и это не оптимизация. Прежде им был весь
// блок `Up`, и это было верно ровно пока представление объявляла ОТДЕЛЬНАЯ
// миграция. В своде тот же блок несёт ВСЮ схему сервиса: «ветви представления»
// стали бы разбираться из чужих операторов, а последняя ветвь тянула бы за собой
// три тысячи строк, к цепи отношения не имеющих. То есть референт выродился бы
// вместе с числом файлов, а не с предметом. Тело не зависит от того, в скольких
// файлах записана схема.
func scopeEdgeViewBody(up string) (string, error) {
	loc := scopeEdgeViewAnchor.FindStringIndex(up)
	if loc == nil {
		return "", fmt.Errorf("в исполняемом блоке нет объявления " +
			"kacho_iam.resource_scope_edge: разбирать нечего, и молчание здесь означало бы " +
			"«ничего не прочитано», а не «источники согласны»")
	}
	body := up[loc[0]:]
	if _, at := sqlTopLevel(body, ";"); len(at) > 0 {
		body = body[:at[";"]]
	}
	return body, nil
}

// parseBranches разбирает ветви представления из ТЕЛА его объявления.
//
// Разбираются ветви, чей первый элемент выборки — литерал типа. Ветвь
// «присланное дословно» такого литерала не несёт (она выбирает колонки
// resource_parent_edge) и в разбор не попадает by construction.
func parseBranches(viewBody string) []scopeEdgeBranch {
	var out []scopeEdgeBranch
	for _, arm := range strings.Split(viewBody, "UNION ALL") {
		if br, ok := parseBranch(arm); ok {
			out = append(out, br)
		}
	}
	return out
}

// parseBranch разбирает ОДНУ ветвь. Форма записи безразлична (см. разбор выше).
func parseBranch(arm string) (scopeEdgeBranch, bool) {
	// Ветвь ограничивается СВОИМ оператором: точка с запятой на нулевой глубине
	// и есть его конец.
	if _, at := sqlTopLevel(arm, ";"); len(at) > 0 {
		arm = arm[:at[";"]]
	}
	sel := strings.Index(arm, "SELECT")
	if sel < 0 {
		return scopeEdgeBranch{}, false
	}
	rest := arm[sel+len("SELECT"):]
	_, at := sqlTopLevel(rest, "FROM", "WHERE")
	fromAt, hasFrom := at["FROM"]
	if !hasFrom {
		// Ветвь без собственного FROM неразбираема, но ТИП назвать можно — и
		// надо: промолчав, гейт вывел бы тип из-под сверки МОЛЧА, то есть завёл
		// бы ровно ту слепую зону, ради закрытия которой написан.
		if m := reObjectType.FindStringSubmatch(arm); m != nil {
			return scopeEdgeBranch{ObjectType: m[1]}, true
		}
		return scopeEdgeBranch{}, false
	}
	items := splitSelectList(rest[:fromAt])
	if len(items) == 0 {
		return scopeEdgeBranch{}, false
	}
	m := reObjectTypeLiteral.FindStringSubmatch(items[0])
	if m == nil {
		return scopeEdgeBranch{}, false
	}
	// Таблица и колонка НЕОБЯЗАТЕЛЬНЫ: ветви проекта и аккаунта читают проекцию
	// журнала и синглтон кластера, а не собственную строку объекта, и пропустить
	// их значило бы вывести два типа из-под сверки МОЛЧА — они не попали бы ни в
	// сверенные, ни в пропущенные, и счётчик объёма соврал бы в обе стороны.
	br := scopeEdgeBranch{ObjectType: m[1]}
	if len(items) >= 5 {
		br.ParentType, br.ParentCol = items[2], items[3]
	}
	tail := rest[fromAt+len("FROM"):]
	if w, has := at["WHERE"]; has && w > fromAt {
		tail = rest[fromAt+len("FROM") : w]
	}
	if t := reFromTableAlias.FindStringSubmatch(tail); t != nil {
		br.SourceTable = t[1]
		if t[2] == "o" {
			br.Table = t[1]
		}
	}
	if w, has := at["WHERE"]; has {
		where := rest[w:]
		if set := reScopeSetIn.FindStringSubmatch(where); set != nil {
			br.ScopeSet = set[1]
		} else if set := reScopeSetAny.FindStringSubmatch(where); set != nil {
			br.ScopeSet = set[1]
		}
	}
	return br, true
}

// TestG2_ScopeEdgeSourceAgreesWithItsPerPropertyReference — Г2.
//
// Утверждается ИСХОД сверки, и печатается объём осмотренного: сколько типов
// сверено, какие ТРИ источника прочитаны, сколько законных различий пропущено.
// «Ноль находок» обязано быть отличимо от «ноль прочитанного», а ноль
// пропущенных различий на дереве, где их четыре, — тоже находка: значит гейт
// читает не то.
func TestG2_ScopeEdgeSourceAgreesWithItsPerPropertyReference(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	report, findings := auditScopeEdgeSources(migration, body)
	for _, line := range report {
		t.Log(line)
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// readScopeEdgeMigration отдаёт текст ДЕЙСТВУЮЩЕЙ миграции цепи.
//
// Отдельной функцией — чтобы инъекция кормила гейт НАСТОЯЩИМ входом из дерева с
// точечной правкой, а не синтетической строкой. Синтетика доказывает, что гейт
// умеет краснеть на том, что для него сочинили, и ничего не говорит о том, что
// он увидит настоящий дефект.
func readScopeEdgeMigration(t *testing.T) (name, body string) {
	t.Helper()
	return actingScopeEdgeMigration(t)
}

// currentContainments — план чтения материализации, каким он лежит в дереве,
// перекодированный в словарь МОДЕЛИ (гейт сверяет типы одним написанием).
func currentContainments() map[string]pg.IAMDirectContainment {
	out := map[string]pg.IAMDirectContainment{}
	for _, c := range pg.IAMDirectContainments() {
		out[authzmap.ModelTypeName(c.ObjectType)] = c
	}
	return out
}

func auditScopeEdgeSources(migration, body string) (report, findings []string) {
	return auditScopeEdgeSourcesWith(migration, body, currentContainments())
}

// auditScopeEdgeSourcesWith — тот же аудит при ЯВНО переданном плане чтения.
//
// План — параметр, а не чтение изнутри, потому что инъекция обязана уметь
// вернуть дефект с ОБЕИХ сторон сверки. Дефект со стороны цепи вносится правкой
// текста миграции; дефект со стороны материализации вносить было НЕЧЕМ, пока
// план читался внутри, — и утверждение «стороны согласны» проверялось бы ровно
// наполовину.
func auditScopeEdgeSourcesWith(
	migration, body string, containment map[string]pg.IAMDirectContainment,
) (report, findings []string) {
	up, err := upBlock(body)
	if err != nil {
		return nil, []string{err.Error()}
	}
	view, verr := scopeEdgeViewBody(up)
	if verr != nil {
		return nil, []string{verr.Error()}
	}
	branches := parseBranches(view)
	if len(branches) == 0 {
		return report, append(findings, fmt.Sprintf(
			"в блоке Up не разобрано НИ ОДНОЙ ветви, выводимой из строки объекта: "+
				"предпосылка гейта не выполнена, и его молчание означало бы «ничего не "+
				"прочитано», а не «источники согласны».\nМиграция: %s", migration))
	}

	// ── источник 1: containment материализации ──────────────────────────────
	if len(containment) == 0 {
		return report, append(findings,
			"план чтения материализации ПУСТ: сверять не с чем, и это ОТКАЗ, а не согласие")
	}

	legal := map[string]string{}
	for _, d := range legalDifferences {
		legal[d.ObjectType] = d.Why
	}

	byType := map[string][]scopeEdgeBranch{}
	for _, b := range branches {
		byType[b.ObjectType] = append(byType[b.ObjectType], b)
	}

	compared, skipped := 0, 0
	types := make([]string, 0, len(byType))
	for ty := range byType {
		types = append(types, ty)
	}
	sort.Strings(types)

	for _, ty := range types {
		if why, ok := legal[ty]; ok {
			skipped++
			report = append(report, fmt.Sprintf("  %-20s законное различие, пропущено: %s", ty, why))
			continue
		}
		wantCol, exact := exactSourceTypes[ty]
		if !exact {
			findings = append(findings, fmt.Sprintf(
				"тип %q имеет ветвь в цепи, но не назван НИ в exactSourceTypes, НИ в "+
					"legalDifferences.\nГейт не знает, с чем его сверять, и промолчать здесь "+
					"значило бы вывести тип из-под сверки МОЛЧА — ровно то, что гейт и ловит.", ty))
			continue
		}
		c, ok := containment[ty]
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"у типа %q есть ветвь цепи, а плана чтения материализации нет: цепь и "+
					"реконсайлер считают «внутри» по разным источникам", ty))
			continue
		}
		compared++
		for _, b := range byType[ty] {
			if b.Table != c.Table {
				findings = append(findings, fmt.Sprintf(
					"тип %q: цепь читает таблицу %s, containment материализации — %s.\n"+
						"  цепь:           %s\n"+
						"  материализация: pg.IAMDirectContainments()[%q].Table",
					ty, b.Table, c.Table, migration, c.ObjectType))
			}
			if b.ParentCol != wantCol || c.ParentAccountExpr != wantCol {
				findings = append(findings, fmt.Sprintf(
					"тип %q: колонка-указатель разошлась.\n"+
						"  цепь:           %s (%s)\n"+
						"  материализация: %s (pg.IAMDirectContainments()[%q].ParentAccountExpr)\n"+
						"  эталон:         %s\n"+
						"По этой колонке выдача на область ФАКТИЧЕСКИ накрывает объект; расхождение "+
						"означает, что форма E и материализация считают «внутри» по-разному.",
					ty, b.ParentCol, migration, c.ParentAccountExpr, c.ObjectType, wantCol))
			}
		}
	}

	// ── источник 2: закрытый набор областей привязки ────────────────────────
	//
	// Эталон — НЕ перечень в этом файле, а ИСХОД запасного структурного пути:
	// спрашивается то же, что спрашивает эмиттер указателя. Перечень был бы
	// вторым местом об одном предмете и разошёлся бы молча.
	bindingSet := ""
	for _, b := range byType["iam_access_binding"] {
		if b.ScopeSet != "" {
			bindingSet = b.ScopeSet
		}
	}
	if bindingSet == "" {
		return report, append(findings, fmt.Sprintf(
			"в ветви привязки не разобран закрытый набор областей: сверять не с чем, и "+
				"молчание здесь означало бы «не прочитано», а не «наборы совпали».\n"+
				"Миграция: %s", migration))
	}
	probes := []string{"project", "account", "cluster", "vpc_network", "*", "", "organization"}
	setChecked := 0
	for _, scope := range probes {
		_, bindable := domain.AccessBinding{
			ID: "abn-probe", ResourceType: domain.ResourceType(scope), ResourceID: "res-probe",
		}.StructuralParent()
		inChain := strings.Contains(bindingSet, "'"+scope+"'")
		setChecked++
		if bindable != inChain {
			findings = append(findings, fmt.Sprintf(
				"область %q: запасной путь говорит bindable=%v, цепь — %v.\n"+
					"  цепь:   %s (набор ветви привязки: %s)\n"+
					"  эталон: domain.AccessBinding.StructuralParent — тот же закрытый набор, "+
					"которым пользуется эмиттер указателя\n"+
					"Расхождение набора означает либо звено на объект, отношения к которому у "+
					"типа в модели нет, либо ПОТЕРЮ законной области: привязка на неё перестала "+
					"бы иметь предка, и верхний ярус доступа к ней отвечал бы отказом, "+
					"неотличимым от честного.",
				scope, bindable, inChain, migration, bindingSet))
		}
	}

	// ── источник 4: звено, чей предок НЕ является свойством своей строки ────
	//
	// Посвойственная сверка колонки такому звену не годится (разбор ветвей
	// написан под форму «колонка своей строки»), но БЕЗ ВСЯКОЙ сверки тип вышел
	// бы из-под гейта молча — то есть завёл бы ровно ту слепую зону, ради
	// закрытия которой гейт написан. Поэтому сверяется то, что сверить можно и
	// что и есть предмет: обе стороны обязаны читать ОДНУ И ТУ ЖЕ таблицу.
	//
	// Личность — единственный такой тип сегодня, и перечень выводится из ПЛАНА
	// ЧТЕНИЯ (у кого нет колонки собственной строки), а не выписывается: второй
	// такой тип попадёт под сверку сам, а не будет ждать, пока о нём вспомнят.
	linked := 0
	linkedTypes := make([]string, 0, len(containment))
	for ty, c := range containment {
		if c.ParentAccountExpr != "" {
			continue // аккаунт — колонка своей строки; сверен выше либо законно пропущен
		}
		linkedTypes = append(linkedTypes, ty)
	}
	sort.Strings(linkedTypes)
	for _, ty := range linkedTypes {
		c := containment[ty]
		brs := byType[ty]
		if len(brs) == 0 {
			findings = append(findings, fmt.Sprintf(
				"тип %q берёт аккаунт СВЯЗЬЮ (колонки своей строки у него нет), а ветви в "+
					"цепи областей у него НЕТ: администратор аккаунта не достаёт до объекта "+
					"вовсе, и отказ неотличим от честного.\n  материализация: %s",
				ty, c.ParentAccountsExpr))
			continue
		}
		for _, b := range brs {
			linked++
			if b.SourceTable == "" {
				findings = append(findings, fmt.Sprintf(
					"тип %q: у ветви цепи не разобрана таблица-источник — сверять не с чем, "+
						"и молчание здесь означало бы «не прочитано», а не «стороны согласны».\n"+
						"  Миграция: %s", ty, migration))
				continue
			}
			if !strings.Contains(c.ParentAccountsExpr, b.SourceTable) {
				findings = append(findings, fmt.Sprintf(
					"тип %q: цепь берёт предка из %s, а план чтения материализации его не "+
						"называет.\n"+
						"  цепь:           %s (%s)\n"+
						"  материализация: %s (pg.IAMDirectContainments()[%q].ParentAccountsExpr)\n"+
						"Две записи об одном предмете — «через какой аккаунт достаётся объект» — "+
						"и они разошлись: выдача накрывает не тех, кого накрывает каскад.",
					ty, b.SourceTable, migration, b.SourceTable, c.ParentAccountsExpr, c.ObjectType))
			}
		}
	}

	// ── источник 3: модель прав — типы, чей предок объявлен выводимым ───────
	declared := len(authzcascade.DerivableTypes)
	if declared == 0 {
		return report, append(findings,
			"перечень выводимых типов ПУСТ: предпосылка гейта не выполнена, и «ноль находок» "+
				"здесь означало бы «ноль прочитанного»")
	}

	report = append(report, fmt.Sprintf(
		"прочитано ТРИ источника: containment материализации (%d записей), запасной "+
			"структурный путь (%d областей опрошено), перечень выводимых типов (%d)",
		len(containment), setChecked, declared))
	report = append(report, fmt.Sprintf(
		"сверено типов: %d, законных различий пропущено: %d, "+
			"звеньев «предок берётся связью» сверено по таблице-источнику: %d",
		compared, skipped, linked))
	if len(linkedTypes) > 0 && linked == 0 {
		findings = append(findings, fmt.Sprintf(
			"типов, берущих аккаунт связью, %d, а сверено по таблице-источнику НОЛЬ: "+
				"гейт читает не то, и его молчание об этих типах ничего не означает",
			len(linkedTypes)))
	}

	if compared == 0 {
		findings = append(findings, fmt.Sprintf(
			"сверено НОЛЬ типов при %d разобранных ветвях: гейт читает не то, и его молчание "+
				"не означает согласия источников", len(branches)))
	}
	if skipped != len(legalDifferences) {
		findings = append(findings, fmt.Sprintf(
			"законных различий пропущено %d, а объявлено %d.\n"+
				"Меньше объявленного означает, что гейт читает не то; больше — что запись "+
				"пережила свой предмет и её надо снять вместе с ним.",
			skipped, len(legalDifferences)))
	}
	return report, findings
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ
//
// Гейт без инъекции ловит форму, а не существо, и первый же ложный срабат его
// выключит. Инъекции ниже кормят гейт НАСТОЯЩИМ текстом миграции из дерева с
// точечной правкой — синтетическая строка доказывала бы только, что гейт умеет
// краснеть на том, что для него сочинили.
//
// Проверяется ПАРА: (а) вернуть дефект — краснеет и называет координату;
// (б) поставить рядом ЗАКОННУЮ конструкцию той же формы — молчит.

// injectedFindings прогоняет ТЕЛО гейта на подложенном тексте и отдаёт находки.
//
// Прогоняется не подставной `*testing.T`, а сам аудитор: он возвращает находки
// значением, поэтому инъекция читает ИСХОД, а не побочный эффект. Через `t.Run`
// это было бы невыразимо — падение подпробы делает красной и родительскую, и
// «инъекция сработала» стало бы неотличимо от «инъекция сломала гейт».
func injectedFindings(t *testing.T, migration, body string) []string {
	t.Helper()
	_, findings := auditScopeEdgeSources(migration, body)
	return findings
}

// pointEdit — точечная правка НАСТОЯЩЕГО текста в той форме, которая в дереве
// есть. Возвращает число применённых правок: инъекция обязана требовать РОВНО
// одной, иначе «гейт покраснел» ничего не доказывает.
//
// Форм у представления две (см. разбор выше), и инъекция обязана уметь обе:
// привязанная к одной, при смене формы она отказывает словами «ничего не
// изменилось» — а этот отказ читается как поломка гейта, хотя гейт исправен.
func pointEdit(body string, forms [][2]string) (string, int) {
	out, applied := body, 0
	for _, f := range forms {
		if strings.Contains(out, f[0]) {
			out = strings.Replace(out, f[0], f[1], 1)
			applied++
		}
	}
	return out, applied
}

// groupPointerForms — увод колонки-указателя группы с account_id на её же id.
var groupPointerForms = [][2]string{
	{ // форма свода
		"    o.account_id AS parent_id,\n    1 AS depth\n   FROM kacho_iam.groups o",
		"    o.id AS parent_id,\n    1 AS depth\n   FROM kacho_iam.groups o",
	},
	{ // рукописная
		"SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1",
		"SELECT 'iam_group'::text, o.id, 'account'::text, o.id, 1",
	},
}

// bindingScopeDropForms — снятие области «кластер» из закрытого набора привязки.
var bindingScopeDropForms = [][2]string{
	{ // форма свода
		"lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text, 'cluster'::text])",
		"lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text])",
	},
	{ // рукописная
		"lower(o.resource_type) IN ('project', 'account', 'cluster')",
		"lower(o.resource_type) IN ('project', 'account')",
	},
}

// identityBranchToColumnForms — увод звена личности с таблицы связи обратно на
// колонку строки, то есть в состояние, из которого его вывели #944 и #1172.
var identityBranchToColumnForms = [][2]string{
	{ // форма свода
		"    m.user_id AS object_id,\n    'account'::text AS parent_type,\n" +
			"    m.account_id AS parent_id,\n    1 AS depth\n   FROM kacho_iam.memberships m",
		"    o.id AS object_id,\n    'account'::text AS parent_type,\n" +
			"    o.account_id AS parent_id,\n    1 AS depth\n   FROM kacho_iam.users o",
	},
	{ // рукописная
		"SELECT 'iam_user'::text, m.user_id, 'account'::text, m.account_id, 1\n" +
			"    FROM kacho_iam.memberships m",
		"SELECT 'iam_user'::text, o.id, 'account'::text, o.account_id, 1\n" +
			"    FROM kacho_iam.users o",
	},
}

// handWrittenForms — перевод ДВУХ ветвей свода в РУКОПИСНУЮ форму без смены
// смысла. Текст правой части взят дословно из миграции, объявлявшей
// представление до свода: это настоящая форма дерева, а не сочинённая для пробы.
//
// Ветви выбраны так, чтобы задеть ОБА распознавателя, которых касается форма:
// список выборки (группа) и закрытый набор областей (привязка). Скобки в обеих
// заменах сбалансированы — иначе разбор по глубине читал бы следующую ветвь как
// продолжение этой.
var handWrittenForms = [][2]string{
	{
		" SELECT 'iam_group'::text AS object_type,\n    o.id AS object_id,\n" +
			"    'account'::text AS parent_type,\n    o.account_id AS parent_id,\n" +
			"    1 AS depth\n   FROM kacho_iam.groups o",
		"  SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1\n" +
			"    FROM kacho_iam.groups o",
	},
	{
		"(lower(o.resource_type) = ANY (ARRAY['project'::text, 'account'::text, 'cluster'::text]))",
		"(lower(o.resource_type) IN ('project', 'account', 'cluster'))",
	},
}

// TestG2_InjectionPointerColumnDivergedIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Колонка-указатель изменена в ОДНОЙ записи (в представлении) и не изменена в
// другой (в плане чтения материализации) — ровно тот дрейф, ради которого гейт
// существует: удержать две записи «одним источником» невозможно, значит
// расхождение обязано краснеть, а не обнаруживаться прогоном на стенде.
// ЦЕЛЬ ИНЪЕКЦИИ — ГРУППА, а не личность, и это не безразличный выбор. Личность
// выведена из ПОСВОЙСТВЕННОЙ сверки колонки (её предок — не колонка своей строки),
// и меряется она другим утверждением — согласием таблицы-источника (источник 4,
// своя пара инъекций ниже). Ветвь группы осталась в exactSourceTypes и имеет ту же
// форму — значит эта инъекция по-прежнему меряет способность гейта найти ДРЕЙФ
// КОЛОНКИ, а не конкретный тип.
func TestG2_InjectionPointerColumnDivergedIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	// Точечная правка НАСТОЯЩЕГО текста: у группы указатель уводится с
	// account_id на собственный идентификатор.
	broken, applied := pointEdit(body, groupPointerForms)
	if applied != 1 {
		t.Fatalf("правок применено %d вместо одной: ветвь группы в миграции не найдена "+
			"НИ В ОДНОЙ из известных форм записи, и «гейт покраснел» ничего не "+
			"доказывало бы.\nМиграция: %s", applied, migration)
	}
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на разошедшейся колонке-указателе: цепь читает o.id, " +
			"containment материализации — o.account_id. Такой гейт не держит ничего.")
	}
	// Находка обязана НАЗВАТЬ КООРДИНАТУ — и тип, и обе стороны. Красное без
	// координаты заставляет читателя искать расхождение самому, и первым он
	// найдёт не то.
	joined := strings.Join(found, "\n")
	for _, want := range []string{"iam_group", "o.account_id", migration} {
		if !strings.Contains(joined, want) {
			t.Errorf("находка не называет %q:\n%s", want, joined)
		}
	}
}

// TestG2_InjectionScopeDroppedFromClosedSetIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Из набора областей привязки убрано значение, которое `isBindableScope`
// по-прежнему признаёт. Наблюдаемо это ПОТЕРЯ ЗАКОННОЙ ОБЛАСТИ: привязка,
// сделанная на кластер, перестала бы иметь предка, и верхний ярус доступа к ней
// отвечал бы отказом, неотличимым от честного.
func TestG2_InjectionScopeDroppedFromClosedSetIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	broken, applied := pointEdit(body, bindingScopeDropForms)
	if applied != 1 {
		t.Fatalf("правок применено %d вместо одной: закрытый набор областей в миграции "+
			"не найден НИ В ОДНОЙ из известных форм записи.\nМиграция: %s", applied, migration)
	}
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на области, убранной из набора цепи и оставшейся в " +
			"закрытом наборе эмиттера: наборы разошлись, а сторож этого не заметил")
	}
	if joined := strings.Join(found, "\n"); !strings.Contains(joined, "cluster") {
		t.Errorf("находка не называет потерянную область:\n%s", joined)
	}
}

// TestG2_InjectionUndeclaredTypeIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Ветвь заведена типу, который не назван НИ эталоном-колонкой, НИ законным
// различием. Промолчать здесь значило бы вывести тип из-под сверки МОЛЧА — то
// есть завести ровно ту слепую зону, ради закрытия которой гейт и написан.
func TestG2_InjectionUndeclaredTypeIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	// Законная по форме, но никем не объявленная ветвь: тот же вид, что у
	// пользователя, только тип другой. Записана РУКОПИСНОЙ формой — она
	// такая же законная, как форма свода, и заодно даёт разбору список выборки
	// без псевдонимов.
	//
	// Вставляется ВНУТРЬ тела представления, а не после него: гейт судит тело, и
	// ветвь, приписанная за точкой с запятой, до него не доехала бы вовсе — а
	// «гейт промолчал» читалось бы как его слепота, хотя он не видел правки.
	up, uerr := upBlock(body)
	if uerr != nil {
		t.Fatalf("блок Up не разобран: %v", uerr)
	}
	view, verr := scopeEdgeViewBody(up)
	if verr != nil {
		t.Fatalf("тело представления не найдено: %v", verr)
	}
	extra := `
UNION ALL
  SELECT 'iam_unnamed'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.users o
   WHERE COALESCE(o.account_id, '') <> ''`
	broken := "-- +goose Up\n" + strings.Replace(up, view, view+extra, 1) + "\n-- +goose Down\n"
	if !strings.Contains(broken, "iam_unnamed") {
		t.Fatalf("инъекция ничего не изменила: ветвь не вставлена в тело представления")
	}
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на ветви типа, не названного ни эталоном, ни законным " +
			"различием: тип вышел из-под сверки, и его дрейф был бы невидим")
	}
	if joined := strings.Join(found, "\n"); !strings.Contains(joined, "iam_unnamed") {
		t.Errorf("находка не называет тип:\n%s", joined)
	}
}

// TestG2_InjectionLegalDifferencesStaySilent — (б) ОБЯЗАН МОЛЧАТЬ.
//
// ЗАКОННЫЙ БЛИЗНЕЦ, и без него гейт ловил бы форму, а не существо. Все ПЯТЬ
// законных различий дерева стоят В МИГРАЦИИ КАК ЕСТЬ, и гейт обязан на них
// молчать: у привязки с областью «кластер» containment предка не даёт, а цепь
// даёт; у проектной роли containment добирает аккаунт соединением, а цепь
// поднимается обходом; предок проекта взят из журнала; предок аккаунта — из
// синглтона кластера; предок ЛИЧНОСТИ взят из таблицы членств — оттуда же, откуда
// его берёт план чтения материализации (#944 / #1172), и посвойственная сверка
// колонки ему не годится, потому что колонки у него нет.
//
// Красное здесь означало бы гейт, красный НА ВЕРНОЙ РЕАЛИЗАЦИИ, — и худший его
// исход не краснота, а то, что читатель «приведёт стороны в согласие», правя
// материализацию, то есть поведение авторизации.
func TestG2_InjectionLegalDifferencesStaySilent(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	if found := injectedFindings(t, migration, body); len(found) > 0 {
		t.Fatalf("гейт КРАСЕН на дереве, где все ПЯТЬ различий законны и объявлены:\n%s\n"+
			"Он сверяет цепь с ОДНИМ эталоном вместо посвойственного, и следующий читатель "+
			"начнёт «приводить стороны в согласие», правя материализацию — то есть поведение "+
			"авторизации.", strings.Join(found, "\n"))
	}
}

// TestG2_InjectionHandWrittenFormStaysSilent — (б) ОБЯЗАН МОЛЧАТЬ.
//
// ФОРМА, А НЕ СМЫСЛ. Две ветви свода переписаны РУКОПИСНОЙ формой — той самой,
// какой представление объявлялось до сведения цепи, — и смысл при этом не
// изменён ни в одном знаке: тот же тип, та же таблица, та же колонка, тот же
// закрытый набор.
//
// Без этой пробы «распознаватель знает обе формы» было бы объявлением. Знай он
// одну, вторая дала бы ему не красное и не зелёное, а МОЛЧАНИЕ: ветвь группы
// осталась бы без колонки-указателя (находка о верной реализации), а ветвь
// привязки — без набора областей (отказ «не разобрано»). Обе стороны здесь и
// проверяются разом.
func TestG2_InjectionHandWrittenFormStaysSilent(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	handWritten, applied := pointEdit(body, handWrittenForms)
	if applied != len(handWrittenForms) {
		t.Fatalf("переведено в рукописную форму %d ветвей из %d: перевод не состоялся, "+
			"и молчание гейта ничего не сказало бы о второй форме.\nМиграция: %s",
			applied, len(handWrittenForms), migration)
	}
	if found := injectedFindings(t, migration, handWritten); len(found) > 0 {
		t.Fatalf("гейт КРАСЕН на том же представлении, записанном РУКОПИСНОЙ формой:\n%s\n"+
			"Смысл не менялся — значит распознаватель судит написание, а не предмет, и на "+
			"дереве этой формы он объявлял бы расхождение по каждой ветви сразу.",
			strings.Join(found, "\n"))
	}
}

// TestG2_InjectionHandWrittenFormDefectIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Обратная половина предыдущей: молчание на рукописной форме обязано быть
// молчанием ПО СУЩЕСТВУ, а не оттого, что распознаватель её не прочитал. Дефект
// вносится в РУКОПИСНУЮ запись закрытого набора — область «кластер» снята, —
// и он обязан быть найден так же, как в форме свода.
func TestG2_InjectionHandWrittenFormDefectIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	handWritten, applied := pointEdit(body, handWrittenForms)
	if applied != len(handWrittenForms) {
		t.Fatalf("переведено в рукописную форму %d ветвей из %d: инъекции нечего ломать.\n"+
			"Миграция: %s", applied, len(handWrittenForms), migration)
	}
	broken := strings.Replace(handWritten,
		"lower(o.resource_type) IN ('project', 'account', 'cluster')",
		"lower(o.resource_type) IN ('project', 'account')", 1)
	if broken == handWritten {
		t.Fatalf("инъекция ничего не изменила: рукописного набора областей в тексте нет")
	}
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на области, снятой из РУКОПИСНОЙ записи набора: вторая " +
			"форма прочитана, но не судится — то есть не прочитана")
	}
	if joined := strings.Join(found, "\n"); !strings.Contains(joined, "cluster") {
		t.Errorf("находка не называет потерянную область:\n%s", joined)
	}
}

// TestG2_InjectionLinkedParentTableDivergedInTheChainIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// СТОРОНА ЦЕПИ. Звено личности уводится обратно на колонку строки — то есть в то
// состояние, из которого его вывели #944 и #1172. Наблюдаемо это разъезд двух
// записей об одном предмете: материализация накрывает человека по членствам, а
// каскад достаёт до него через аккаунт, названный колонкой, — и второй аккаунт
// человека перестаёт быть для каскада его аккаунтом.
func TestG2_InjectionLinkedParentTableDivergedInTheChainIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	broken, applied := pointEdit(body, identityBranchToColumnForms)
	if applied != 1 {
		t.Fatalf("правок применено %d вместо одной: ветвь личности в миграции не найдена "+
			"НИ В ОДНОЙ из известных форм записи, и «гейт покраснел» ничего не "+
			"доказывало бы.\nМиграция: %s", applied, migration)
	}
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на звене личности, уведённом с таблицы связи на колонку " +
			"строки: обе записи о предке разошлись, а сторож этого не заметил")
	}
	joined := strings.Join(found, "\n")
	for _, want := range []string{"iam_user", "kacho_iam.users", "kacho_iam.memberships"} {
		if !strings.Contains(joined, want) {
			t.Errorf("находка не называет %q:\n%s", want, joined)
		}
	}
}

// TestG2_InjectionLinkedParentTableDivergedInThePlanIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// СТОРОНА МАТЕРИАЛИЗАЦИИ, и без неё утверждение «стороны согласны» проверялось бы
// ровно наполовину: инъекция по тексту миграции ничего не говорит о том, заметит
// ли гейт дрейф ПЛАНА ЧТЕНИЯ. Здесь план возвращают на колонку строки — ровно тот
// дефект, который чинит #1172, — при нетронутой цепи.
func TestG2_InjectionLinkedParentTableDivergedInThePlanIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	plan := currentContainments()
	c, ok := plan["iam_user"]
	if !ok {
		t.Fatal("в плане чтения нет записи о личности: инъекция беспредметна, и её " +
			"«покраснел» ничего не доказывало бы")
	}
	c.ParentAccountsExpr = "ARRAY_REMOVE(ARRAY[COALESCE(o.account_id, '')], '')"
	plan["iam_user"] = c
	_, found := auditScopeEdgeSourcesWith(migration, body, plan)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на плане чтения, вернувшемся к колонке строки, при " +
			"цепи, читающей таблицу связи: дрейф со стороны материализации невидим")
	}
	joined := strings.Join(found, "\n")
	for _, want := range []string{"iam_user", "kacho_iam.memberships"} {
		if !strings.Contains(joined, want) {
			t.Errorf("находка не называет %q:\n%s", want, joined)
		}
	}
}

// TestG2_InjectionLinkedParentWithNoChainBranchIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Третий способ разъехаться: у типа, чей предок берётся связью, ветви в цепи не
// стало вовсе. Материализация накрывает объект, а каскад до него не достаёт —
// отказ, неотличимый от честного, поэтому молчание здесь недопустимо.
func TestG2_InjectionLinkedParentWithNoChainBranchIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	up, err := upBlock(body)
	if err != nil {
		t.Fatalf("блок Up не разобран: %v", err)
	}
	var kept []string
	dropped := false
	for _, arm := range strings.Split(up, "UNION ALL") {
		if strings.Contains(arm, "'iam_user'::text") {
			dropped = true
			continue
		}
		kept = append(kept, arm)
	}
	if !dropped {
		t.Fatalf("инъекция ничего не изменила: ветви личности в блоке Up нет.\nМиграция: %s",
			migration)
	}
	broken := "-- +goose Up\n" + strings.Join(kept, "UNION ALL") + "\n-- +goose Down\n"
	found := injectedFindings(t, migration, broken)
	if len(found) == 0 {
		t.Fatalf("гейт ПРОМОЛЧАЛ на типе, чей предок берётся связью, но ветви в цепи нет: " +
			"каскад до объекта не достаёт, а сторож этого не заметил")
	}
	if joined := strings.Join(found, "\n"); !strings.Contains(joined, "iam_user") {
		t.Errorf("находка не называет тип:\n%s", joined)
	}
}

// TestG2_InjectionEmptyUpBlockRefusesInsteadOfPassing — ПРЕДПОСЫЛКА.
//
// Пустой блок Up обязан дать ОТКАЗ, а не успех: «ноль находок» здесь означало бы
// «ноль прочитанного», а гейт, молчащий на нечитаемом источнике, сторожит
// только тех, у кого источник читается.
func TestG2_InjectionEmptyUpBlockRefusesInsteadOfPassing(t *testing.T) {
	empty := "-- +goose Up\n\n-- +goose Down\n"
	if found := injectedFindings(t, "инъекция: пустой блок Up", empty); len(found) == 0 {
		t.Fatalf("гейт ПРОШЁЛ на пустом блоке Up: «источники согласны» стало неотличимо " +
			"от «ничего не прочитано»")
	}
}

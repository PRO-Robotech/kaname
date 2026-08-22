// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/internal/gitenv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
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
	Table      string // из какой таблицы читается
	ParentType string // тип предка: литерал либо выражение над колонкой
	ParentCol  string // колонка-указатель (без псевдонима)
	ScopeSet   string // закрытый набор областей из отбора ветви, если он там есть
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
	{"iam_user", "звено ЛИЧНОСТИ берётся из kacho_iam.memberships (#944), а containment " +
		"материализации — из колонки kacho_iam.users.account_id. Различие НАМЕРЕННОЕ и есть " +
		"предмет отрыва (#471): принадлежность человека аккаунту перестала быть свойством его " +
		"строки, а parentAccountExpr — выражение СКАЛЯРНОЕ, одна строка → один предок, и N " +
		"членств оно не выражает by construction. Пока членство у каждого одно, оба источника " +
		"дают одну и ту же пару — это держат обратное заполнение и зеркалящий триггер 470001. " +
		"Эталон здесь — ЦЕПЬ: она умеет назвать столько предков, сколько у человека членств; " +
		"привести к согласию правкой материализации нельзя, не сменив объект, про который " +
		"спрашивает гейт (приёмка IAM-ID-1 §2.3а)"},
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

var (
	reObjectType = regexp.MustCompile(`SELECT\s+'([a-z_]+)'::text`)
	reFrom       = regexp.MustCompile(`FROM\s+(kacho_iam\.[a-z_]+)\s+o\b`)
	reSelectList = regexp.MustCompile(`SELECT\s+'[a-z_]+'::text,\s*o\.id,\s*([^,]+),\s*([^,]+),\s*1`)
	// reScopeSet — ЗАКРЫТЫЙ НАБОР областей берётся из отбора ветви, а не из
	// списка выборки: в списке стоит `lower(o.resource_type)` — ВЫРАЖЕНИЕ,
	// а не перечень. Гейт, прочитавший выражение вместо набора, объявил бы
	// расхождение по каждой законной области сразу — то есть покраснел бы на
	// верной реализации, ровно тем способом, который сам и ловит.
	reScopeSet = regexp.MustCompile(`lower\(o\.resource_type\)\s+IN\s*\(([^)]*)\)`)
)

// parseBranches разбирает ветви представления из исполняемого SQL.
//
// Разбираются только ветви формы «SELECT '<тип>'::text, o.id, <предок>, <колонка>, 1
// FROM <таблица> o» — то есть выводимые из СОБСТВЕННОЙ СТРОКИ объекта. Ветви
// журнала и синглтона кластера этой формы не имеют и попадают в
// legalDifferences по имени типа.
func parseBranches(sqlText string) []scopeEdgeBranch {
	var out []scopeEdgeBranch
	for _, arm := range strings.Split(sqlText, "UNION ALL") {
		ot := reObjectType.FindStringSubmatch(arm)
		if ot == nil {
			continue
		}
		// Таблица НЕОБЯЗАТЕЛЬНА: ветви проекта и аккаунта читают проекцию
		// журнала и синглтон кластера, а не собственную строку объекта, и
		// пропустить их значило бы вывести два типа из-под сверки МОЛЧА —
		// они не попали бы ни в сверенные, ни в пропущенные, и счётчик
		// объёма осмотренного соврал бы в обе стороны сразу.
		br := scopeEdgeBranch{ObjectType: ot[1]}
		if from := reFrom.FindStringSubmatch(arm); from != nil {
			br.Table = from[1]
		}
		if set := reScopeSet.FindStringSubmatch(arm); set != nil {
			br.ScopeSet = set[1]
		}
		if sl := reSelectList.FindStringSubmatch(arm); sl != nil {
			br.ParentType = strings.TrimSpace(sl[1])
			br.ParentCol = strings.TrimSpace(sl[2])
		}
		out = append(out, br)
	}
	return out
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

func auditScopeEdgeSources(migration, body string) (report, findings []string) {
	up, err := upBlock(body)
	if err != nil {
		return nil, []string{err.Error()}
	}
	branches := parseBranches(up)
	if len(branches) == 0 {
		return report, append(findings, fmt.Sprintf(
			"в блоке Up не разобрано НИ ОДНОЙ ветви, выводимой из строки объекта: "+
				"предпосылка гейта не выполнена, и его молчание означало бы «ничего не "+
				"прочитано», а не «источники согласны».\nМиграция: %s", migration))
	}

	// ── источник 1: containment материализации ──────────────────────────────
	containment := map[string]pg.IAMDirectContainment{}
	for _, c := range pg.IAMDirectContainments() {
		containment[authzmap.ModelTypeName(c.ObjectType)] = c
	}
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
		"сверено типов: %d, законных различий пропущено: %d", compared, skipped))

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

// TestG2_InjectionPointerColumnDivergedIsFound — (а) ОБЯЗАН ПОКРАСНЕТЬ.
//
// Колонка-указатель изменена в ОДНОЙ записи (в представлении) и не изменена в
// другой (в плане чтения материализации) — ровно тот дрейф, ради которого гейт
// существует: удержать две записи «одним источником» невозможно, значит
// расхождение обязано краснеть, а не обнаруживаться прогоном на стенде.
// ЦЕЛЬ ИНЪЕКЦИИ — ГРУППА, а не личность, и это не безразличный выбор. У личности
// звено с #944 берётся из таблицы членств и объявлено ЗАКОННЫМ РАЗЛИЧИЕМ, то есть
// гейт на ней молчит НАМЕРЕННО: инъекция по ней доказывала бы обратное тому, что
// должна. Ветвь группы осталась в exactSourceTypes и имеет ту же форму — значит
// инъекция по-прежнему меряет способность гейта найти ДРЕЙФ, а не конкретный тип.
func TestG2_InjectionPointerColumnDivergedIsFound(t *testing.T) {
	migration, body := readScopeEdgeMigration(t)
	// Точечная правка НАСТОЯЩЕГО текста: у группы указатель уводится с
	// account_id на собственный идентификатор.
	broken := strings.Replace(body,
		"SELECT 'iam_group'::text, o.id, 'account'::text, o.account_id, 1",
		"SELECT 'iam_group'::text, o.id, 'account'::text, o.id, 1", 1)
	if broken == body {
		t.Fatalf("инъекция ничего не изменила: ветвь группы в миграции не найдена "+
			"в ожидаемой форме, и «гейт покраснел» ничего не доказывало бы.\n"+
			"Миграция: %s", migration)
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
	broken := strings.Replace(body,
		"lower(o.resource_type) IN ('project', 'account', 'cluster')",
		"lower(o.resource_type) IN ('project', 'account')", 1)
	if broken == body {
		t.Fatalf("инъекция ничего не изменила: закрытый набор областей в миграции не "+
			"найден в ожидаемой форме.\nМиграция: %s", migration)
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
	// пользователя, только тип другой.
	extra := `
UNION ALL
  SELECT 'iam_unnamed'::text, o.id, 'account'::text, o.account_id, 1
    FROM kacho_iam.users o
   WHERE COALESCE(o.account_id, '') <> ''`
	broken := strings.Replace(body, "\n\nCOMMENT ON VIEW", extra+";\n\nCOMMENT ON VIEW", 1)
	if broken == body {
		t.Fatalf("инъекция ничего не изменила: якорь вставки в миграции не найден")
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
// синглтона кластера; предок ЛИЧНОСТИ взят из таблицы членств, тогда как
// containment остался на колонке строки (#944 — предмет отрыва, а не дрейф).
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

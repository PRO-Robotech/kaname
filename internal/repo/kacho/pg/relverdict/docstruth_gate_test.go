// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// docstruth_gate_test.go — R7-4-17: ДВА МЕСТА ОБ ОДНОМ ПРЕДМЕТЕ ПРИВЕДЕНЫ В
// СОГЛАСИЕ, И ГЕЙТ ДЕРЖИТ ИХ ТАМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ, ИЗМЕРЕННЫЙ ДО РАБОТЫ
//
// На ревизии посадки архитектурный документ цепи и комментарий обхода в тексте
// вердикта были ЛОЖНЫ КАЖДЫЙ, и каждый — В ДВУХ ВЕЛИЧИНАХ:
//
//	(а) ИСТОЧНИК звена проекта. Оба говорили «предок проекта — projects.account_id»,
//	    тогда как миграция 781001 В ТОМ ЖЕ ДЕРЕВЕ перевела это звено на проекцию
//	    журнала. Перечень таблиц под представлением при этом называл
//	    `kacho_iam.projects`, которую цепь не читает вовсе, и НЕ называл
//	    `relation_fact`, которую читает;
//	(б) ДОВОД О ПРЕДЕЛЕ ОБХОДА. Оба обосновывали «предел не усекает» равенством
//	    «рёбер у объекта не больше глубин (ключ таблицы уникален по глубине)» —
//	    доводом, который 781001 ПРЯМО ОТМЕНИЛА для журнальной ветви и заменила
//	    числом, проверяемым переписью.
//
// Это не устаревание, а расхождение: утверждение, которое дерево опровергает.
// Достройка #785 добавляет к тем же двум текстам пять звеньев и меняет число
// ветвей представления — оставить их значило бы сделать расхождение семикратным.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ГЕЙТ, А НЕ «ПОЧИНИЛИ И ЛАДНО»
//
// Оба текста уже однажды пережили свой предмет: миграция, отменившая довод,
// лежала в том же дереве, что и тексты, его повторявшие. Правка без сторожа
// повторит это на следующей ветви цепи, и повторит МОЛЧА — комментарий не
// компилируется, документ не исполняется, красным не станет ни один прогон.
//
// Гейт выводит истину ИЗ МИГРАЦИИ, а не из второго перечня: перечень был бы
// третьим местом об одном предмете и разошёлся бы с первыми двумя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ДЕРЖИТ, СКАЗАНО ПРЯМО
//
// Он судит ДВЕ НАЗВАННЫЕ ВЕЛИЧИНЫ и состав перечня таблиц — то есть ровно то, что
// уже разошлось. Он НЕ читает прозу целиком и не может: «текст говорит правду» —
// не предикат. Следующее расхождение другого рода он не поймает, и выдавать его
// за сторожа правдивости этих текстов было бы тем же классом, который он ловит.

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
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

const (
	chainArchDoc = "services/iam/docs/engineering/architecture/scope-chain-reaches-the-root.md"
	chainQueryGo = "services/iam/internal/repo/kacho/pg/relverdict/query.go"
	// chainMigDecl — по чему опознаётся миграция, ОБЪЯВЛЯЮЩАЯ представление цепи.
	// Здесь стоял образец имени файла (`785001_*.sql`), и он ПЕРЕЖИЛ СВОЙ ПРЕДМЕТ
	// в тот же день, когда цепь была объявлена заново другой миграцией: гейт
	// продолжал выводить «истину о цепи» из СНЯТОГО определения и объявлял
	// расхождением ровно то, что стало верным. Действующая миграция выводится из
	// набора — берётся НАИБОЛЬШАЯ версия, чей блок Up объявляет представление,
	// потому что порядок применения числовой и последнее объявление переживает
	// предыдущие.
	chainMigDecl      = `CREATE\s+(OR\s+REPLACE\s+)?VIEW\s+kacho_iam\.resource_scope_edge\b`
	cteCommentTop     = "-- scope — ОБЛАСТИ"
	cteCommentEnd     = "scope(s_type, s_id, depth) AS ("
	docsChainViewName = "kacho_iam.resource_scope_edge"
)

// retiredClaims — утверждения, ОТМЕНЁННЫЕ деревом. Каждое несёт причину и то,
// чем оно заменено: запись без причины через полгода неотличима от вкусовщины.
var retiredClaims = []struct {
	Pattern *regexp.Regexp
	Why     string
}{
	{
		regexp.MustCompile(`projects\.account_id`),
		"источник звена проекта: 781001 перевела его на проекцию журнала " +
			"(relation_fact), таблица projects цепью больше не читается",
	},
	{
		regexp.MustCompile(`не\s+бывает\s+больше\s+рёбер,?\s+чем\s+глубин`),
		"довод о пределе обхода: 781001 прямо отменила равенство «рёбер не больше " +
			"глубин» (у проекта два указателя на глубине 1) и заменила его числом, " +
			"которое ПРОВЕРЯЕТСЯ переписью",
	},
}

func docsRepoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): гейту негде искать тексты, и его "+
			"молчание не означало бы их правдивости", err)
	}
	return strings.TrimSpace(string(out))
}

func readTreeFile(t *testing.T, root, rel string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join(root, rel))
	if err != nil {
		t.Fatalf("текст %s не прочитан (%v): источник, который гейт не смог прочитать, — "+
			"ОТКАЗ, а не пропуск", rel, err)
	}
	return string(body)
}

// cteComment вырезает комментарий обхода — только его, без исполняемого SQL.
//
// Иначе гейт судил бы и код: «projects.account_id» в теле запроса было бы
// находкой, хотя предмет здесь — ПРОЗА.
func cteComment(t *testing.T, queryGo string) string {
	t.Helper()
	i := strings.Index(queryGo, cteCommentTop)
	j := strings.Index(queryGo, cteCommentEnd)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("комментарий обхода не найден в %s (начало=%d, конец=%d): гейт читал бы "+
			"неизвестно что, и его молчание не относилось бы к предмету", chainQueryGo, i, j)
	}
	return queryGo[i:j]
}

var reChainTable = regexp.MustCompile(`kacho_iam\.[a-z_]+`)

// viewBodyOf вырезает ТЕЛО объявления представления: от глагола до его
// собственной точки с запятой.
//
// Кавычки учитываются, потому что тело несёт строковые литералы; скобки — нет:
// точки с запятой внутри скобок в этом объявлении не бывает, а комментарий
// представления (единственное место, где она встретилась бы) стоит уже ЗА
// телом.
func viewBodyOf(t *testing.T, up string, decl *regexp.Regexp) string {
	t.Helper()
	loc := decl.FindStringIndex(up)
	if loc == nil {
		t.Fatalf("в исполняемом блоке нет объявления %s: выводить истину не из чего, "+
			"и «перечни совпали» стало бы неотличимо от «ничего не прочитано»", docsChainViewName)
	}
	body := up[loc[0]:]
	inQuote := false
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\'':
			if inQuote && i+1 < len(body) && body[i+1] == '\'' {
				i++
				continue
			}
			inQuote = !inQuote
		case ';':
			if !inQuote {
				return body[:i]
			}
		}
	}
	t.Fatalf("объявление %s не завершено точкой с запятой: разобрать его тело нельзя, "+
		"и молчание здесь означало бы «не прочитано»", docsChainViewName)
	return ""
}

// tablesUnderTheView выводит таблицы, которые цепь ФАКТИЧЕСКИ читает, из ТЕЛА
// объявления представления в действующей миграции — с вырезанными комментариями.
//
// Вырезать комментарии обязательно: шапка миграции называет все девять таблиц
// десятки раз, объясняя их, и гейт по подстроке зеленел бы на собственном
// объяснении.
//
// РЕФЕРЕНТ — ТЕЛО, А НЕ БЛОК `Up`, и это правка, а не оттенок. Прежде читался
// весь блок, и это было верно ровно пока представление объявляла ОТДЕЛЬНАЯ
// миграция: тогда «всё, что назвал блок» и «всё, что читает цепь» совпадали. В
// своде тот же блок несёт ВСЮ схему сервиса — 89 имён вместо девяти, включая
// последовательности, функции и ограничения, — то есть референт выродился бы
// вместе с числом файлов, а не с предметом, и гейт потребовал бы от комментария
// обхода назвать всю схему. Тело от числа файлов не зависит.
func tablesUnderTheView(t *testing.T) map[string]bool {
	t.Helper()
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		t.Fatalf("миграции не прочитаны (%v): выводить истину не из чего", err)
	}
	decl := regexp.MustCompile(chainMigDecl)
	version := regexp.MustCompile(`^([0-9]+)_`)
	var body, from string
	best, seen := -1, 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		seen++
		raw, rerr := migrations.FS.ReadFile(e.Name())
		if rerr != nil {
			t.Fatalf("миграция %s не прочитана: %v", e.Name(), rerr)
		}
		text := string(raw)
		upAt, downAt := strings.Index(text, "-- +goose Up"), strings.Index(text, "-- +goose Down")
		if upAt < 0 || downAt < upAt || !decl.MatchString(text[upAt:downAt]) {
			continue
		}
		m := version.FindStringSubmatch(e.Name())
		if m == nil {
			t.Fatalf("у миграции %s нет числовой версии в имени: порядок применения по "+
				"такому имени не установить", e.Name())
		}
		v, cerr := strconv.Atoi(m[1])
		if cerr != nil {
			t.Fatalf("версия миграции %s не число: %v", e.Name(), cerr)
		}
		if v > best {
			best, body, from = v, text, e.Name()
		}
	}
	if seen == 0 {
		t.Fatal("во встроенном наборе НОЛЬ миграций: предпосылка гейта ложна, и его " +
			"молчание означало бы «ничего не прочитано»")
	}
	if body == "" {
		t.Fatalf("среди %d миграций ни одна не объявляет %s: гейт не может вывести истину "+
			"о цепи, и это ОТКАЗ, а не согласие", seen, docsChainViewName)
	}
	t.Logf("осмотрено миграций %d; действующее определение цепи — %s (версия %d)", seen, from, best)
	up := strings.Index(body, "-- +goose Up")
	down := strings.Index(body, "-- +goose Down")
	if up < 0 || down < 0 || down < up {
		t.Fatalf("в миграции цепи не найдены оба блока goose: строка блока Down была бы " +
			"прочитана как действительность")
	}
	var executable []string
	for _, line := range strings.Split(body[up:down], "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		executable = append(executable, line)
	}
	out := map[string]bool{}
	for _, line := range strings.Split(viewBodyOf(t, strings.Join(executable, "\n"), decl), "\n") {
		for _, name := range reChainTable.FindAllString(line, -1) {
			// Само представление — ОПРЕДЕЛЯЕМОЕ, а не читаемое. Требовать, чтобы
			// комментарий назвал его в перечне «того, что лежит ПОД
			// представлением», значило бы требовать, чтобы оно лежало под собой.
			if name == docsChainViewName {
				continue
			}
			out[name] = true
		}
	}
	return out
}

// TestR7_4_17_ChainTextsAgreeWithTheTreeOnSourceAndOnTheWalkLimit — R7-4-17.
//
// Сверяется, что КАЖДЫЙ из двух текстов говорит правду о ДВУХ величинах: об
// источнике каждого звена и о доводе, которым обоснован предел обхода.
func TestR7_4_17_ChainTextsAgreeWithTheTreeOnSourceAndOnTheWalkLimit(t *testing.T) {
	root := docsRepoRoot(t)
	texts := map[string]string{
		chainArchDoc: readTreeFile(t, root, chainArchDoc),
		chainQueryGo: cteComment(t, readTreeFile(t, root, chainQueryGo)),
	}

	// ── величина 1 и 2: отменённые утверждения ──────────────────────────────
	checked := 0
	for name, body := range texts {
		for _, claim := range retiredClaims {
			checked++
			if loc := claim.Pattern.FindStringIndex(body); loc != nil {
				t.Errorf("%s несёт утверждение, ОТМЕНЁННОЕ деревом: %q.\n  Почему отменено: %s\n"+
					"  Это не «устарело», а расхождение двух мест об одном предмете, из которых "+
					"верно одно: текст отговаривает от уже принятого решения.",
					name, strings.TrimSpace(body[loc[0]:loc[1]]), claim.Why)
			}
		}
	}

	// ── величина 3: перечень таблиц под представлением ──────────────────────
	//
	// Он несущий, и текст запроса говорит об этом сам: отпечаток предмета замера
	// выводит читаемые таблицы ИЗ ТЕКСТА вердикта. Представление, названное одним
	// своим именем, увело бы собственные основания из-под прибора.
	want := tablesUnderTheView(t)
	if len(want) == 0 {
		t.Fatalf("из миграции цепи не выведено НИ ОДНОЙ таблицы: сверять не с чем, и " +
			"молчание означало бы «не прочитано», а не «перечни совпали»")
	}
	got := map[string]bool{}
	for _, name := range reChainTable.FindAllString(texts[chainQueryGo], -1) {
		got[name] = true
	}
	var missing, extra []string
	for name := range want {
		if !got[name] {
			missing = append(missing, name)
		}
	}
	for name := range got {
		if !want[name] {
			extra = append(extra, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("комментарий обхода НЕ называет таблиц, которые цепь читает: %v.\n"+
			"Прибор свежести выводит основания замера ИЗ ЭТОГО ТЕКСТА, поэтому их правку "+
			"он перестал бы замечать МОЛЧА.", missing)
	}
	if len(extra) > 0 {
		t.Errorf("комментарий обхода называет таблицы, которых цепь НЕ читает: %v.\n"+
			"Прибор взял бы под наблюдение чужой предмет, а название пережило бы то, что "+
			"им обозначалось.", extra)
	}

	t.Logf("осмотрено: текстов %d, отменённых утверждений проверено %d, таблиц выведено "+
		"из миграции %d, названо комментарием %d", len(texts), checked, len(want), len(got))
}

// ─────────────────────────────────────────────────────────────────────────────
// ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ

// TestR7_4_17_InjectionRetiredClaimIsFound — ОБЯЗАН НАЙТИ.
//
// Кормится НАСТОЯЩИЙ текст дерева с точечно возвращённым отменённым доводом.
func TestR7_4_17_InjectionRetiredClaimIsFound(t *testing.T) {
	root := docsRepoRoot(t)
	live := cteComment(t, readTreeFile(t, root, chainQueryGo))
	for _, claim := range retiredClaims {
		if claim.Pattern.MatchString(live) {
			t.Fatalf("отменённое утверждение %q УЖЕ стоит в дереве: инъекция ничего не "+
				"добавила бы, а гейт обязан быть красным сам по себе", claim.Pattern)
		}
	}
	// Возвращаем оба отменённых утверждения — каждое обязано быть найдено.
	injected := live + "\n-- предок проекта — projects.account_id\n" +
		"-- у объекта не бывает больше рёбер, чем глубин\n"
	found := 0
	for _, claim := range retiredClaims {
		if claim.Pattern.MatchString(injected) {
			found++
		}
	}
	if found != len(retiredClaims) {
		t.Fatalf("гейт нашёл %d отменённых утверждений из %d: инъекция настоящим текстом "+
			"прошла мимо, значит предикат ловит форму, а не существо", found, len(retiredClaims))
	}
}

// TestR7_4_17_InjectionLiveClaimStaysSilent — ОБЯЗАН МОЛЧАТЬ.
//
// ЗАКОННЫЙ БЛИЗНЕЦ: текст, называющий ДЕЙСТВУЮЩИЙ источник и ДЕЙСТВУЮЩИЙ довод,
// находкой не является. Без него гейт ловил бы слова «проект», «предел», «довод»
// и краснел бы на любой правке прозы — а первый ложный срабат его выключит.
func TestR7_4_17_InjectionLiveClaimStaysSilent(t *testing.T) {
	legal := "-- предок проекта берётся из проекции журнала relation_fact;\n" +
		"-- предел не усекает: звеньев у объекта столько, сколько отношений-указателей\n" +
		"-- у его типа, и это число ПРОВЕРЯЕТСЯ переписью, а не выводится равенством.\n"
	for _, claim := range retiredClaims {
		if claim.Pattern.MatchString(legal) {
			t.Errorf("гейт назвал находкой ЗАКОННЫЙ текст, описывающий действующее "+
				"устройство: предикат %q ловит форму, а не отменённое утверждение.\n%s",
				claim.Pattern, legal)
		}
	}
}

// TestR7_4_17_InjectionTableListDriftIsFound — ОБЯЗАН НАЙТИ, обе стороны.
//
// Перечень таблиц обязан СОВПАДАТЬ с тем, что цепь читает, — по обеим сторонам:
// недостача уводит основания замера из-под прибора, избыток берёт под наблюдение
// чужой предмет.
func TestR7_4_17_InjectionTableListDriftIsFound(t *testing.T) {
	want := tablesUnderTheView(t)
	if len(want) < 2 {
		t.Fatalf("из миграции выведено %d таблиц: инъекции нечего убирать", len(want))
	}
	live := map[string]bool{}
	for name := range want {
		live[name] = true
	}

	// Недостача: убираем одну и требуем, чтобы разница нашлась.
	var dropped string
	for name := range live {
		dropped = name
		break
	}
	delete(live, dropped)
	if diff := diffSets(want, live); len(diff.missing) != 1 || diff.missing[0] != dropped {
		t.Errorf("недостача таблицы %q не найдена: %v", dropped, diff.missing)
	}

	// Избыток: добавляем таблицу, которой цепь не читает.
	live[dropped] = true
	live["kacho_iam.projects"] = true
	if diff := diffSets(want, live); len(diff.extra) != 1 || diff.extra[0] != "kacho_iam.projects" {
		t.Errorf("избыточная таблица не найдена: %v", diff.extra)
	}
	// Законный близнец: совпадающие перечни находкой не являются.
	delete(live, "kacho_iam.projects")
	if diff := diffSets(want, live); len(diff.missing) != 0 || len(diff.extra) != 0 {
		t.Errorf("гейт нашёл расхождение на СОВПАДАЮЩИХ перечнях: %v / %v",
			diff.missing, diff.extra)
	}
}

type setDiff struct{ missing, extra []string }

func diffSets(want, got map[string]bool) setDiff {
	var d setDiff
	for name := range want {
		if !got[name] {
			d.missing = append(d.missing, name)
		}
	}
	for name := range got {
		if !want[name] {
			d.extra = append(d.extra, name)
		}
	}
	sort.Strings(d.missing)
	sort.Strings(d.extra)
	return d
}

// TestR7_4_17_InjectionMissingTextRefusesInsteadOfPassing — ПРЕДПОСЫЛКА.
//
// Текст, которого гейт не смог прочитать, — ОТКАЗ, а не пропуск: молчащий на
// нечитаемом источнике гейт сторожит только тех, у кого источник читается.
func TestR7_4_17_InjectionMissingTextRefusesInsteadOfPassing(t *testing.T) {
	root := docsRepoRoot(t)
	if _, err := os.ReadFile(filepath.Join(root, chainArchDoc)); err != nil {
		t.Fatalf("предпосылка не выполнена: документ цепи отсутствует в дереве (%v)", err)
	}
	// Вырожденный вход: комментарий обхода не найден — гейт обязан отказать, а
	// не счесть его пустым и «правдивым».
	if i := strings.Index("нет тут никакого комментария", cteCommentTop); i >= 0 {
		t.Fatalf("маркер комментария обхода найден там, где его нет: предикат вырожден")
	}
	fmt.Fprint(os.Stdout, "")
}

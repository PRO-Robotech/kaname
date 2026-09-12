// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_depth_agreement_test.go — ТРИ ВЕЛИЧИНЫ ГЛУБИНЫ ЦЕПИ ОБЯЗАНЫ СОВПАДАТЬ
// (порт с монорепо `internal/repohygiene/scopedepthagreement_test.go`,
// держатель `TestScopeDepthBoundsAgreeAcrossAllThreePlaces`, снят вынесением
// службы доступа — `kacho#2597`).
//
// Способность гейта упасть доказана инъекцией —
// scope_depth_agreement_injection_test.go.
//
// # Предмет
//
// Предел обхода цепи областей несёт ДВОЙНУЮ нагрузку: тем же числом ограничена
// и рекурсия (сколько уровней вверх пройти), и выборка внутри соединения вбок
// (сколько рёбер взять у одного объекта). Довод «предел не усекает» верен
// ровно пока это число не меньше того, что допускает схема: у объекта не
// бывает больше рёбер, чем глубин, а глубина ограничена проверкой
// `depth BETWEEN 1 AND N`.
//
// Совпадение сегодня есть, и оно НИЧЕМ НЕ ДЕРЖИТСЯ. Понизить константу обхода —
// и предел начнёт молча отбрасывать рёбра; поднять границу схемы новой
// миграцией — то же самое с другой стороны. Отбрасывать он будет по
// `ORDER BY pe.depth`, то есть ДАЛЬНИХ предков первыми: аккаунт и кластер.
// Область схлопывается вверх, ответ остаётся «нет», и отказ неотличим от
// честного.
//
// # Что изменилось при переносе, а что осталось дословно
//
// Изменилось: пакет (`repohygiene` → `check`), путь-константы (без префикса
// `services/iam/` — код лежит от корня модуля kaname), корень обхода
// (`platformtree.RequireCorpus` вместо ручного `repoRoot(t)` — предмет лежит
// целиком внутри службы, дерева платформы модулю не нужно, и все три
// координаты теперь резолвятся приставкой модуля, которая пуста в
// самостоятельном клоне). Осталось дословно: обе регулярки, форма суждения
// (`adjudicateScopeDepth`, отделённая от добычи величин), имя держателя
// `TestScopeDepthBoundsAgreeAcrossAllThreePlaces` и все три координаты по
// смыслу (query.go, 0001_initial.sql, compile.go — только без префикса
// `services/iam/`).
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// scopeDepthConstRel — где живёт предел обхода в коде, ОТ КОРНЯ МОДУЛЯ.
const scopeDepthConstRel = "internal/repo/kaname/pg/relverdict/query.go"

// scopeDepthMigrationRel — файл, в котором граница глубины ОБЪЯВЛЕНА СЕГОДНЯ.
//
// Координата остаётся ОДНИМ файлом намеренно. Поиск по каталогу миграций был
// бы устойчивее к переезду, но неверен по существу: в цепи из многих файлов
// границу может поднять более поздняя миграция, и тогда объявлений станет
// два, причём законно — побеждает последнее. Правило «величина объявлена
// ровно один раз» верно ВНУТРИ файла и неверно поперёк цепи, поэтому предикат
// смотрит в файл.
const scopeDepthMigrationRel = "internal/migrations/0001_initial.sql"

// scopeDepthPlanFileRel — третья величина названа координатой затем, чтобы
// находка о ней называла МЕСТО, а не только число. Обходу этот путь не нужен
// (findScopeDepthPlan ищет по всему дереву модуля) — здесь путь служит только
// тексту находки, и его устаревание гейт заметит сам:
// TestScopeDepthPlanFileCoordinateIsAlive ниже.
const scopeDepthPlanFileRel = "internal/authzplan/compile.go"

var (
	reMaxAncestorDepth = regexp.MustCompile(`MaxAncestorDepth\s*=\s*(\d+)`)

	// reDepthCheck знает ОБЕ законные формы записи одной и той же границы, и
	// это не запас на будущее, а измеренный факт дерева.
	//
	// Миграция пишет предикат человеком: `depth BETWEEN 1 AND 4`. Свод цепи
	// получается из `pg_dump`, а он печатает разложенную форму:
	// `((depth >= 1) AND (depth <= 4))`. Обе законны; предикат, знающий только
	// первую, на сведённой схеме молчит — не краснеет и не зеленеет
	// (`testing.md` §«Гейт на класс», п. 7).
	reDepthCheck = regexp.MustCompile(`\bdepth BETWEEN 1 AND (\d+)|\bdepth\s*<=\s*(\d+)`)

	rePlanDepth = regexp.MustCompile(`MaxPointerDepth\s*=\s*(\d+)`)
)

func TestScopeDepthBoundsAgreeAcrossAllThreePlaces(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)

	constPath := platformtree.Under(prefix, scopeDepthConstRel)
	migrationPath := platformtree.Under(prefix, scopeDepthMigrationRel)
	planPath := platformtree.Under(prefix, scopeDepthPlanFileRel)

	code := readFileForDepth(t, filepath.Join(root, filepath.FromSlash(constPath)))
	schema := readFileForDepth(t, filepath.Join(root, filepath.FromSlash(migrationPath)))

	goDepth := singleNumber(t, reMaxAncestorDepth, code, "предел обхода в коде (MaxAncestorDepth)")
	sqlDepth := singleNumber(t, reDepthCheck, schema, "граница глубины в проверке схемы")

	planDepth, planFound := findScopeDepthPlan(t, root, prefix)

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: предел обхода %d (%s) · граница схемы %d (%s) · "+
		"предел компилятора модели %s",
		goDepth, constPath, sqlDepth, migrationPath,
		scopeDepthPlanText(planDepth, planFound, planPath))

	for _, finding := range adjudicateScopeDepth(scopeDepthTriple{
		goDepth: goDepth, sqlDepth: sqlDepth,
		planDepth: planDepth, planFound: planFound,
		constPath: constPath, migrationPath: migrationPath, planPath: planPath,
	}) {
		t.Error(finding)
	}
}

// scopeDepthTriple — три величины, которые обязаны совпадать, признак того,
// найдена ли третья, и координаты для текста находки.
type scopeDepthTriple struct {
	goDepth   int
	sqlDepth  int
	planDepth int
	planFound bool

	constPath     string
	migrationPath string
	planPath      string
}

// adjudicateScopeDepth — СУЖДЕНИЕ О ТРЁХ ВЕЛИЧИНАХ, отделённое от их добычи.
//
// Отделено намеренно: пока сверка живёт внутри пробы, доказать её способность
// упасть можно только испортив настоящее дерево — то есть никак. Находка
// называет ОБЕ координаты: расхождение — это всегда пара, и «предел обхода 4»
// без второго числа не говорит, что чинить.
func adjudicateScopeDepth(tr scopeDepthTriple) []string {
	var out []string
	if tr.goDepth != tr.sqlDepth {
		out = append(out, fmt.Sprintf("предел обхода %d (%s) не равен границе схемы %d (%s).\n"+
			"    Тем же числом ограничена выборка внутри соединения вбок, и довод «предел не "+
			"усекает» держится ровно их равенством. При меньшем пределе выборка молча "+
			"отбросит рёбра, причём по ORDER BY pe.depth — ДАЛЬНИХ предков первыми, то есть "+
			"аккаунт и кластер. Область схлопнется вверх, ответ останется «нет», и отказ "+
			"будет неотличим от честного.",
			tr.goDepth, tr.constPath, tr.sqlDepth, tr.migrationPath))
	}
	if tr.planFound && tr.planDepth != tr.goDepth {
		out = append(out, fmt.Sprintf("предел компилятора модели %d (%s) не равен пределу "+
			"обхода %d (%s): модель выводит права на глубину, до которой обход не доходит "+
			"(или наоборот)",
			tr.planDepth, tr.planPath, tr.goDepth, tr.constPath))
	}
	return out
}

func readFileForDepth(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path) // #nosec G304 -- путь взят из состава дерева этого модуля
	if err != nil {
		t.Fatalf("файл %s не читается: %v — гейт не может судить дерево, которого не видит", path, err)
	}
	return string(body)
}

// singleNumber — величина обязана быть НАЙДЕНА и быть ЕДИНСТВЕННОЙ.
//
// Ноль совпадений означает, что объявление переехало и гейт сторожит пустоту;
// два — что величина уже задвоена, и сверять её саму с собой бессмысленно.
func singleNumber(t *testing.T, re *regexp.Regexp, body, what string) int {
	t.Helper()
	ms := re.FindAllStringSubmatch(body, -1)
	if len(ms) == 0 {
		t.Fatalf("%s не найдена: объявление переехало, и «величины совпадают» стало бы "+
			"утверждением ни о чём", what)
	}
	if len(ms) > 1 {
		t.Fatalf("%s объявлена %d раз: она уже задвоена, и расхождение возможно внутри "+
			"одного файла", what, len(ms))
	}
	raw := ""
	for _, g := range ms[0][1:] {
		if g != "" {
			raw = g
			break
		}
	}
	if raw == "" {
		t.Fatalf("%s: совпадение есть, а числа в нём нет — распознаватель нашёл форму, "+
			"из которой не извлекает величину", what)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("%s не число: %q", what, raw)
	}
	return n
}

// findScopeDepthPlan — предел компилятора модели, если он в дереве модуля
// объявлен.
//
// ОБХОД — ВСЁ ДЕРЕВО МОДУЛЯ (от `root`, приведённого приставкой `prefix`), а не
// поддерево одной службы: величина живёт в `internal/authzplan`, и монорепошный
// предок этого гейта однажды искал только в `services/iam/internal` — слепая
// зона, снятая kacho#918.
//
// Состав берётся У ИНДЕКСА РЕПОЗИТОРИЯ, а не обходом диска.
//
// Объявлений с ЧИСЛОМ ожидается ровно одно. Псевдоним под предикат не
// подпадает by construction — он не несёт цифры; два РАЗНЫХ числа — находка.
func findScopeDepthPlan(t *testing.T, root, prefix string) (int, bool) {
	t.Helper()
	dir := root
	if prefix != "" {
		dir = filepath.Join(root, filepath.FromSlash(prefix))
	}
	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		t.Fatalf("состав дерева модуля у индекса репозитория: %v — гейт не может судить о "+
			"дереве, которого не может назвать", err)
	}
	type decl struct {
		path  string
		value int
	}
	var found []decl
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь взят из состава дерева этого модуля
		if rerr != nil {
			continue
		}
		if m := rePlanDepth.FindStringSubmatch(string(body)); m != nil {
			if n, cerr := strconv.Atoi(m[1]); cerr == nil {
				rel, _ := filepath.Rel(dir, abs)
				found = append(found, decl{path: filepath.ToSlash(rel), value: n})
			}
		}
	}
	if len(found) == 0 {
		return 0, false
	}
	for _, d := range found[1:] {
		if d.value != found[0].value {
			t.Errorf("предел компилятора модели объявлен ДВАЖДЫ и по-разному: "+
				"%s = %d, %s = %d.\n"+
				"    Два места об одном пределе расходятся молча, и следующий читатель "+
				"возьмёт то, которое нашёл первым. Оставьте одно объявление, остальные "+
				"сделайте ссылкой на него.",
				found[0].path, found[0].value, d.path, d.value)
		}
	}
	return found[0].value, true
}

func scopeDepthPlanText(n int, ok bool, path string) string {
	if !ok {
		return "не объявлен в дереве (сверять не с чем — названо, а не проглочено)"
	}
	return strconv.Itoa(n) + " (" + path + ")"
}

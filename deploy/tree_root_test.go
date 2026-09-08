// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tree_root_test.go — как пробы этого чарта находят своё дерево.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Один и тот же каталог `deploy/` живёт в ДВУХ деревьях, и глубина у него в них
// разная:
//
//	монорепо   <корень>/services/iam/deploy/     — служба среди соседей
//	арендатор  <корень>/deploy/                  — служба и есть весь продукт
//
// Пробы складывали корень фиксированным числом `..` (`../../..`). Такое сложение
// верно ровно в одном из двух деревьев, а во втором указывает наружу репозитория
// — и не «почти туда», а в каталог, которого не существует. У арендатора это
// давало три отказа вида `open ../../../services/iam/Dockerfile: no such file or
// directory`: пробы поставлены, слот занят, вердикта о посадке нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ВМЕСТО СЧЁТА
//
// Корень ИЩЕТСЯ ПОДЪЁМОМ вверх до маркера, а маркер — `go.mod`. Он есть у обоих
// деревьев и лежит ровно там, где кончается модуль службы: `services/iam/go.mod`
// в монорепо, `go.mod` в корне у арендатора. Число `..` при этом не называется
// вовсе, поэтому смена глубины перестаёт быть предметом правки.
//
// РАЗЛИЧАЮТСЯ ДВА КОРНЯ, и путать их нельзя:
//
//	serviceRootFrom  — БЛИЖАЙШИЙ вверх `go.mod`. Корень МОДУЛЯ СЛУЖБЫ: рядом с
//	                   ним лежат её `Dockerfile`, `deploy/`, `manifest.yaml`.
//	                   Это единственный корень, который есть в ОБОИХ деревьях.
//	outerRootFrom    — САМЫЙ ВНЕШНИЙ `go.mod`. Корень МОНОРЕПО: под ним лежат
//	                   `services/*` и зонтичный чарт стенда. У арендатора он
//	                   СОВПАДАЕТ со служебным, и это не поломка, а факт дерева:
//	                   монорепо над продуктом нет.
//
// Тот же выбор «самого внешнего, а не первого встречного» сделан соседями по
// модулю — `internal/publicauthzcensus` repoRoot и `internal/moduleroleparity`
// repoRoot; расходиться им нельзя, и здесь он повторён по существу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ МАРКЕР — `go.mod`, А НЕ ИМЯ КАТАЛОГА
//
// Имя каталога у арендатора выбирает тот, кто клонировал: `kaname`, `iam`,
// `kaname-0.1.0`, `src`. Проба, опознающая корень по имени, у половины
// клонирующих не находит его вовсе — и не находит МОЛЧА, потому что «каталога с
// таким именем нет» неотличимо от «предмета нет». `go.mod` кладёт сборка, а не
// клонирующий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОДЪЁМ ОТ РАБОЧЕГО КАТАЛОГА
//
// `go test` запускает пробу с рабочим каталогом, равным каталогу её пакета, —
// то есть ровно в `deploy/`. Это то же основание, на котором уже стоят соседние
// пробы этого чарта (`templates/`, `values.prod.yaml` читаются относительными
// путями). `runtime.Caller` дал бы путь ВРЕМЕНИ СБОРКИ и разошёлся бы с деревом
// под `-trimpath`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТОТ ФАЙЛ НЕ ДЕЛАЕТ
//
// Он не решает, ЧТО читать, — только откуда считать пути. Что именно осмотрено
// и почему «ноль осмотренного» есть отказ, а не зелёное, отвечают сами пробы:
// каждая печатает перепись и падает на пустом обходе.
package deploy_test

import (
	"os"
	"path/filepath"
	"testing"
)

// errNoModuleMarker — текст отказа, общий для обоих подъёмов. Вынесен, чтобы
// доказательство ниже узнавало отказ по той же строке, которую увидит человек.
const errNoModuleMarker = "маркер go.mod не найден подъёмом от "

// serviceRootFrom поднимается от start до БЛИЖАЙШЕГО каталога с `go.mod`.
// Пустая строка означает, что маркера нет ни на одном уровне.
func serviceRootFrom(start string) string {
	dir := start
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// outerRootFrom поднимается от start до САМОГО ВНЕШНЕГО каталога с `go.mod`.
// У арендатора возвращает то же, что serviceRootFrom.
func outerRootFrom(start string) string {
	dir, outermost := start, ""
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && !st.IsDir() {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return outermost
		}
		dir = parent
	}
}

// serviceRoot — корень модуля службы для текущей пробы.
func serviceRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не прочитан: %v", err)
	}
	root := serviceRootFrom(wd)
	if root == "" {
		t.Fatalf("%s%s — дерево не открыто, доказывать нечего", errNoModuleMarker, wd)
	}
	return root
}

// outerRoot — корень монорепо, если проба исполняется в нём; иначе тот же
// служебный корень. Вызывающий отличает одно от другого сравнением, а не
// догадкой: `outerRoot(t) == serviceRoot(t)` означает «монорепо над продуктом
// нет».
func outerRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог не прочитан: %v", err)
	}
	root := outerRootFrom(wd)
	if root == "" {
		t.Fatalf("%s%s — дерево не открыто, доказывать нечего", errNoModuleMarker, wd)
	}
	return root
}

// TestTreeRootIsFoundByClimbingWhateverTheDirectoriesAreCalled — доказательство
// того, что подъём находит корень независимо от имён каталогов и от глубины, и
// что на дереве БЕЗ маркера он отвечает отказом, а не пустым путём, который
// вызывающий склеил бы с относительным именем и прочитал бы не там.
//
// Вход синтетический НАМЕРЕННО: настоящее дерево несёт ровно одну раскладку из
// двух, а предмет здесь — обе плюс третья, которой в дереве нет и быть не
// должно.
func TestTreeRootIsFoundByClimbingWhateverTheDirectoriesAreCalled(t *testing.T) {
	base := t.TempDir()

	// (1) Раскладка арендатора: корень с go.mod, чарт под ним. Имя каталога
	// заведомо не то, которое проба могла бы ожидать.
	tenant := filepath.Join(base, "some-random-clone-name")
	mkdirAllOrFail(t, filepath.Join(tenant, "deploy", "templates"))
	writeFileOrFail(t, filepath.Join(tenant, "go.mod"), "module example.test\n\ngo 1.26.0\n")

	tenantProbeDir := filepath.Join(tenant, "deploy")
	if got := serviceRootFrom(tenantProbeDir); got != tenant {
		t.Fatalf("раскладка арендатора: служебный корень %q, ожидался %q", got, tenant)
	}
	if got := outerRootFrom(tenantProbeDir); got != tenant {
		t.Fatalf("раскладка арендатора: внешний корень %q, ожидался %q — над продуктом монорепо нет, "+
			"поэтому оба корня обязаны совпасть", got, tenant)
	}

	// (2) Раскладка монорепо: свой go.mod у корня и свой у службы. Имена
	// каталогов снова не те, что назвал бы счёт `..`.
	mono := filepath.Join(base, "outer-tree")
	svc := filepath.Join(mono, "components", "the-service")
	mkdirAllOrFail(t, filepath.Join(svc, "deploy", "templates"))
	writeFileOrFail(t, filepath.Join(mono, "go.mod"), "module example.test/outer\n\ngo 1.26.0\n")
	writeFileOrFail(t, filepath.Join(svc, "go.mod"), "module example.test/svc\n\ngo 1.26.0\n")

	monoProbeDir := filepath.Join(svc, "deploy")
	if got := serviceRootFrom(monoProbeDir); got != svc {
		t.Fatalf("раскладка монорепо: служебный корень %q, ожидался %q — подъём обязан остановиться "+
			"на модуле службы, а не уехать в корень дерева", got, svc)
	}
	if got := outerRootFrom(monoProbeDir); got != mono {
		t.Fatalf("раскладка монорепо: внешний корень %q, ожидался %q", got, mono)
	}
	if serviceRootFrom(monoProbeDir) == outerRootFrom(monoProbeDir) {
		t.Fatal("раскладка монорепо: корни совпали — тогда проба не отличит монорепо от клона арендатора")
	}

	// (3) Отрицательный случай: дерева без маркера не бывает у нас, но бывает у
	// того, кто распаковал архив без `go.mod`. Ответ обязан быть пустым — то
	// есть вызывающий обязан упасть, а не читать от текущего каталога.
	bare := filepath.Join(base, "no-marker-here", "deploy")
	mkdirAllOrFail(t, bare)
	if got := serviceRootFrom(bare); got != "" {
		t.Fatalf("дерево без go.mod: служебный корень %q, ожидалась пустота", got)
	}
	if got := outerRootFrom(bare); got != "" {
		t.Fatalf("дерево без go.mod: внешний корень %q, ожидалась пустота", got)
	}

	t.Logf("перепись: раскладок осмотрено 3 — арендатор (подъём на %d уровень), "+
		"монорепо (на %d и %d), дерево без маркера (маркер не найден); расхождений 0",
		climbDepth(tenantProbeDir, tenant), climbDepth(monoProbeDir, svc), climbDepth(monoProbeDir, mono))
}

// climbDepth — на сколько уровней пришлось подняться от каталога пробы до
// корня. Печатается в перепись, чтобы «нашёл» было отличимо от «нашёл там же,
// где стоял»: второе означало бы, что маркер лежит не там, где думает проба.
func climbDepth(from, root string) int {
	depth := 0
	for dir := from; dir != root; depth++ {
		parent := filepath.Dir(dir)
		if parent == dir {
			return -1
		}
		dir = parent
	}
	return depth
}

func mkdirAllOrFail(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("фикстура не собрана, каталог %s: %v", dir, err)
	}
}

func writeFileOrFail(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatalf("фикстура не собрана, файл %s: %v", path, err)
	}
}

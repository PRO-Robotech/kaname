// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_identity_census_boundary_injection_test.go — доказательство, что ГРАНИЦА
// переписи посевной идентичности знает ОБА дома текста приёмки и что она при
// этом НЕ СТАЛА МАСКОЙ.
//
// # ЧТО ДОКАЗЫВАЕТСЯ, И ПОЧЕМУ ЭТОГО НЕ ДОКАЗЫВАЛ НИ ОДИН СОСЕДНИЙ ФАЙЛ
//
// Соседняя инъекция (`seed_identity_census_injection_test.go`) судит РАЗБОР:
// сходится ли объявление §0 с напечатанным. О том, КАК предикат раскладывает
// вхождение по вёдрам, она не утверждает ничего — этот вопрос жил в самом
// предикате и держался чтением. Ровно там он и разошёлся: запись ревью
// (`docs/specs/reviews/<документ>/<sha256>.yaml`) цитирует сценарии приёмки
// дословно, вместе с литералами посевной идентичности, — и цитата считалась
// ОСТАТКОМ, то есть двигала ведро, обязанное дойти до нуля (задача #158).
//
// # ОДИН ФАКТ, И ОН — ПУТЬ
//
// Инъекция переносит ТОТ ЖЕ файл с теми же байтами из дома записей ревью
// наружу. Содержимое, имя, литералы, порядок строк — всё прежнее; различие
// ровно одно, и это путь. Иначе неизвестно, что дало сдвиг: граница или текст.
//
// # ВТОРАЯ СТОРОНА: ГРАНИЦА НЕ СТАЛА МАСКОЙ
//
// Проверяется ДВУМЯ близнецами сразу, и порознь ни один не годится:
//
//  1. литерал ВНЕ обоих домов — по-прежнему остаток;
//  2. литерал ВНУТРИ каталога записей ревью, но не в файле записи
//     (`README.md`) — тоже остаток. Приставка каталога без сужения до `*.yaml`
//     прощала бы всякий соседний файл, случайно туда положенный.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/treeroot"
)

// seedBoundaryLiteral — литерал посевной идентичности, один и тот же во ВСЕХ
// файлах фикстуры. Разные литералы сделали бы различие между прогонами не
// одним, а двумя.
//
// СОБИРАЕТСЯ ИЗ ЧАСТЕЙ, и это не украшение. Написанный целиком, он стал бы для
// переписи ОСТАТКОМ: файл пробы живёт вне обоих домов текста приёмки, и
// граница его не изымает — что и правильно, иначе она прощала бы всякий файл,
// назвавший литерал. Но тогда проба О ПРЕДМЕТЕ переписи двигала бы саму
// перепись: её посадка прибавила бы ведру «живой» ровно единицу и уронила
// сверку с §0 чужими руками. Замерено, а не предположено: до сборки из частей
// гейт на дереве этой полосы давал «живой 108 · 46 ф.» против объявленных
// 107 · 45 ф. Фикстура получает написание ДОСЛОВНО, дерево его не содержит.
var seedBoundaryLiteral = "kacho" + "-system.admin"

// seedBoundaryEdgeLine — строка изъятого в выводе предиката.
var seedBoundaryEdgeLine = regexp.MustCompile(
	`изъято как текст приёмки:\s*(\d+)\s*вхожден\S*\s+в\s+(\d+)\s*ф\.`)

// seedBoundaryTree — фикстура: по одному файлу на каждый разбираемый случай.
//
// Ключ — путь в синтетическом дереве, значение — строка с литералом.
func seedBoundaryTree() map[string]string {
	return map[string]string{
		// ОСТАТОК: живое написание, которое дерево читает как значение.
		"internal/apps/live.go": "const seat = \"" + seedBoundaryLiteral + "\"\n",
		// ЗАМЁРЗШЕЕ: применённая миграция. Без него сработала бы антимаска
		// пустого свода, и находок стало бы две — то есть «ровно одна» ниже
		// перестало бы различать предмет инъекции от соседа.
		"internal/migrations/0001_seed.sql": "INSERT INTO a VALUES ('" +
			seedBoundaryLiteral + "');\n",
		// ГРАНИЦА, дом 1: текст приёмки.
		"docs/engineering/acceptance/some-acceptance.md": "Сценарий цитирует `" +
			seedBoundaryLiteral + "` как предмет разбора.\n",
		// ГРАНИЦА, дом 2: запись ревью — носитель отпечатка.
		"docs/specs/reviews/some-acceptance/deadbeef.yaml": "  where: сценарий про " +
			seedBoundaryLiteral + "\n",
		// НЕ ГРАНИЦА: каталог тот же, файлом записи не является.
		"docs/specs/reviews/README.md": "Соседний файл про " + seedBoundaryLiteral + ".\n",
	}
}

// TestSeedCensusBoundary_BothHomesOfAcceptanceTextAreTheEdge — обе стороны разом.
func TestSeedCensusBoundary_BothHomesOfAcceptanceTextAreTheEdge(t *testing.T) {
	root, err := treeroot.ModuleRootFrom(".")
	if err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: корень модуля не назван: %v", err)
	}
	predicate := filepath.Join(root, seedCensusPredicate)
	if _, err := os.Stat(predicate); err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: предиката %s нет: %v", seedCensusPredicate, err)
	}

	dir := t.TempDir()
	seedBoundaryRepo(t, dir, seedBoundaryTree())

	// ── КОНТРОЛЬ ────────────────────────────────────────────────────────────
	//
	// Стоит первым и не формальность: без него всякий сдвиг ниже объяснялся бы
	// предикатом, который кладёт в остаток что попало.
	before := seedBoundaryRun(t, predicate, dir)
	live, ok := before.rep.Buckets["ПРЕДМЕТ: живой"]
	if !ok {
		t.Fatalf("предпосылка не выполнена: предикат не напечатал живого ведра:\n%s", before.out)
	}
	if live.Hits != 2 || live.Files != 2 {
		t.Fatalf("КОНТРОЛЬ: остатком обязаны быть РОВНО два файла — живой код и сосед "+
			"записей ревью, не являющийся записью. Получено %s:\n%s", live, before.out)
	}
	if before.edgeHits != 2 || before.edgeFiles != 2 {
		t.Fatalf("КОНТРОЛЬ: границей обязаны быть РОВНО два дома текста приёмки, "+
			"получено %d вхождений в %d ф.:\n%s", before.edgeHits, before.edgeFiles, before.out)
	}
	if !before.rep.EdgeNamed {
		t.Fatalf("КОНТРОЛЬ: разбор не увидел строки изъятого — величина границы вне "+
			"наблюдения:\n%s", before.out)
	}

	// ── ЗАКОННЫЙ БЛИЗНЕЦ №1: литерал вне обоих домов — ОСТАТОК ──────────────
	//
	// Он уже в контроле выше (`internal/apps/live.go`), и называется отдельно,
	// потому что это ровно то требование, которое граница могла бы нарушить,
	// став маской.
	if !strings.Contains(before.out, "ПРЕДМЕТ: живой") {
		t.Fatal("предикат перестал печатать живое ведро — сверять нечего")
	}

	// ── ИНЪЕКЦИЯ ОДНОГО ФАКТА: тот же файл, тот же байт, другой путь ────────
	seedBoundaryGit(t, dir, "mv", "docs/specs/reviews/some-acceptance/deadbeef.yaml",
		"docs/deadbeef.yaml")

	after := seedBoundaryRun(t, predicate, dir)
	moved := after.rep.Buckets["ПРЕДМЕТ: живой"]
	if moved.Hits != live.Hits+1 || moved.Files != live.Files+1 {
		t.Fatalf("ИНЪЕКЦИЯ: запись ревью, вынесенная из своего дома, обязана стать "+
			"остатком. Было %s, стало %s — граница судит не путь:\n%s",
			live, moved, after.out)
	}
	if after.edgeHits != before.edgeHits-1 || after.edgeFiles != before.edgeFiles-1 {
		t.Fatalf("ИНЪЕКЦИЯ: изъятое обязано убыть ровно на перенесённый файл. Было "+
			"%d · %d ф., стало %d · %d ф.:\n%s",
			before.edgeHits, before.edgeFiles, after.edgeHits, after.edgeFiles, after.out)
	}

	t.Logf("осмотрено: файлов фикстуры %d · остаток %s → %s · изъято %d · %d ф. → %d · %d ф. "+
		"· различие между прогонами одно (путь одного файла)",
		len(seedBoundaryTree()), live, moved,
		before.edgeHits, before.edgeFiles, after.edgeHits, after.edgeFiles)
}

// TestSeedCensusBoundary_EdgeUnprintedIsAFinding — АНТИМАСКА: величина границы
// изъята из вёдер, но не из наблюдения.
//
// Перестань предикат её печатать — текст приёмки исчез бы из переписи целиком,
// и «в тексте приёмки литералов нет» стало бы неотличимо от «предикат о нём
// молчит». Законный близнец — соседняя проба
// `TestSeedCensusInjection_LegitimateTwinIsSilent`: тот же вывод со строкой
// изъятого находок не даёт.
func TestSeedCensusBoundary_EdgeUnprintedIsAFinding(t *testing.T) {
	t.Parallel()

	out := strings.Replace(seedCensusSyntheticOutput, seedCensusSyntheticEdgeLine, "", 1)
	if out == seedCensusSyntheticOutput {
		t.Fatal("предпосылка инъекции не выполнена: строки изъятого не было и в близнеце")
	}
	rep, err := check.ParseSeedCensusOutput(out)
	if err != nil {
		t.Fatalf("вывод без строки изъятого обязан разбираться (это находка, а не "+
			"беспредметность), получено: %v", err)
	}
	if rep.EdgeNamed {
		t.Fatal("разбор объявил границу названной там, где строки нет")
	}
	decl := check.ParseSeedCensusDeclaration(
		seedCensusSyntheticDoc("abc1234", "130 · 56 ф."), rep.Order)
	if !seedCensusMentions(check.AdjudicateSeedCensus(decl, rep), "изъятое как текст приёмки") {
		t.Fatalf("непечатаемая граница не названа находкой: %v",
			check.AdjudicateSeedCensus(decl, rep))
	}
}

// seedBoundaryOutcome — вывод предиката и то, что из него вычитано.
type seedBoundaryOutcome struct {
	out       string
	rep       check.SeedCensusReport
	edgeHits  int
	edgeFiles int
}

// seedBoundaryRun зовёт НАСТОЯЩИЙ предикат на синтетическом дереве.
//
// Предикат берётся из дерева, а не переписывается пробой: копия разошлась бы с
// оригиналом ровно тогда, когда правят границу, — то есть осталась бы зелёной
// на том единственном изменении, ради которого проба написана.
func seedBoundaryRun(t *testing.T, predicate, dir string) seedBoundaryOutcome {
	t.Helper()

	out, err := seedBoundaryPython(t, predicate, dir)
	if err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: предикат не отработал на фикстуре: %v\n%s", err, out)
	}
	rep, perr := check.ParseSeedCensusOutput(out)
	if perr != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: вывод предиката не разобран: %v\n%s", perr, out)
	}
	res := seedBoundaryOutcome{out: out, rep: rep}
	if m := seedBoundaryEdgeLine.FindStringSubmatch(out); m != nil {
		res.edgeHits, _ = strconv.Atoi(m[1])
		res.edgeFiles, _ = strconv.Atoi(m[2])
	}
	return res
}

// seedBoundaryRepo кладёт фикстуру в СВОЙ репозиторий.
//
// Изоляция обязательна: проба, заводящая репозиторий, не трогает индекс того, из
// которого запущена (`multi-agent-flow-shared-tree.md` §13). Здесь она
// достигается тем, что все команды идут с явным `-C dir`, а само дерево лежит
// вне рабочей копии.
func seedBoundaryRepo(t *testing.T, dir string, tree map[string]string) {
	t.Helper()

	seedBoundaryGit(t, dir, "init", "--quiet", "-b", "main")
	for rel, body := range tree {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: каталог %s не создан: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: файл %s не записан: %v", rel, err)
		}
	}
	seedBoundaryGit(t, dir, "add", "-A")
}

func seedBoundaryGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := gitenv.Command(dir, args...)
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: git %v: %v\n%s", args, err, out)
	}
}

// seedBoundaryPython исполняет предикат с рабочим каталогом фикстуры.
//
// Каталог задаётся ЯВНО, а не переменной окружения: предикат спрашивает git о
// «текущем дереве», и без явного каталога он ответил бы о том репозитории, из
// которого запущена проба.
func seedBoundaryPython(t *testing.T, predicate, dir string) (string, error) {
	t.Helper()

	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: python3 не найден: %v — предикат написан на "+
			"нём, и без него о границе не известно ничего", err)
	}
	// Обе части команды константны: имя интерпретатора и путь предиката от
	// корня модуля.
	cmd := exec.Command(python, predicate)
	cmd.Dir = dir
	var buf strings.Builder
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	runErr := cmd.Run()
	return buf.String(), runErr
}

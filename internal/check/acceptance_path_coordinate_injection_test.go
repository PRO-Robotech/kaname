// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptance_path_coordinate_injection_test.go — ДОКАЗАТЕЛЬСТВО СПОСОБНОСТИ
// `TestAcceptancePathCoordinateResolves` УПАСТЬ И СМОЛЧАТЬ.
//
// Инъекция идёт В ОБЕ СТОРОНЫ по КАЖДОЙ оси: внесённый дефект обязан краснеть и
// называть координату, а ЗАКОННЫЙ БЛИЗНЕЦ той же формы — молчать. Односторонняя
// проба зеленела бы на гейте, который отвергает всё.
//
// ВХОД ПОДАЁТСЯ ЗНАЧЕНИЯМИ. Ядро судит поданные документы и поданный перечень
// отслеживаемых путей, поэтому инъекция не трогает рабочую копию, из которой
// запущена, — и не может испортить индекс соседней сессии.
//
// ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ. Последняя проба подаёт тот же синтетический
// корпус СОСЕДНЕМУ гейту (`JudgeProbeCoordinates`) и требует от него молчания:
// без неё красное было бы неотличимо от красного, пришедшего от соседа, и новый
// гейт мог бы оказаться вакуумным, не показав этого ничем.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// syntheticTree — отслеживаемые пути синтетического дерева. Перечень нарочно
// короткий: он и есть определение «резолвится» для этих проб.
var syntheticTree = []string{
	"internal/manifest/roles.go",
	"internal/manifest/manifest_test.go",
	"internal/migrations/0001_initial.sql",
	"internal/check/acceptance_path_coordinate.go",
	"go.mod",
}

func judgeOne(t *testing.T, body string) check.PathCoordinateCensus {
	t.Helper()
	return check.JudgePathCoordinates(
		map[string]string{"docs/engineering/acceptance/synthetic.md": body},
		syntheticTree, nil)
}

// findingsJoined — все находки одной строкой, для проверки, что координата названа.
func findingsJoined(c check.PathCoordinateCensus) string { return strings.Join(c.Findings, "\n") }

// ── ОСЬ 1. Мёртвый путь после `--` — находка, и она НАЗЫВАЕТ КООРДИНАТУ ───────

func TestInjection_PathCoordinate_DeadPathIsAFinding(t *testing.T) {
	c := judgeOne(t, "Предикат: `git grep -n 'X' -- services/iam/internal/manifest`\n")
	if len(c.Findings) != 1 {
		t.Fatalf("мёртвый путь предиката НЕ дал находки: находок %d, координат %d "+
			"(перепись: резолвится %d)", len(c.Findings), c.Coordinates, c.Resolved)
	}
	f := findingsJoined(c)
	for _, want := range []string{"synthetic.md:1", "services/iam/internal/manifest"} {
		if !strings.Contains(f, want) {
			t.Errorf("находка не называет %q — читатель не найдёт строку: %s", want, f)
		}
	}
}

// ── ОСЬ 1-бис. ЗАКОННЫЙ БЛИЗНЕЦ: живой путь — молчание ───────────────────────

func TestInjection_PathCoordinate_LivePathIsSilent(t *testing.T) {
	c := judgeOne(t, "Предикат: `git grep -n 'X' -- internal/manifest`\n")
	if len(c.Findings) != 0 {
		t.Fatalf("живой путь объявлен мёртвым — гейт ловит форму, а не существо: %s",
			findingsJoined(c))
	}
	if c.Coordinates != 1 || c.Resolved != 1 {
		t.Fatalf("живой путь не распознан координатой: координат %d, резолвится %d",
			c.Coordinates, c.Resolved)
	}
}

// ── ОСЬ 2. Названный ДОМ — вне суждения, НО в переписи ────────────────────────

func TestInjection_PathCoordinate_NamedHomeIsOutOfJudgementButCounted(t *testing.T) {
	c := judgeOne(t, "Предикат: `git grep -n 'X' -- PRO-Robotech/kacho:internal/repohygiene`\n")
	if len(c.Findings) != 0 {
		t.Fatalf("путь с названным домом объявлен находкой — чужое дерево этот гейт "+
			"судить не может: %s", findingsJoined(c))
	}
	if c.Foreign != 1 {
		t.Fatalf("чужой дом не сосчитан: Foreign=%d — «вне суждения» без счёта "+
			"неотличимо от «прощено»", c.Foreign)
	}
	if len(c.ForeignHomes) != 1 || c.ForeignHomes[0] != "PRO-Robotech/kacho" {
		t.Fatalf("дом не напечатан переписью: %v — опечатка в имени репозитория ушла бы "+
			"молча", c.ForeignHomes)
	}
	if c.RevisionBound != 0 {
		t.Fatalf("дом без ревизии сосчитан связанным ревизией: %d", c.RevisionBound)
	}
}

func TestInjection_PathCoordinate_HomeBoundToARevisionIsCountedApart(t *testing.T) {
	c := judgeOne(t, "Предикат: `git grep -n 'X' -- PRO-Robotech/kacho@d941344bd9:internal/repohygiene`\n")
	if len(c.Findings) != 0 {
		t.Fatalf("дом с ревизией объявлен находкой: %s", findingsJoined(c))
	}
	if c.Foreign != 1 || c.RevisionBound != 1 {
		t.Fatalf("координата, связанная ревизией, не выделена отдельной величиной: "+
			"Foreign=%d RevisionBound=%d — она не проверяема даже там, где дерево дома есть",
			c.Foreign, c.RevisionBound)
	}
}

// ── ОСЬ 3. Приставка, домом НЕ являющаяся, — НАХОДКА ─────────────────────────
//
// Без этой оси любой неразобранный префикс снимал бы путь с суждения, и
// приставка стала бы способом спрятать адрес, а не назвать дом.

func TestInjection_PathCoordinate_MalformedHomeIsAFinding(t *testing.T) {
	for _, bad := range []string{"kacho:internal/repohygiene", "MOD-MF-21:internal/manifest"} {
		c := judgeOne(t, "Предикат: `git grep -n 'X' -- "+bad+"`\n")
		if len(c.Findings) != 1 || !strings.Contains(findingsJoined(c), "ДОМ НАЗВАН НЕ ДОМОМ") {
			t.Errorf("приставка %q принята за дом либо пропущена: находок %d (%s)",
				bad, len(c.Findings), findingsJoined(c))
		}
		if c.Foreign != 0 {
			t.Errorf("приставка %q сосчитана чужим домом: Foreign=%d", bad, c.Foreign)
		}
	}
}

// ── ОСЬ 4. ПРОЗА вне суждения — путь без команды не координата ───────────────

func TestInjection_PathCoordinate_ProseIsNotJudged(t *testing.T) {
	c := judgeOne(t, "Зеркало живёт в `services/iam/internal/repo/kaname/pg/resource_mirror`.\n")
	if c.Coordinates != 0 || len(c.Findings) != 0 {
		t.Fatalf("путь, названный ПРОЗОЙ, попал под суждение: координат %d, находок %d "+
			"(%s) — судить прозу значило бы требовать переписать свидетельство о прошлом",
			c.Coordinates, len(c.Findings), findingsJoined(c))
	}
}

// ── ОСЬ 5. ОГОРОЖЕННЫЙ БЛОК СУДИТСЯ — инверсия относительно соседа ───────────
//
// Сосед пропускает блоки кода целиком. Здесь блок — главное место жительства
// предиката: пропусти его гейт, и он потерял бы четверть корпуса молча.

func TestInjection_PathCoordinate_FencedBlockIsJudged(t *testing.T) {
	body := "Предикат:\n\n```sh\ngit grep -n 'X' -- services/iam/internal/manifest\n```\n"
	c := judgeOne(t, body)
	if len(c.Findings) != 1 {
		t.Fatalf("мёртвый путь ВНУТРИ огороженного блока не пойман: находок %d, "+
			"координат %d — блок кода есть главное место жительства предиката",
			len(c.Findings), c.Coordinates)
	}
	live := judgeOne(t, "Предикат:\n\n```sh\ngit grep -n 'X' -- internal/manifest\n```\n")
	if len(live.Findings) != 0 || live.Resolved != 1 {
		t.Fatalf("законный близнец в блоке кода объявлен находкой: %s", findingsJoined(live))
	}
}

// ── ОСЬ 6. ПОДСТАНОВОЧНЫЙ ЗНАК — судится глубочайший предок без метасимвола ──

func TestInjection_PathCoordinate_WildcardJudgesTheDeepestLiteralAncestor(t *testing.T) {
	// Живой каталог + шаблон, которому НИЧТО не соответствует, — законный вердикт.
	live := judgeOne(t, "`git ls-files -- 'internal/migrations/*.sql'`\n")
	if len(live.Findings) != 0 {
		t.Errorf("шаблон над ЖИВЫМ каталогом объявлен мёртвой координатой: %s",
			findingsJoined(live))
	}
	// Мёртвый каталог под тем же шаблоном — находка.
	dead := judgeOne(t, "`git ls-files -- 'services/iam/internal/migrations/*.sql'`\n")
	if len(dead.Findings) != 1 {
		t.Errorf("шаблон над МЁРТВЫМ каталогом пропущен: находок %d", len(dead.Findings))
	}
}

// TestInjection_PathCoordinate_MetacharInsideAFilenameDoesNotKillItsDirectory —
// РЕГРЕССИЯ НА ДЕФЕКТ, ПОЙМАННЫЙ НА СЕБЕ ПРИ ЗАВЕДЕНИИ ГЕЙТА.
//
// Наивное отсечение «часть до звёздочки» даёт `internal/migrations/20260902` —
// префикс ИМЕНИ ФАЙЛА, а не каталог, — и объявляет мёртвым живой каталог.
func TestInjection_PathCoordinate_MetacharInsideAFilenameDoesNotKillItsDirectory(t *testing.T) {
	c := judgeOne(t, "`git ls-files -- 'internal/migrations/20260902*'`\n")
	if len(c.Findings) != 0 {
		t.Fatalf("шаблон с метасимволом ВНУТРИ имени файла объявлен мёртвым: %s — "+
			"отсекать надо до ближайшего `/`, а не до первой звёздочки", findingsJoined(c))
	}
	if c.Resolved != 1 {
		t.Fatalf("шаблон не сосчитан резолвящимся: резолвится %d", c.Resolved)
	}
}

// ── ОСЬ 7. Магическая спецификация и эллипсис — НЕ пути ──────────────────────

func TestInjection_PathCoordinate_MagicSpecAndEllipsisAreNotPaths(t *testing.T) {
	c := judgeOne(t, "`git grep -n 'X' -- internal/manifest ':!*_test.go'`\n")
	if len(c.Findings) != 0 || c.Coordinates != 1 {
		t.Fatalf("магическая путь-спецификация принята за путь: координат %d, находок %d (%s)",
			c.Coordinates, len(c.Findings), findingsJoined(c))
	}
	if c.Borders.Magic != 1 {
		t.Errorf("магическая спецификация не сосчитана границей: %d", c.Borders.Magic)
	}
	e := judgeOne(t, "`git grep -n 'X' -- '…/*.yaml'`\n")
	if len(e.Findings) != 0 || e.Coordinates != 0 {
		t.Fatalf("эллипсис прозы принят за путь: координат %d, находок %d",
			e.Coordinates, len(e.Findings))
	}
	if e.Borders.Elided != 1 {
		t.Errorf("эллипсис не сосчитан границей: %d", e.Borders.Elided)
	}
}

// ── ОСЬ 8. `git ls-files <спец>` БЕЗ `--` — вне суждения, но в переписи ──────
//
// Там путь сплошь и рядом САМ ЕСТЬ утверждение об отсутствии («такого корня
// нет, → 0»), и находка на нём была бы ложной.

func TestInjection_PathCoordinate_BareSpecIsCountedNotJudged(t *testing.T) {
	c := judgeOne(t, "`git ls-files 'proto/kacho/cloud/iam/**'` → **0**\n")
	if len(c.Findings) != 0 || c.Coordinates != 0 {
		t.Fatalf("путь-спецификация без `--` попала под суждение: координат %d, находок %d "+
			"(%s) — там нерезолвящийся путь и есть доказываемое",
			c.Coordinates, len(c.Findings), findingsJoined(c))
	}
	if c.Borders.BareSpec != 1 {
		t.Fatalf("путь-спецификация без `--` не сосчитана границей: %d — слепая зона, "+
			"о которой молчат, есть дыра", c.Borders.BareSpec)
	}
}

// ── ОСЬ 9. `--name-only` НЕ открывает пробег путей ───────────────────────────

func TestInjection_PathCoordinate_LongOptionIsNotAPathspecRun(t *testing.T) {
	c := judgeOne(t, "`git ls-files --name-only | grep -c '^services/iam/'`\n")
	if c.Coordinates != 0 || len(c.Findings) != 0 {
		t.Fatalf("длинный ключ принят за начало пробега путей: координат %d, находок %d (%s)",
			c.Coordinates, len(c.Findings), findingsJoined(c))
	}
}

// ── ОСЬ 10. ПОСЛАБЛЕНИЕ истекает САМО — оба конца ────────────────────────────

func TestInjection_PathCoordinate_ExemptionExpiresFromBothEnds(t *testing.T) {
	docs := map[string]string{
		"docs/engineering/acceptance/synthetic.md": "`git grep -n 'X' -- services/iam/internal/manifest`\n",
	}
	// Запись С ПРЕДМЕТОМ — молчит и считается.
	with := check.JudgePathCoordinates(docs, syntheticTree,
		[]check.DeadPathCoordinate{{Path: "services/iam/internal/manifest", Issue: 71}})
	if len(with.Findings) != 0 || with.Exempted != 1 {
		t.Fatalf("запись с предметом не сработала: находок %d, по ведомости %d",
			len(with.Findings), with.Exempted)
	}
	// Запись, которой НЕЧЕГО исключать, — находка (путь больше не стоит).
	gone := check.JudgePathCoordinates(
		map[string]string{"docs/engineering/acceptance/synthetic.md": "проза без предикатов\n"},
		syntheticTree,
		[]check.DeadPathCoordinate{{Path: "services/iam/internal/manifest", Issue: 71}})
	if len(gone.Findings) != 1 || !strings.Contains(findingsJoined(gone), "ПОСЛАБЛЕНИЕ БЕЗ ПРЕДМЕТА") {
		t.Fatalf("послабление без предмета не истекло: %s", findingsJoined(gone))
	}
	// Второй конец: путь СНОВА резолвится — исключать тоже нечего.
	alive := check.JudgePathCoordinates(
		map[string]string{"docs/engineering/acceptance/synthetic.md": "`git grep -n 'X' -- internal/manifest`\n"},
		syntheticTree,
		[]check.DeadPathCoordinate{{Path: "internal/manifest", Issue: 71}})
	if len(alive.Findings) != 1 || !strings.Contains(findingsJoined(alive), "снова резолвится") {
		t.Fatalf("послабление на ожившем пути не истекло: %s", findingsJoined(alive))
	}
}

// ── ОСЬ 11. ПУСТОЙ ОБХОД — «ноль находок» отличимо от «ноль прочитанного» ────

func TestInjection_PathCoordinate_EmptyWalkIsDistinguishable(t *testing.T) {
	c := check.JudgePathCoordinates(map[string]string{}, syntheticTree, nil)
	if c.Docs != 0 || c.Coordinates != 0 {
		t.Fatalf("пустой корпус не опознан: приёмок %d, координат %d", c.Docs, c.Coordinates)
	}
	if len(c.Findings) != 0 {
		t.Fatalf("пустой корпус дал находки: %s", findingsJoined(c))
	}
	// Отказ на пустом обходе живёт в ГЕЙТЕ, а не в ядре: ядро судит поданные
	// значения, и корпус из нуля документов — законный вход для него.
	// Здесь проверено, что величина, по которой гейт фатает, ДОХОДИТ до него.
}

// ── ОСЬ 12. ИНЪЕКЦИЯ РОНЯЕТ ТОЛЬКО ПРОВЕРЯЕМОЕ ──────────────────────────────
//
// Тот же синтетический вход подаётся СОСЕДНЕМУ гейту. Он обязан молчать: иначе
// красное нового гейта неотличимо от красного, пришедшего от соседа, и новый
// мог бы оказаться вакуумным, не показав этого ничем.

func TestInjection_PathCoordinate_NeighbourGateIsSilentOnTheSameInput(t *testing.T) {
	body := "Предикат: `git grep -n 'X' -- services/iam/internal/manifest`\n"
	mine := judgeOne(t, body)
	if len(mine.Findings) != 1 {
		t.Fatalf("предпосылка пробы не выполнена: проверяемый гейт обязан краснеть, "+
			"находок %d", len(mine.Findings))
	}
	neighbour := check.JudgeProbeCoordinates(
		map[string]string{"docs/engineering/acceptance/synthetic.md": body},
		[]string{"TestSomethingThatExists"}, nil)
	if len(neighbour.Findings) != 0 {
		t.Fatalf("СОСЕДНИЙ гейт краснеет на том же входе (%s) — инъекция роняет не только "+
			"проверяемое, и вердикт нового гейта ничего не доказывает",
			strings.Join(neighbour.Findings, "; "))
	}
}

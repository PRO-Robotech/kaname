// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// ErrPostureNotBuilt — посадку собрать не удалось: проверка НЕ ИСПОЛНЯЛАСЬ.
//
// Отдельный признак, а не общий отказ: «клон не собран» и «цель отказала» —
// разные исходы, и первый не вычитается из вердикта и не зачитывается в успех.
var ErrPostureNotBuilt = errors.New("самостоятельная посадка не собрана")

// monorepoMark — пометка, которой рецепт объявляет, что цель зовёт соседей по
// дереву. Читается ДОСЛОВНО той же строкой, которую печатает `make help`:
// перечень там выводится из строк `## `, и второго словаря у пометки нет.
const monorepoMark = "[монорепо]"

// targetLine — строка объявления цели в рецепте: `## <имя> — <что делает>`.
//
// Разделитель — тире, а не дефис, и это не придирка: `help` печатает эти строки
// как есть, а имена целей дефис содержат (`build-migrator`, `model-canon-check`).
// Образец, принявший дефис за разделитель, обрезал бы имя по первому же дефису и
// судил бы цель `build`, которой в перечне нет, — то есть молчал бы о настоящей.
var targetLine = regexp.MustCompile(`^##\s+(\S+)\s+—\s+(.*)$`)

// Target — цель рецепта в том виде, в каком её читает арендатор.
type Target struct {
	// Name — имя цели, которым её зовут.
	Name string
	// Desc — описание из той же строки; в находке оно называется, чтобы
	// читатель не ходил за ним в рецепт.
	Desc string
	// Monorepo — рецепт объявил, что цель зовёт соседей по дереву.
	Monorepo bool
}

// Waiver — цель, которую гейт не зовёт, и НАЗВАННАЯ причина.
//
// Причина обязательна: запись без неё есть «не спрашиваем» без основания —
// ровно тот дефект, который гейты этого дерева ищут. Предмет у каждой записи
// один и тот же по форме — ресурс, которого у пробы нет by construction
// (демон сборки образов, живая база, сеть). Это НЕ отсрочка: такая цель не
// станет проверяемой оттого, что кто-то ею займётся, — её предпосылку создаёт
// не код, а стенд.
//
// Запись, которой больше нечего покрывать (цель исчезла из рецепта либо стала
// помеченной), — НАХОДКА: послабление живёт, пока у него есть предмет.
type Waiver struct {
	Target string
	Reason string
}

// ParseTargets — перечень целей, выведенный из рецепта.
//
// Выводится из ТОГО ЖЕ источника, который печатает `make help` (строки `## `), а
// не из второго списка: выписанный разошёлся бы с рецептом молча, и гейт судил
// бы цели, которых арендатор не видит, пропуская те, что видит.
func ParseTargets(makefile []byte) []Target {
	var out []Target
	for _, ln := range strings.Split(string(makefile), "\n") {
		m := targetLine.FindStringSubmatch(strings.TrimRight(ln, "\r"))
		if m == nil {
			continue
		}
		out = append(out, Target{
			Name:     m[1],
			Desc:     strings.TrimSpace(m[2]),
			Monorepo: strings.Contains(m[2], monorepoMark),
		})
	}
	return out
}

// Census — объём осмотренного. Печатается ВСЕГДА и первым: без него зелёный
// вердикт неотличим от вердикта гейта, не прочитавшего ничего.
type Census struct {
	Declared  int
	Monorepo  int
	Waived    int
	Judged    int
	Posture   string
	StaleWaiv []string
}

func (c Census) String() string {
	return fmt.Sprintf(
		"перепись: целей объявлено %d · помечено %s %d · прощено ведомостью %d · судимых %d · посадка %s",
		c.Declared, monorepoMark, c.Monorepo, c.Waived, c.Judged, c.Posture)
}

// Judged — цели, которые гейт обязан позвать, и переучёт по ведомости.
//
// Ведомость сверяется В ОБЕ СТОРОНЫ: запись без предмета возвращается в
// StaleWaiv и делает вердикт находкой. Без этого послабление пережило бы свою
// цель и досталось бы следующей, случайно совпавшей по имени.
func Judged(targets []Target, waivers []Waiver) ([]Target, Census) {
	byName := map[string]string{}
	for _, w := range waivers {
		byName[w.Target] = w.Reason
	}

	var judged []Target
	c := Census{Declared: len(targets)}
	used := map[string]bool{}
	for _, t := range targets {
		switch {
		case t.Monorepo:
			c.Monorepo++
		case byName[t.Name] != "":
			c.Waived++
			used[t.Name] = true
		default:
			judged = append(judged, t)
		}
	}
	for _, w := range waivers {
		if !used[w.Target] {
			c.StaleWaiv = append(c.StaleWaiv, w.Target)
		}
	}
	sort.Strings(c.StaleWaiv)
	c.Judged = len(judged)
	return judged, c
}

// ModuleRootFrom поднимается от start до БЛИЖАЙШЕГО каталога с `go.mod`.
//
// Маркер — `go.mod`, а не имя каталога: имя у арендатора выбирает тот, кто
// клонировал (`kaname`, `iam`, `src`), и проба, опознающая корень по имени, у
// половины клонирующих не находит его МОЛЧА. Число `..` не называется вовсе,
// поэтому смена глубины перестаёт быть предметом правки. Та же форма, что у
// соседа по модулю — `deploy/tree_root_test.go`.
func ModuleRootFrom(start string) (string, error) {
	dir := start
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && st.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: маркер go.mod не найден подъёмом от %s", ErrPostureNotBuilt, start)
		}
		dir = parent
	}
}

// AssertOutsideAnyRepository — предпосылка фикстуры: каталог, в котором будет
// собран клон, НЕ лежит внутри чужого репозитория.
//
// Несущая, а не гигиеническая. Клон внутри чужого дерева получает при обходе
// вверх ЧУЖОЙ индекс, и цели выносят по нему вердикт — зелёный, отличить его от
// настоящего нечем. Это тот же класс, ради которого написаны tree-root.sh
// (#2145) и резолв канона (#2159); гейт, воспроизводящий его собственной
// фикстурой, судил бы не то, что объявляет.
//
// Проверяется НАЛИЧИЕ каталога `.git` на каждом уровне вверх, а не ответ git:
// ответ git о самом каталоге ничего не скажет, пока каталог ещё не создан.
func AssertOutsideAnyRepository(dir string) error {
	cur := filepath.Clean(dir)
	for {
		if st, err := os.Stat(filepath.Join(cur, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return fmt.Errorf(
				"%w: каталог фикстуры лежит внутри репозитория\n"+
					"  осмотрено:        %s\n"+
					"  найден признак:   %s\n"+
					"  ожидался признак: ни одного .git на пути вверх от каталога фикстуры\n"+
					"  клон, собранный внутри чужого дерева, получает при обходе вверх ЧУЖОЙ\n"+
					"  индекс — и цели выносят вердикт о нём, а не о модуле; отличить такой\n"+
					"  зелёный от настоящего нечем. Назовите TMPDIR вне всякого репозитория",
				ErrPostureNotBuilt, dir, filepath.Join(cur, ".git"))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

// Finding — цель, объявленная рабочей вне монорепо, которая в самостоятельном
// клоне отказала.
type Finding struct {
	Target Target
	Code   int
	Tail   string
}

func (f Finding) String() string {
	return fmt.Sprintf(
		"цель %q объявлена рабочей вне монорепо (пометки %s в её строке нет), а в самостоятельном клоне отказала кодом %d\n"+
			"  объявлено:   ## %s — %s\n"+
			"  хвост вывода:\n%s\n"+
			"  исходов два: либо цель работает у арендатора, либо рецепт помечает её %s и\n"+
			"  отказывает СЛОВАМИ, называя, что делать вместо. Молчаливое красное у всякого,\n"+
			"  кто склонирует, исходом не является",
		f.Target.Name, monorepoMark, f.Code, f.Target.Name, f.Target.Desc, f.Tail, monorepoMark)
}

// RunTargets зовёт каждую цель в собранной посадке и возвращает находки.
//
// Отделено от фикстуры намеренно: посадку строит проба (ей нужен git и
// временный каталог), а СУЖДЕНИЕ живёт здесь — и потому доказуемо инъекцией на
// синтетической посадке, где отказ цели подан нарочно. Гейт, чью способность
// падать нельзя предъявить иначе как поломкой дерева, доказательства не имеет.
//
// Ошибка запуска (`make` не нашёлся) — НЕ находка: это «проверка не
// исполнялась», и она возвращается отдельно, а не подмешивается к находкам.
func RunTargets(dir string, targets []Target, run func(dir, target string) (int, string, error)) ([]Finding, error) {
	var out []Finding
	for _, t := range targets {
		code, output, err := run(dir, t.Name)
		if err != nil {
			return nil, fmt.Errorf("%w: цель %s не запустилась: %w", ErrPostureNotBuilt, t.Name, err)
		}
		if code != 0 {
			out = append(out, Finding{Target: t, Code: code, Tail: Tail(output, 25)})
		}
	}
	return out, nil
}

// Tail — последние n строк вывода, с отступом. Находка обязана нести ТЕКСТ
// отказа цели, а не только её имя: имя посылает читателя искать причину, текст
// её называет.
func Tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return "    " + strings.Join(lines, "\n    ")
}

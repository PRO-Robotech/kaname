// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_recipe_exit_test.go — код обязательного вызова доходит до кода цели.
//
// ЗАЧЕМ. Проба `make -n` (notify_recipe_test.go) судит, что вызов НАПЕЧАТАН.
// Напечатанный вызов с гасителем кода — `… || true` в конце строки или
// префикс make «-» перед ней (make -n префикс снимает) — печатается так же, а
// красная сверка D07 даёт зелёную цель и зелёный конвейер. Измерено
// check-verifier на fd78327c1: обе порчи проходили пробу `make -n` зелёными.
//
// КАК СУДИТ — двумя независимыми путями.
//
//  1. ЧТЕНИЕ ТЕКСТА РЕЦЕПТА на гасители по форме. Префикс «-» и `.IGNORE`
//     читаются из базы make (`make -p`), где строка рецепта стоит как написана;
//     строка признаётся строкой обязательного вызова, если её развёртка самим
//     make (служебная цель с тем же телом без префикса) печатает этот вызов.
//     `|| true`, `|| :`, `|| exit 0`, `; true` в конце строки и `set +e`
//     читаются в выводе make -n по простым командам строки вызова.
//  2. ИСПОЛНЕНИЕ с заведомо неверным входом: цель обязана выйти НЕНУЛЕВЫМ
//     кодом, а в выводе обязан стоять отказ ИМЕННО обязательного вызова на
//     поданном входе. Этот путь общий: он ловит и гасители, которых чтение
//     по форме не знает (труба без pipefail, `MAKEFLAGS += -i`, гаситель,
//     собранный из переменной).
//
// Неверный вход не бывает законным: `notifications-check` получает базу
// notifyRecipeBase, которая ревизией не разрешается (генератор отвечает
// «база не найдена»), `notify-tree-gates` — образец -run notifyRecipeRun,
// который не компилируется (`go test` отвечает «invalid regexp»). Ни одна
// проба при этом не исполняется — рекурсии в этот пакет нет: исполнение
// разрешено, лишь когда make -n показал, что вызов несёт поданный вход.
//
// `set +e` судится только по форме: оболочка рецепта этого Makefile идёт без
// `-e` (.SHELLFLAGS не задан), и на исполнении код вызова до цели доходит; в
// строке обязательного вызова у `set +e` нет законной работы, кроме как
// пропустить отказ дальше по строке.
package check_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// notifyRecipeRun — заведомо некомпилируемый образец -run для notify-tree-gates.
const notifyRecipeRun = "(ntf1-recipe-probe-run"

// notifyRecipeLineTarget — служебная цель, телом которой make разворачивает
// одну строку рецепта.
const notifyRecipeLineTarget = "ntf1-recipe-probe-line"

// notifyRecipeExecTimeout — предел исполнения цели: холодная сборка
// генератора и тестового бинаря пакета на машине конвейера.
const notifyRecipeExecTimeout = 10 * time.Minute

// notifyRecipeSpec — что проба знает о цели.
type notifyRecipeSpec struct {
	target string
	vars   []string                      // переменные make для make -n и make -p
	match  func([]string) (bool, string) // обязательный вызов
	absent string                        // находка «вызова нет»

	execVars   []string            // переменные make для исполнения с неверным входом
	driven     func([]string) bool // вызов несёт поданный неверный вход
	drivenWhat string
	refusal    []string // подстроки отказа вызова на неверном входе — все
}

func notifyRecipeSpecFor(t *testing.T, root string, extra []string, target string) notifyRecipeSpec {
	t.Helper()
	switch target {
	case "notifications-check":
		base := []string{"BASE=" + notifyRecipeBase}
		return notifyRecipeSpec{
			target: target,
			vars:   base,
			match:  func(cmd []string) (bool, string) { return isNotifygenCheck(cmd, notifyRecipeBase) },
			absent: "вызова `notifygen -check -base " + notifyRecipeBase + "` нет — сверка D07 не исполняется",

			execVars:   base,
			driven:     func(cmd []string) bool { ok, _ := isNotifygenCheck(cmd, notifyRecipeBase); return ok },
			drivenWhat: "-base " + notifyRecipeBase,
			refusal:    []string{`база не найдена: "` + notifyRecipeBase + `"`},
		}
	case "notify-tree-gates":
		gates := notifyTreeGatesList(t, root, extra)
		return notifyRecipeSpec{
			target: target,
			match:  func(cmd []string) (bool, string) { return isTreeGatesRun(cmd, gates) },
			absent: "вызова `go test ./internal/check/ -run <перечень>` нет — гейты дерева не исполняются",

			execVars: []string{"NOTIFY_TREE_GATES_RUN=" + notifyRecipeRun},
			driven: func(cmd []string) bool {
				if len(cmd) < 2 || cmd[0] != "go" || cmd[1] != "test" ||
					!slices.ContainsFunc(cmd[2:], func(w string) bool { return slices.Contains(notifyTreeGatesPkgs, w) }) {
					return false
				}
				run, ok := goFlags(cmd[2:])["run"]
				return ok && run == notifyRecipeRun
			},
			drivenWhat: "-run из NOTIFY_TREE_GATES_RUN=" + notifyRecipeRun,
			refusal:    []string{"invalid regexp", notifyRecipeRun},
		}
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: цель %s пробе не известна", target)
	return notifyRecipeSpec{}
}

// judgeRecipeQuench — путь 1: гасители кода по форме у строк обязательного
// вызова. out — вывод make -n цели.
func judgeRecipeQuench(t *testing.T, root string, extra []string, spec notifyRecipeSpec, out string, r *recipeReport) {
	t.Helper()
	if lines, err := shellLines(out); err == nil { // отказ разбора уже назван judgeRecipe
		for _, line := range lines {
			for i, c := range line {
				if ok, _ := spec.match(c.Words); ok {
					r.Findings = append(r.Findings, quenchInLine(line, i)...)
				}
			}
		}
	}

	db := makeRun(t, root, extra, append([]string{"-pn", spec.target}, spec.vars...)...)
	recipe := recipeFromDatabase(db, spec.target)
	r.RecipeLines = len(recipe)
	if len(recipe) == 0 {
		r.Findings = append(r.Findings, "рецепт цели не прочитан базой make (make -p) — префиксы строк судить не по чему")
	}
	for _, l := range recipe {
		if !strings.Contains(l.prefix, "-") {
			continue
		}
		if recipeLineCalls(t, root, extra, spec, l.body) {
			r.Findings = append(r.Findings, fmt.Sprintf(
				"%s (%s:%d): make игнорирует код строки, отказ вызова не доходит до кода цели",
				"префикс make «-» у строки обязательного вызова", l.file, l.line))
		}
	}
	if f, ok := ignoreFinding(db, spec.target); ok {
		r.Findings = append(r.Findings, f)
	}
}

// quenchInLine — гасители кода вызова line[i] в его строке оболочки.
func quenchInLine(line []shellCmd, i int) []string {
	var f []string
	for _, d := range line {
		if isSetPlusE(d.Words) {
			f = append(f, "`set +e` в строке обязательного вызова ("+strings.Join(d.Words, " ")+
				"): у него здесь нет работы, кроме как пропустить отказ вызова дальше по строке")
		}
	}
	c := line[i]
	if c.Op == "||" && i+1 < len(line) && isQuencher(line[i+1].Words) {
		return append(f, fmt.Sprintf("гаситель кода `|| %s` после обязательного вызова: отказ заменяется успехом",
			strings.Join(line[i+1].Words, " ")))
	}
	if last := len(line) - 1; last > i && isQuencher(line[last].Words) && line[last-1].Op != "&&" {
		f = append(f, fmt.Sprintf("гаситель кода `%s %s` в конце строки обязательного вызова: код строки — код гасителя",
			line[last-1].Op, strings.Join(line[last].Words, " ")))
	}
	return f
}

// isQuencher — команда, всегда выходящая нулём: `true`, `:`, `exit 0`.
func isQuencher(w []string) bool {
	if len(w) == 0 {
		return false
	}
	switch w[0] {
	case "true", ":":
		return true
	case "exit":
		return len(w) > 1 && w[1] == "0"
	}
	return false
}

// isSetPlusE — `set +e`, `set +eu`, `set +o errexit`.
func isSetPlusE(w []string) bool {
	if len(w) < 2 || w[0] != "set" {
		return false
	}
	for j, a := range w[1:] {
		if a == "+o" && j+2 < len(w) && w[j+2] == "errexit" {
			return true
		}
		if strings.HasPrefix(a, "+") && a != "+o" && strings.ContainsRune(a, 'e') {
			return true
		}
	}
	return false
}

// recipeLine — логическая строка рецепта из базы make.
type recipeLine struct {
	prefix string // префиксы make: `@`, `-`, `+`
	body   string // текст после префиксов, переносы `\` сохранены
	file   string
	line   int
}

var recipeFromRe = regexp.MustCompile(`^#  recipe to execute \(from '(.*)', line (\d+)\):$`)

// recipeFromDatabase — рецепт цели target из вывода `make -p` (LC_ALL=C):
// строки за заголовком «recipe to execute» записи цели, сведённые по
// переносам `\` в логические.
func recipeFromDatabase(db, target string) []recipeLine {
	lines := strings.Split(db, "\n")
	for i := 0; i < len(lines); i++ {
		if lines[i] != target+":" && !strings.HasPrefix(lines[i], target+": ") {
			continue
		}
		j := i + 1
		for j < len(lines) && strings.HasPrefix(lines[j], "#") && !recipeFromRe.MatchString(lines[j]) {
			j++
		}
		if j >= len(lines) {
			return nil
		}
		m := recipeFromRe.FindStringSubmatch(lines[j])
		if m == nil {
			continue
		}
		start, _ := strconv.Atoi(m[2])
		var out []recipeLine
		open := false
		for k := j + 1; k < len(lines) && strings.HasPrefix(lines[k], "\t"); k++ {
			phys := lines[k]
			if open {
				out[len(out)-1].body += "\n" + phys
			} else {
				body := strings.TrimPrefix(phys, "\t")
				var prefix strings.Builder
				for body != "" && strings.ContainsRune("@-+ \t", rune(body[0])) {
					if body[0] != ' ' && body[0] != '\t' {
						prefix.WriteByte(body[0])
					}
					body = body[1:]
				}
				out = append(out, recipeLine{prefix: prefix.String(), body: body, file: m[1], line: start + (k - j - 1)})
			}
			open = strings.HasSuffix(phys, "\\")
		}
		return out
	}
	return nil
}

// recipeLineCalls — печатает ли строка рецепта body, развёрнутая самим make
// телом служебной цели, обязательный вызов.
func recipeLineCalls(t *testing.T, root string, extra []string, spec notifyRecipeSpec, body string) bool {
	t.Helper()
	helper := filepath.Join(t.TempDir(), "recipe-line.mk")
	if err := os.WriteFile(helper, []byte(notifyRecipeLineTarget+":\n\t"+body+"\n"), 0o600); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	out := makeRun(t, root, append(slices.Clone(extra), helper), append([]string{"-n", notifyRecipeLineTarget}, spec.vars...)...)
	cmds, err := shellCommands(out)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: развёртка строки рецепта не разбирается: %v\n%s", err, out)
	}
	return slices.ContainsFunc(cmds, func(c []string) bool { ok, _ := spec.match(c); return ok })
}

// ignoreFinding — `.IGNORE` без пререквизитов либо с целью среди них.
func ignoreFinding(db, target string) (string, bool) {
	for _, l := range strings.Split(db, "\n") {
		if !strings.HasPrefix(l, ".IGNORE:") {
			continue
		}
		pre := strings.Fields(strings.TrimPrefix(l, ".IGNORE:"))
		if len(pre) == 0 || slices.Contains(pre, target) {
			return "цель названа в .IGNORE (`" + l + "`): make игнорирует коды всех её строк", true
		}
	}
	return "", false
}

// judgeRecipeExit — путь 2: исполнить цель с неверным входом и требовать
// ненулевой код при напечатанном отказе обязательного вызова. Исполняется
// лишь тело, где make -n показал ровно один вызов, несущий поданный вход.
func judgeRecipeExit(t *testing.T, root string, extra []string, spec notifyRecipeSpec, r *recipeReport) {
	t.Helper()
	if r.Calls != 1 {
		return // находку о вызове уже назвал judgeRecipe; исполнять нечего
	}
	pre, err := shellCommands(makeRun(t, root, extra, append([]string{"-n", spec.target}, spec.execVars...)...))
	if err != nil {
		return // отказ разбора уже назван judgeRecipe
	}
	if n := len(slices.DeleteFunc(pre, func(c []string) bool { return !spec.driven(c) })); n != 1 {
		r.Findings = append(r.Findings, fmt.Sprintf(
			"исполнение не проверено: вызовов, несущих поданный неверный вход (%s), %d, а не один — "+
				"распространение кода судить не по чему", spec.drivenWhat, n))
		return
	}
	out, rc := makeExec(t, root, extra, append([]string{spec.target}, spec.execVars...)...)
	r.Executed, r.ExitCode = true, rc
	for _, s := range spec.refusal {
		if !strings.Contains(out, s) {
			r.Findings = append(r.Findings, fmt.Sprintf(
				"отказа обязательного вызова на неверном входе нет (ждали «%s», код make %d): вызов не исполнился\n%s",
				s, rc, out))
			return
		}
	}
	if rc == 0 {
		r.Findings = append(r.Findings, fmt.Sprintf(
			"код вызова не доходит до кода цели: вызов отказал на неверном входе («%s»), а make вышел 0",
			strings.Join(spec.refusal, "» · «")))
	}
}

// makeExec исполняет make (не -n) и возвращает объединённый вывод и код.
// Отказ запуска make — «проверка НЕ ИСПОЛНЯЛАСЬ», ненулевой код — исход.
func makeExec(t *testing.T, root string, extra []string, args ...string) (string, int) {
	t.Helper()
	argv := []string{"-f", "Makefile"}
	for _, e := range extra {
		argv = append(argv, "-f", e)
	}
	argv = append(argv, args...)
	ctx, cancel := context.WithTimeout(t.Context(), notifyRecipeExecTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "make", argv...) // #nosec G204 -- argv[0] фиксирован, аргументы — цели и файлы пробы
	cmd.Dir = root
	cmd.Env = notifyRecipeEnv()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: make %s не уложился в %s\n%s", strings.Join(argv, " "), notifyRecipeExecTimeout, out)
	}
	var ee *exec.ExitError
	switch {
	case err == nil:
		return string(out), 0
	case errors.As(err, &ee) && ee.ExitCode() > 0:
		return string(out), ee.ExitCode()
	}
	t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: make %s — %v\n%s", strings.Join(argv, " "), err, out)
	return "", 0
}

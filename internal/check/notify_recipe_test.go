// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_recipe_test.go — тела целей NTF-1 по дереву kaname: `make -n
// notifications-check BASE=<база>` обязан печатать вызов генератора
// `notifygen -check -base <база>`, а `make -n notify-tree-gates` — прогон
// `go test` пакета internal/check с образцом `-run`, покрывающим КАЖДУЮ пробу
// перечня NOTIFY_TREE_GATES.
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ D08. Гейт D08 (`notify_wiring_test.go` →
// `treehygiene.AuditNotifyWiring`) судит, что конвейер ЗОВЁТ цели, а о самих
// целях спрашивает только «make -n выходит нулём и печатает непустое». Цель с
// телом `@echo ok` этому отвечает: конвейер зелёный, D08 зелёный, а сверка
// D07 не исполняется ни разу — измерено подменой тела на `@echo ok`
// (TestNTF1D08_* зелёные). Эта проба закрывает ровно этот участок: судит
// НАПЕЧАТАННЫЕ make команды, а не код возврата make.
//
// КАК СУДИТ. Вывод `make -n` режется на простые команды словами оболочки
// (кавычки, `\`-перенос, `$(…)`, операторы `;` `&&` `||` `|`, ведущие
// присваивания и служебные слова снимаются). Команда — это первое слово
// простой команды, поэтому `echo "go run … -check"` вызовом не является.
// Флаги генератора разбираются формами пакета flag: `-x`, `--x`, `-x=v`,
// `-x v` — переформатированная, но равносильная запись остаётся вызовом.
//
// База подаётся СТОРОЖЕВЫМ значением, а не HEAD^1: проба требует, чтобы в
// `-base` пришло именно поданное, — зашитая в тело ревизия здесь красная.
//
// Проба НЕ пропускается при -short: шаг `go test` конвейера идёт с -short.
package check_test

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// notifyRecipeBase — сторожевое значение BASE: ревизией оно не разрешается и
// в теле цели зашито быть не может, поэтому его появление в `-base` значит,
// что тело передаёт поданную базу.
const notifyRecipeBase = "ntf1-recipe-probe-base"

// notifyTreeGatesPkgs — законные записи пакета гейтов дерева в `go test`.
var notifyTreeGatesPkgs = []string{
	"./internal/check/", "./internal/check", "github.com/PRO-Robotech/kaname/internal/check",
}

// notifyPrintGatesTarget — служебная цель, печатающая перечень NOTIFY_TREE_GATES
// значением, развёрнутым самим make (форма объявления переменной не важна).
const notifyPrintGatesTarget = "ntf1-recipe-probe-print-gates"

// recipeReport — исход пробы тела одной цели.
type recipeReport struct {
	Target   string
	Lines    int      // строк вывода make -n
	Commands int      // простых команд после разбора
	Calls    int      // команд, признанных обязательным вызовом
	Findings []string // находки словами
}

func (r recipeReport) String() string {
	return fmt.Sprintf("тело цели %s: строк make -n %d · простых команд %d · обязательных вызовов %d · находок %d",
		r.Target, r.Lines, r.Commands, r.Calls, len(r.Findings))
}

// makeRun исполняет make в корне дерева с Makefile дерева и дополнительными
// файлами extra (порядок важен: позднее тело цели переопределяет раннее).
// Отказ make — «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка о теле.
func makeRun(t *testing.T, root string, extra []string, args ...string) string {
	t.Helper()
	argv := []string{"-f", "Makefile"}
	for _, e := range extra {
		argv = append(argv, "-f", e)
	}
	argv = append(argv, args...)
	cmd := exec.Command("make", argv...) // #nosec G204 -- argv[0] фиксирован, аргументы — цели и файлы пробы
	cmd.Dir = root
	cmd.Env = notifyRecipeEnv()
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: make %s — %v\n%s", strings.Join(argv, " "), err, stderr.String())
	}
	return stdout.String()
}

// notifyRecipeEnv — окружение без флагов вызывающего make: проба, запущенная
// из рецепта, иначе унаследовала бы его -n/-s/-k.
func notifyRecipeEnv() []string {
	var env []string
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		switch k {
		case "MAKEFLAGS", "MFLAGS", "MAKELEVEL", "MAKEOVERRIDES", "LC_ALL", "LANG":
			continue
		}
		env = append(env, kv)
	}
	return append(env, "LC_ALL=C", "LANG=C")
}

// notifyTreeGatesList — перечень NOTIFY_TREE_GATES, развёрнутый make дерева.
func notifyTreeGatesList(t *testing.T, root string, extra []string) []string {
	t.Helper()
	printer := filepath.Join(t.TempDir(), "print-gates.mk")
	body := notifyPrintGatesTarget + ":\n\t@echo $(NOTIFY_TREE_GATES)\n"
	if err := os.WriteFile(printer, []byte(body), 0o600); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	names := strings.Fields(makeRun(t, root, append(slices.Clone(extra), printer), "-s", notifyPrintGatesTarget))
	if len(names) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: перечень NOTIFY_TREE_GATES пуст — судить образец -run не по чему")
	}
	return names
}

// auditNotifyRecipes — исход пробы по обеим целям для Makefile дерева root и
// файлов-переопределений extra.
func auditNotifyRecipes(t *testing.T, root string, extra []string) []recipeReport {
	t.Helper()
	check := judgeRecipe("notifications-check",
		makeRun(t, root, extra, "-n", "notifications-check", "BASE="+notifyRecipeBase),
		func(cmd []string) (bool, string) { return isNotifygenCheck(cmd, notifyRecipeBase) },
		"вызова `notifygen -check -base "+notifyRecipeBase+"` нет — сверка D07 не исполняется")
	gates := notifyTreeGatesList(t, root, extra)
	tree := judgeRecipe("notify-tree-gates",
		makeRun(t, root, extra, "-n", "notify-tree-gates"),
		func(cmd []string) (bool, string) { return isTreeGatesRun(cmd, gates) },
		"вызова `go test ./internal/check/ -run <перечень>` нет — гейты дерева не исполняются")
	return []recipeReport{check, tree}
}

// judgeRecipe режет вывод make -n на простые команды и считает обязательные
// вызовы. Ровно один — норма; ноль — находка absent; больше одного — находка
// (проверка исполнялась бы дважды). Почти-вызовы (та же программа, не те
// аргументы) называются по отдельности.
func judgeRecipe(target, out string, match func([]string) (bool, string), absent string) recipeReport {
	r := recipeReport{Target: target, Lines: strings.Count(out, "\n")}
	cmds, err := shellCommands(out)
	if err != nil {
		r.Findings = append(r.Findings, "вывод make -n не разбирается словами оболочки: "+err.Error())
		return r
	}
	r.Commands = len(cmds)
	var near []string
	for _, c := range cmds {
		ok, why := match(c)
		switch {
		case ok:
			r.Calls++
		case why != "":
			near = append(near, why+" ("+strings.Join(c, " ")+")")
		}
	}
	switch {
	case r.Calls == 0:
		r.Findings = append(r.Findings, absent)
		r.Findings = append(r.Findings, near...)
	case r.Calls > 1:
		r.Findings = append(r.Findings, fmt.Sprintf("обязательный вызов печатается %d раз — ожидается ровно один", r.Calls))
	}
	return r
}

// isNotifygenCheck — `go run <notifygenPkg> … -check … -base <base>`.
func isNotifygenCheck(cmd []string, base string) (bool, string) {
	if len(cmd) < 3 || cmd[0] != "go" || cmd[1] != "run" {
		return false, ""
	}
	i := slices.Index(cmd[2:], notifygenPkg)
	if i < 0 {
		return false, ""
	}
	flags := goFlags(cmd[2+i+1:])
	if _, ok := flags["version"]; ok && len(flags) == 1 {
		return false, "" // строка версии — законная соседка, не почти-вызов
	}
	v, hasCheck := flags["check"]
	if !hasCheck || (v != "" && v != "true") {
		return false, "генератор вызван без -check"
	}
	b, hasBase := flags["base"]
	if !hasBase {
		return false, "генератор вызван без -base"
	}
	if b != base {
		return false, "-base не поданная база: " + b
	}
	return true, ""
}

// isTreeGatesRun — `go test … ./internal/check/ … -run <образец>`, где образец
// (его часть верхнего уровня, до первого `/`) совпадает с КАЖДЫМ именем перечня.
func isTreeGatesRun(cmd []string, gates []string) (bool, string) {
	if len(cmd) < 2 || cmd[0] != "go" || cmd[1] != "test" {
		return false, ""
	}
	if !slices.ContainsFunc(cmd[2:], func(w string) bool { return slices.Contains(notifyTreeGatesPkgs, w) }) {
		return false, ""
	}
	run, ok := goFlags(cmd[2:])["run"]
	if !ok || run == "" {
		return false, "go test пакета гейтов без -run"
	}
	top, _, _ := strings.Cut(run, "/")
	re, err := regexp.Compile(top)
	if err != nil {
		return false, "образец -run не компилируется: " + err.Error()
	}
	var missing []string
	for _, g := range gates {
		if !re.MatchString(g) {
			missing = append(missing, g)
		}
	}
	if len(missing) > 0 {
		return false, "образец -run не покрывает пробы перечня: " + strings.Join(missing, ", ")
	}
	return true, ""
}

// goFlags разбирает флаги формами пакета flag до первого не-флага или `--`:
// `-x`, `--x`, `-x=v`, `--x=v`, `-x v`. Значение без `=` берётся следующим
// словом только у флагов, известных как значимые; булев флаг даёт "".
func goFlags(args []string) map[string]string {
	valued := map[string]bool{"base": true, "run": true, "count": true, "timeout": true, "o": true,
		"tags": true, "p": true, "parallel": true, "skip": true, "coverprofile": true, "exec": true}
	out := map[string]string{}
	for j := 0; j < len(args); j++ {
		a := args[j]
		if a == "--" || !strings.HasPrefix(a, "-") || a == "-" {
			// go test принимает пакеты вперемешку с флагами: не-флаг пропускается,
			// а не обрывает разбор (у go run пакет стоит до флагов программы).
			continue
		}
		name, val, hasEq := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		switch {
		case hasEq:
			out[name] = val
		case valued[name] && j+1 < len(args):
			out[name] = args[j+1]
			j++
		default:
			out[name] = ""
		}
	}
	return out
}

// shellReserved — служебные слова, снимаемые в начале простой команды.
var shellReserved = map[string]bool{"{": true, "}": true, "!": true, "if": true, "then": true,
	"else": true, "elif": true, "fi": true, "do": true, "done": true, "while": true, "until": true}

var shellAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// shellCommands режет текст оболочки на простые команды (слова без кавычек).
func shellCommands(s string) ([][]string, error) {
	toks, err := shellLex(s)
	if err != nil {
		return nil, err
	}
	var cmds [][]string
	var cur []string
	flush := func() {
		for len(cur) > 0 && (shellReserved[cur[0]] || shellAssignment.MatchString(cur[0])) {
			cur = cur[1:]
		}
		if len(cur) > 0 {
			cmds = append(cmds, cur)
		}
		cur = nil
	}
	for _, tk := range toks {
		if tk.op {
			flush()
			continue
		}
		cur = append(cur, tk.text)
	}
	flush()
	return cmds, nil
}

type shellToken struct {
	text string
	op   bool
}

// shellLex — лексер оболочки в объёме вывода make -n: одинарные и двойные
// кавычки, `\`-экранирование и перенос строки, `$(…)` с вложенностью,
// комментарий с начала слова, операторы `;` `&` `&&` `|` `||` `(` `)` и
// перевод строки. Перенаправление `2>&1` остаётся словом.
func shellLex(s string) ([]shellToken, error) {
	var toks []shellToken
	var w strings.Builder
	inWord := false
	end := func() {
		if inWord {
			toks = append(toks, shellToken{text: w.String()})
		}
		w.Reset()
		inWord = false
	}
	r := []rune(s)
	for i := 0; i < len(r); i++ {
		c := r[i]
		switch {
		case c == '\\' && i+1 < len(r):
			i++
			if r[i] != '\n' {
				w.WriteRune(r[i])
				inWord = true
			}
		case c == ' ' || c == '\t':
			end()
		case c == '\n' || c == ';' || c == '(' || c == ')':
			end()
			toks = append(toks, shellToken{op: true, text: string(c)})
		case c == '&' && inWord && (strings.HasSuffix(w.String(), ">") || strings.HasSuffix(w.String(), "<")):
			w.WriteRune(c)
		case c == '&' || c == '|':
			end()
			if i+1 < len(r) && r[i+1] == c {
				i++
			}
			toks = append(toks, shellToken{op: true, text: string(c)})
		case c == '#' && !inWord:
			for i+1 < len(r) && r[i+1] != '\n' {
				i++
			}
		case c == '\'':
			j := i + 1
			for j < len(r) && r[j] != '\'' {
				j++
			}
			if j >= len(r) {
				return nil, fmt.Errorf("незакрытая одинарная кавычка")
			}
			w.WriteString(string(r[i+1 : j]))
			inWord, i = true, j
		case c == '"':
			j := i + 1
			for ; j < len(r) && r[j] != '"'; j++ {
				if r[j] == '\\' && j+1 < len(r) && strings.ContainsRune("\"\\$`\n", r[j+1]) {
					j++
					if r[j] != '\n' {
						w.WriteRune(r[j])
					}
					continue
				}
				w.WriteRune(r[j])
			}
			if j >= len(r) {
				return nil, fmt.Errorf("незакрытая двойная кавычка")
			}
			inWord, i = true, j
		case c == '$' && i+1 < len(r) && r[i+1] == '(':
			depth, j := 0, i+1
			for ; j < len(r); j++ {
				if r[j] == '(' {
					depth++
				} else if r[j] == ')' {
					depth--
					if depth == 0 {
						break
					}
				}
			}
			if j >= len(r) {
				return nil, fmt.Errorf("незакрытая подстановка $(")
			}
			w.WriteString(string(r[i : j+1]))
			inWord, i = true, j
		default:
			w.WriteRune(c)
			inWord = true
		}
	}
	end()
	return toks, nil
}

// TestNTF1Recipe_KanameMakeRunsTheNotifyCommands — тела целей NTF-1 в дереве
// kaname печатают ровно по одному обязательному вызову, находок ноль.
func TestNTF1Recipe_KanameMakeRunsTheNotifyCommands(t *testing.T) {
	root := notifyTreeRoot(t)
	for _, r := range auditNotifyRecipes(t, root, nil) {
		t.Log(r.String())
		if r.Lines == 0 || r.Commands == 0 {
			t.Fatalf("пустой обход — не вердикт: %s", r)
		}
		for _, f := range r.Findings {
			t.Errorf("тело цели %s · %s", r.Target, f)
		}
	}
}

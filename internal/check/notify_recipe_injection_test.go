// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_recipe_injection_test.go — проба тел целей NTF-1 доказана инъекцией в
// обе стороны на НАСТОЯЩЕМ Makefile дерева.
//
// Тело цели подменяется вторым файлом `make -f Makefile -f <подмена>.mk`:
// GNU make исполняет последнее объявленное тело цели и предупреждает о
// переопределении. Остальное — переменные, include, соседние цели — остаётся
// деревом, поэтому инъекция и близнец различаются ровно телом одной цели, а
// контроль (без подмены) — пробой по дереву в notify_recipe_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// recipeOverride пишет файл-подмену тела цели target строками lines.
func recipeOverride(t *testing.T, target string, lines ...string) string {
	t.Helper()
	return recipeOverrideWithHead(t, "", target, lines...)
}

// recipeOverrideWithHead — подмена тела, перед которой в файле стоит head
// (объявление специальной цели вроде `.IGNORE`); пустой head — без него.
func recipeOverrideWithHead(t *testing.T, head, target string, lines ...string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "override.mk")
	body := target + ":\n\t" + strings.Join(lines, "\n\t") + "\n"
	if head != "" {
		body = head + "\n" + body
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	return p
}

// recipeFindings — находки пробы по цели target при подмене override.
func recipeFindings(t *testing.T, override, target string) recipeReport {
	t.Helper()
	r := auditNotifyRecipe(t, notifyTreeRoot(t), []string{override}, target)
	t.Log(r.String())
	for _, f := range r.Findings {
		t.Log("находка: " + f)
	}
	return r
}

func TestNTF1Recipe_InjectionsInKanameAreFound(t *testing.T) {
	cases := []struct {
		name   string
		target string
		lines  []string
		want   string // подстрока ПЕРВОЙ находки; пусто — близнец, проба молчит
	}{
		{
			name:   "близнец: notifications-check — флаги переставлены, --base=, одинарные кавычки",
			target: "notifications-check",
			lines: []string{
				"@test -n \"$(BASE)\" || { echo 'УСЛОВИЕ НЕ СОЗДАНО'; exit 2; }",
				"$(NOTIFYGEN) -version",
				"go run github.com/PRO-Robotech/corelib/cmd/notifygen --base='$(BASE)' -check=true",
			},
		},
		{
			name:   "близнец: notify-tree-gates — флаги переставлены, пакет без косой черты, -run=",
			target: "notify-tree-gates",
			lines:  []string{"go test -count=1 -run='$(NOTIFY_TREE_GATES_RUN)' -v ./internal/check || exit 1"},
		},
		{
			name:   "(1) тело notifications-check — @echo ok",
			target: "notifications-check",
			lines:  []string{"@echo ok"},
			want:   "вызова `notifygen -check -base " + notifyRecipeBase + "` нет",
		},
		{
			name:   "(2) тело notify-tree-gates — @echo ok",
			target: "notify-tree-gates",
			lines:  []string{"@echo ok"},
			want:   "вызова `go test ./internal/check/ -run <перечень>` нет",
		},
		{
			name:   "(3) вызов генератора стал текстом echo",
			target: "notifications-check",
			lines:  []string{"@echo \"$(NOTIFYGEN) -check -base $(BASE)\""},
			want:   "вызова `notifygen -check -base",
		},
		{
			name:   "(4) база зашита в тело, поданная не доходит",
			target: "notifications-check",
			lines:  []string{"$(NOTIFYGEN) -check -base HEAD^1"},
			want:   "вызова `notifygen -check -base",
		},
		{
			name:   "(5) генератор зовётся без -check",
			target: "notifications-check",
			lines:  []string{"$(NOTIFYGEN) -base \"$(BASE)\""},
			want:   "вызова `notifygen -check -base",
		},
		{
			name:   "(6) образец -run теряет одну пробу перечня",
			target: "notify-tree-gates",
			lines:  []string{"go test ./internal/check/ -count=1 -v -run '^(TestNTF1B27Gate_OnKaname)$$'"},
			want:   "вызова `go test ./internal/check/ -run <перечень>` нет",
		},
		{
			name:   "(7) обязательный вызов печатается дважды",
			target: "notifications-check",
			lines:  []string{"$(NOTIFYGEN) -check -base \"$(BASE)\"", "$(NOTIFYGEN) -check -base \"$(BASE)\""},
			want:   "печатается 2 раз",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := recipeFindings(t, recipeOverride(t, c.target, c.lines...), c.target)
			if r.Commands == 0 {
				t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: make -n по подмене не напечатал ни одной команды: %s", r)
			}
			if c.want == "" {
				for _, f := range r.Findings {
					t.Errorf("близнец обязан молчать: %s", f)
				}
				if r.Calls != 1 {
					t.Errorf("близнец: обязательных вызовов %d, ожидается 1", r.Calls)
				}
				return
			}
			if len(r.Findings) == 0 || !strings.Contains(r.Findings[0], c.want) {
				t.Fatalf("ожидается находка %q, получено: %v", c.want, r.Findings)
			}
		})
	}
}

// TestNTF1Recipe_InjectionNearMissIsNamed — у инъекции (6) находка называет
// выпавшую пробу перечня по имени: причина, а не симптом.
func TestNTF1Recipe_InjectionNearMissIsNamed(t *testing.T) {
	r := recipeFindings(t, recipeOverride(t, "notify-tree-gates",
		"go test ./internal/check/ -count=1 -v -run '^(TestNTF1B27Gate_OnKaname)$$'"), "notify-tree-gates")
	joined := strings.Join(r.Findings, "\n")
	for _, missing := range []string{"TestNTF1B28Gate_OnKaname", "TestNTF1Gates_InjectionsInKanameAreFound"} {
		if !strings.Contains(joined, missing) {
			t.Errorf("находка не называет выпавшую пробу %s:\n%s", missing, joined)
		}
	}
	if strings.Contains(joined, "образец -run не покрывает пробы перечня: TestNTF1B27Gate_OnKaname") {
		t.Errorf("покрытая проба названа выпавшей:\n%s", joined)
	}
}

// Находки пробы распространения кода — подстроки, по которым инъекции ниже
// узнают свою причину.
const (
	findPrefixDash  = "префикс make «-» у строки обязательного вызова"
	findIgnore      = "цель названа в .IGNORE"
	findQuench      = "гаситель кода"
	findSetPlusE    = "`set +e` в строке обязательного вызова"
	findCodeLost    = "код вызова не доходит до кода цели"
	findNotDriven   = "исполнение не проверено"
	notifyCheckLine = `$(NOTIFYGEN) -check -base "$(BASE)"`
	treeGatesLine   = `go test ./internal/check/ -count=1 -v -run '$(NOTIFY_TREE_GATES_RUN)'`
)

// TestNTF1Recipe_ExitCodeInjectionsInKanameAreFound — вызов, НАПЕЧАТАННЫЙ
// make -n, ещё не значит, что его код доходит до кода цели. Каждая инъекция
// меняет против законной строки ровно один факт — гаситель кода; близнецы
// той же формы, но с кодом, доходящим до цели, молчат И исполняются.
//
// want — подстрока ПЕРВОЙ находки (чтение текста рецепта идёт раньше
// исполнения), alsoWant — подстроки, обязанные быть среди остальных находок
// (исполнение с заведомо неверным входом).
func TestNTF1Recipe_ExitCodeInjectionsInKanameAreFound(t *testing.T) {
	cases := []struct {
		name     string
		target   string
		head     string
		lines    []string
		want     string
		alsoWant []string
	}{
		// --- законные близнецы: молчат и исполняются, код цели ненулевой ---
		// Префикс «+» в близнец не берётся: строку с ним make исполняет и под -n.
		{name: "близнец: notifications-check — префикс @, отказ с exit 3",
			target: "notifications-check",
			lines:  []string{"@" + notifyCheckLine + " || { echo 'сверка красная'; exit 3; }"}},
		{name: "близнец: префикс «-» у строки версии, не у обязательного вызова",
			target: "notifications-check",
			lines:  []string{"-$(NOTIFYGEN) -version", notifyCheckLine}},
		{name: "близнец: `|| true` внутри подстановки, не после вызова",
			target: "notifications-check",
			lines:  []string{"v=$$(git rev-parse HEAD || true); " + notifyCheckLine}},
		{name: "близнец: `&& true` после вызова не гасит его код",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + " && true"}},
		{name: "близнец: .IGNORE называет чужую цель",
			target: "notifications-check", head: ".IGNORE: docker",
			lines: []string{notifyCheckLine}},
		{name: "близнец: notify-tree-gates — `|| exit 1`",
			target: "notify-tree-gates",
			lines:  []string{treeGatesLine + " || exit 1"}},

		// --- M1/M2 из вердикта check-verifier и остальные формы гасителя ---
		{name: "M1: `|| true` в конце строки вызова notifygen",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + " || true"},
			want:   findQuench + " `|| true`", alsoWant: []string{findCodeLost}},
		{name: "M2: префикс make «-» перед строкой вызова",
			target: "notifications-check",
			lines:  []string{"-" + notifyCheckLine},
			want:   findPrefixDash, alsoWant: []string{findCodeLost}},
		{name: "префикс «-» после «@»",
			target: "notifications-check",
			lines:  []string{"@-" + notifyCheckLine},
			want:   findPrefixDash, alsoWant: []string{findCodeLost}},
		{name: "`|| :` после вызова",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + " || :"},
			want:   findQuench + " `|| :`", alsoWant: []string{findCodeLost}},
		{name: "`|| exit 0` после вызова",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + " || exit 0"},
			want:   findQuench + " `|| exit 0`", alsoWant: []string{findCodeLost}},
		{name: "`; true` в конце строки вызова",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + "; true"},
			want:   findQuench + " `; true`", alsoWant: []string{findCodeLost}},
		{name: "`set +e` в строке вызова",
			target: "notifications-check",
			lines:  []string{"set +e; " + notifyCheckLine},
			want:   findSetPlusE},
		{name: ".IGNORE называет цель",
			target: "notifications-check", head: ".IGNORE: notifications-check",
			lines: []string{notifyCheckLine},
			want:  findIgnore, alsoWant: []string{findCodeLost}},
		{name: "труба после вызова — формы чтением нет, ловит исполнение",
			target: "notifications-check",
			lines:  []string{notifyCheckLine + " 2>&1 | cat"},
			want:   findCodeLost},
		{name: "notify-tree-gates: `|| true` после go test",
			target: "notify-tree-gates",
			lines:  []string{treeGatesLine + " || true"},
			want:   findQuench + " `|| true`", alsoWant: []string{findCodeLost}},
		{name: "notify-tree-gates: префикс «-» перед go test",
			target: "notify-tree-gates",
			lines:  []string{"-" + treeGatesLine},
			want:   findPrefixDash, alsoWant: []string{findCodeLost}},
		{name: "notify-tree-gates: образец -run зашит, поданный не доходит",
			target: "notify-tree-gates",
			lines:  []string{"go test ./internal/check/ -count=1 -v -run '.*'"},
			want:   findNotDriven},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := recipeFindings(t, recipeOverrideWithHead(t, c.head, c.target, c.lines...), c.target)
			if r.Commands == 0 || r.RecipeLines == 0 {
				t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: подмена не прочитана ни make -n, ни базой make: %s", r)
			}
			if c.want == "" {
				for _, f := range r.Findings {
					t.Errorf("близнец обязан молчать: %s", f)
				}
				if r.Calls != 1 || !r.Executed || r.ExitCode == 0 {
					t.Errorf("близнец обязан исполниться с ненулевым кодом цели: %s", r)
				}
				return
			}
			if len(r.Findings) == 0 || !strings.Contains(r.Findings[0], c.want) {
				t.Fatalf("ожидается первая находка %q, получено: %v", c.want, r.Findings)
			}
			for _, w := range c.alsoWant {
				if !slices.ContainsFunc(r.Findings[1:], func(f string) bool { return strings.Contains(f, w) }) {
					t.Errorf("ожидается находка %q, получено: %v", w, r.Findings)
				}
			}
		})
	}
}

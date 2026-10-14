// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config_test

// own_ceilings_prose_injection_test.go — гейт `TestOwnCeilingCountLivesOnlyInTheTable`
// доказан инъекцией в обе стороны на СИНТЕТИЧЕСКОМ дереве, а не на живом: живое
// дерево после правки чисто, и самопроверка на нём не могла бы упасть.
//
// Фразы дефекта собраны склейкой, чтобы этот файл сам не стал находкой гейта.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProseTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	return root
}

func proseVerdictOf(t *testing.T, root string, ex []ownCeilingProseExemption) []string {
	t.Helper()
	c, err := scanOwnCeilingProse(root, ex)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	return ownCeilingProseVerdict(c, ex, 4)
}

const (
	own3  = "СОБСТВЕННЫЕ " + "ТРИ" + " ПОТОЛКА"
	n3own = "ТРЁХ " + "СОБСТВЕННЫХ" + " ПОТОЛКОВ"
	svoi  = "Свои " + "три" + " потолка"
	herN  = "четыре " + "её собственных" + " потолка"
	enOwn = "four " + "own" + " ceilings"
	digit = "4 " + "собственных" + " потолка"
)

// Каждая законная форма дефекта находится и называет свою координату.
func TestOwnCeilingProseInjection_EveryDefectFormIsFoundWithItsCoordinate(t *testing.T) {
	cases := map[string]string{
		"cmd/svc/wiring.go":         "package main\n\n// " + own3 + " СЛУЖБЫ ОТСЮДА НЕ УХОДИЛИ\n",
		"internal/repo/x_test.go":   "package x\n\n// величина " + n3own + "\n",
		"docs/content/api/page.mdx": "# page\n\n" + svoi + " она по-прежнему считает.\n",
		"deploy/values.yaml":        "# " + herN + " объявляет посадка\nk: 1\n",
		"proto/x/v1/x.proto":        "// the service keeps " + enOwn + "\n",
		"docs/content/install/a.md": "Профиль объявляет " + digit + ".\n",
	}
	for rel, body := range cases {
		t.Run(rel, func(t *testing.T) {
			got := proseVerdictOf(t, writeProseTree(t, map[string]string{rel: body}), nil)
			if len(got) != 1 {
				t.Fatalf("ожидалась ровно одна находка, получено %d: %v", len(got), got)
			}
			if !strings.HasPrefix(got[0], rel+":") || !strings.Contains(got[0], "OwnCeilingKnobs") {
				t.Fatalf("находка не называет координату %s и таблицу: %s", rel, got[0])
			}
		})
	}
}

// Законный близнец той же формы молчит: потолки без числа, потолки фундамента с
// числом, число рядом с собственным потолком, но не о числе потолков.
func TestOwnCeilingProseInjection_LawfulTwinsAreSilent(t *testing.T) {
	root := writeProseTree(t, map[string]string{
		"cmd/svc/wiring.go": "package main\n\n// СОБСТВЕННЫЕ ПОТОЛКИ СЛУЖБЫ (перечень — таблица OwnCeilingKnobs)\n" +
			"// Две ручки, два потолка фундамента\n" +
			"// Близнец: 57014 от собственного потолка оператора на живом контексте\n",
		"docs/content/api/page.mdx": "Свои потолки служба считает; перечень — таблица.\n",
		"deploy/values.yaml":        "ownCeilings:\n  accessKeysPerUser: 3\n",
	})
	if got := proseVerdictOf(t, root, nil); len(got) != 0 {
		t.Fatalf("законный близнец дал находки: %v", got)
	}
}

// Исключение снимает находку в своём каталоге и только в нём; исключение, которому
// нечего исключать, — находка.
func TestOwnCeilingProseInjection_ExemptionIsScopedAndExpires(t *testing.T) {
	ex := []ownCeilingProseExemption{{Prefix: "internal/migrations/", Why: "ревизия"}}
	root := writeProseTree(t, map[string]string{
		"internal/migrations/1_x.sql": "-- " + n3own + "\n",
		"cmd/svc/main.go":             "package main\n\n// " + n3own + "\n",
	})
	got := proseVerdictOf(t, root, ex)
	if len(got) != 1 || !strings.HasPrefix(got[0], "cmd/svc/main.go:3:") {
		t.Fatalf("исключение обязано снять ровно миграцию, а не соседа: %v", got)
	}

	empty := writeProseTree(t, map[string]string{"cmd/svc/main.go": "package main\n"})
	got = proseVerdictOf(t, empty, ex)
	if len(got) != 1 || !strings.Contains(got[0], "нечего исключать") {
		t.Fatalf("исключение без предмета обязано стать находкой: %v", got)
	}
}

// Пустой обход — не зелёное.
func TestOwnCeilingProseInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	got := proseVerdictOf(t, t.TempDir(), nil)
	if len(got) != 1 || !strings.Contains(got[0], "вердикта нет") {
		t.Fatalf("пустой обход обязан падать, получено: %v", got)
	}
}

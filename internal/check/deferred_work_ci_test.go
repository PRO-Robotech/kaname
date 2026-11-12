// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"gopkg.in/yaml.v3"
)

const deferredRequiredPass = "github.com/PRO-Robotech/kaname/internal/check::TestNoDeferredWorkInTheTree"

// deferredUnitBody берёт исполняемый шаг unit из настоящего YAML. Комментарий
// с командой, отдельный необязательный шаг и другой job не заменяют этот шаг.
func deferredUnitBody(raw string) (string, error) {
	var doc struct {
		Jobs map[string]struct {
			Steps []struct {
				Run      string `yaml:"run"`
				If       any    `yaml:"if"`
				Continue any    `yaml:"continue-on-error"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return "", err
	}
	var selected []string
	for _, step := range doc.Jobs["unit"].Steps {
		wrapped, err := yaml.Marshal(map[string]any{"jobs": map[string]any{"unit": map[string]any{"steps": []map[string]string{{"run": step.Run}}}}})
		if err != nil {
			return "", err
		}
		bodies, _, err := check.ExecutableRunBodies(string(wrapped))
		if err != nil {
			return "", err
		}
		for _, body := range bodies {
			if !strings.Contains(body, "go test ") {
				continue
			}
			if step.If != nil || step.Continue != nil {
				return "", fmt.Errorf("шаг unit обязан быть без if и continue-on-error")
			}
			selected = append(selected, body)
		}
	}
	if len(selected) != 1 {
		return "", fmt.Errorf("ожидался один общий обязательный шаг unit, найдено %d", len(selected))
	}
	return selected[0], nil
}

// Запускается только shell настоящего шага с подставными go/python3. Подмена
// записывает реальные аргументы и вход прогонщика; сборка дочернего Go не нужна.
// Каждый из четырёх отказов обязан покрасить итог, но не снять соседнюю перепись.
func deferredPartitionFailure(t *testing.T, raw string) error {
	t.Helper()
	body, err := deferredUnitBody(raw)
	if err != nil {
		return err
	}
	dir := t.TempDir()
	scripts := map[string]string{
		"go": `#!/bin/bash
printf 'go %s\n' "$*" >> "$TRACE"
if [ "$2" = ./internal/check ]; then
 printf 'tree\n'
 exit "$TREE_GO"
fi
printf 'race\n'
exit "$RACE_GO"
`,
		"python3": `#!/bin/bash
input=$(cat)
printf 'verdict %s input=%s\n' "$*" "$input" >> "$TRACE"
if [ "$input" = tree ]; then exit "$TREE_VERDICT"; fi
exit "$RACE_VERDICT"
`,
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0700); err != nil {
			return err
		}
	}
	wantTrace := "go test ./internal/check -run ^TestNoDeferredWorkInTheTree$ -short -count=1 -timeout 4m -json\n" +
		"verdict .github/scripts/go-test-verdict.py --require-pass " + deferredRequiredPass + " input=tree\n" +
		"go test ./... -race -short -count=1 -timeout 45m -skip ^TestNoDeferredWorkInTheTree$ -json\n" +
		"verdict .github/scripts/go-test-verdict.py input=race\n"
	cases := [][4]int{{0, 0, 0, 0}, {7, 0, 0, 0}, {0, 8, 0, 0}, {0, 0, 9, 0}, {0, 0, 0, 10}, {7, 8, 9, 10}}
	for _, rc := range cases {
		trace := filepath.Join(dir, "trace")
		if err := os.WriteFile(trace, nil, 0600); err != nil {
			return err
		}
		cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", body)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TRACE="+trace,
			fmt.Sprintf("TREE_GO=%d", rc[0]), fmt.Sprintf("TREE_VERDICT=%d", rc[1]), fmt.Sprintf("RACE_GO=%d", rc[2]), fmt.Sprintf("RACE_VERDICT=%d", rc[3]))
		output, runErr := cmd.CombinedOutput()
		got, err := os.ReadFile(trace)
		if err != nil {
			return err
		}
		if string(got) != wantTrace {
			return fmt.Errorf("коды %v: команды/аргументы/входы переписей расходятся:\n%s", rc, got)
		}
		if (runErr == nil) != (rc == [4]int{}) {
			return fmt.Errorf("коды %v: итог shell=%v; %s", rc, runErr, output)
		}
		tree, err := os.ReadFile(filepath.Join(dir, "deferred-tree.json"))
		if err != nil || string(tree) != "tree\n" {
			return fmt.Errorf("отдельный deferred-tree.json не сохранён: %v", err)
		}
		race, err := os.ReadFile(filepath.Join(dir, "test.json"))
		if err != nil || string(race) != "race\n" {
			return fmt.Errorf("отдельный test.json не сохранён: %v", err)
		}
	}
	return nil
}

func deferredCIWorkflow(t *testing.T) string {
	t.Helper()
	root, prefix := platformtree.RequireCorpus(t)
	raw, err := os.ReadFile(filepath.Join(root, prefix, ".github/workflows/ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestDeferredWorkCIShortPartition(t *testing.T) {
	if err := deferredPartitionFailure(t, deferredCIWorkflow(t)); err != nil {
		t.Fatal(err)
	}
	root, prefix := platformtree.RequireCorpus(t)
	raw, err := os.ReadFile(filepath.Join(root, prefix, ".github/ci-paths.json"))
	if err != nil {
		t.Fatal(err)
	}
	var paths struct {
		Groups []struct{ Jobs, Paths []string }
	}
	if err := json.Unmarshal(raw, &paths); err != nil {
		t.Fatal(err)
	}
	universal := false
	for _, group := range paths.Groups {
		unit, all := false, false
		for _, job := range group.Jobs {
			unit = unit || job == "ci.yml:unit"
		}
		for _, path := range group.Paths {
			all = all || path == "**"
		}
		universal = universal || (unit && all)
	}
	if !universal {
		t.Fatal("unit обязан выбираться для любого пути через **")
	}
	t.Log("перепись: обязательный шаг unit 1; группы 2; сочетаний кодов 6; отдельные JSON 2; выбор unit для ** подтверждён")
}

func TestDeferredWorkCIShortPartitionInjections(t *testing.T) {
	raw := deferredCIWorkflow(t)
	cases := []struct{ name, old, new string }{
		{"нет полного обхода", "go test ./internal/check", "echo test ./internal/check"},
		{"неверный пакет", "go test ./internal/check", "go test ./internal/other"},
		{"расширенный пропуск", "-skip '^TestNoDeferredWorkInTheTree$'", "-skip 'TestNoDeferredWork'"},
		{"нет обязательного прохода", " --require-pass '" + deferredRequiredPass + "'", ""},
		{"код Go скрыт", "|| tree_go_rc=$?", "|| true"},
		{"код вердикта скрыт", "|| race_verdict_rc=$?", "|| true"},
		{"один код не влияет на итог", `[ "$tree_verdict_rc" -ne 0 ]`, `[ 0 -ne 0 ]`},
		{"обход ошибочно под race", "go test ./internal/check", "go test ./internal/check -race"},
		{"шаг необязателен", "- name: пробы (-race -short и отдельный полный обход дерева)", "- if: success()\n        name: пробы (-race -short и отдельный полный обход дерева)"},
		{"отказ шага разрешён", "- name: пробы (-race -short и отдельный полный обход дерева)", "- continue-on-error: true\n        name: пробы (-race -short и отдельный полный обход дерева)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.Count(raw, tc.old) != 1 {
				t.Fatalf("предпосылка инъекции: ожидается одно место %q", tc.old)
			}
			changed := strings.Replace(raw, tc.old, tc.new, 1)
			if err := deferredPartitionFailure(t, changed); err == nil {
				t.Fatal("инъекция не обнаружена")
			}
		})
	}
}

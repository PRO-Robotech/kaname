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

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	"gopkg.in/yaml.v3"
)

// Проверяем настоящий DAG и исполняем shell обязательного агрегата. Аргументы
// Go и потоки canonical verifier отдельно проверяет TestRunUnitPartition.
func deferredUnitBodies(raw string) (map[string]string, error) {
	var doc struct {
		Jobs map[string]struct {
			Needs   []string `yaml:"needs"`
			If      string   `yaml:"if"`
			Name    string   `yaml:"name"`
			Timeout int      `yaml:"timeout-minutes"`
			Steps   []struct {
				Run      string            `yaml:"run"`
				If       any               `yaml:"if"`
				Continue any               `yaml:"continue-on-error"`
				Env      map[string]string `yaml:"env"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, err
	}
	selected := make(map[string]string)
	condition := "${{ needs.changes.outputs.full == 'true' || contains(fromJSON(needs.changes.outputs.jobs || '[]'), 'unit') }}"
	for _, part := range []string{"main", "census", "aggregate"} {
		jobID := "unit" + part
		if part == "aggregate" {
			jobID = "unit"
		}
		job := doc.Jobs[jobID]
		wantNeeds, wantIf := "changes", strings.Replace(condition, "'unit'", "'"+jobID+"'", 1)
		if part == "aggregate" {
			wantNeeds = "changes,unitmain,unitcensus"
			wantIf = "${{ always() && (needs.changes.outputs.full == 'true' || contains(fromJSON(needs.changes.outputs.jobs || '[]'), 'unit')) }}"
			if job.Name != "пробы -race -short (числовой вердикт)" {
				return nil, fmt.Errorf("потерян обязательный контекст unit")
			}
		}
		if strings.Join(job.Needs, ",") != wantNeeds || job.If != wantIf || job.Timeout != 90 {
			return nil, fmt.Errorf("неверные зависимости, условие или бюджет %s", jobID)
		}
		for _, step := range job.Steps {
			if !strings.Contains(step.Run, "run-unit.py") {
				continue
			}
			if selected[part] != "" || step.Continue != nil {
				return nil, fmt.Errorf("повтор/необязательный шаг %s", jobID)
			}
			if part != "aggregate" {
				want := "python3 .github/scripts/run-unit.py " + part + " ci-test-evidence/unit/" + part
				if step.If != nil || step.Run != want {
					return nil, fmt.Errorf("изменён обязательный запуск %s", jobID)
				}
			} else if step.If != "always()" || step.Env["MAIN_RESULT"] != "${{ needs.unitmain.result }}" || step.Env["CENSUS_RESULT"] != "${{ needs.unitcensus.result }}" {
				return nil, fmt.Errorf("агрегат не получает фактические результаты обеих частей")
			}
			selected[part] = step.Run
		}
		if selected[part] == "" {
			return nil, fmt.Errorf("нет обязательного запуска %s", jobID)
		}
	}
	return selected, nil
}

func deferredPartitionFailure(t *testing.T, raw string) error {
	t.Helper()
	bodies, err := deferredUnitBodies(raw)
	if err != nil {
		return err
	}
	dir := t.TempDir()
	script := "#!/bin/bash\nprintf '%s\\n' \"$*\" >> \"$TRACE\"\nexit \"$ACTUAL_RC\"\n"
	if err := os.WriteFile(filepath.Join(dir, "python3"), []byte(script), 0700); err != nil {
		return err
	}
	cases := []struct {
		main, census, aggregate  int
		mainStatus, censusStatus string
	}{
		{0, 0, 0, "success", "success"}, {7, 0, 0, "failure", "success"},
		{0, 8, 0, "success", "failure"}, {0, 0, 9, "success", "success"},
		{7, 8, 9, "failure", "failure"}, {0, 0, 0, "skipped", "success"},
		{0, 0, 0, "success", "cancelled"}, {0, 0, 0, "", "success"},
	}
	for _, tc := range cases {
		trace := filepath.Join(dir, "trace")
		if err := os.WriteFile(trace, nil, 0600); err != nil {
			return err
		}
		for i, part := range []string{"main", "census", "aggregate"} {
			codes := []int{tc.main, tc.census, tc.aggregate}
			cmd := exec.Command("bash", "--noprofile", "--norc", "-e", "-o", "pipefail", "-c", bodies[part])
			cmd.Dir = dir
			cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"), "TRACE="+trace,
				fmt.Sprintf("ACTUAL_RC=%d", codes[i]), "MAIN_RESULT="+tc.mainStatus, "CENSUS_RESULT="+tc.censusStatus)
			output, runErr := cmd.CombinedOutput()
			wantOK := codes[i] == 0
			if part == "aggregate" {
				wantOK = wantOK && tc.mainStatus == "success" && tc.censusStatus == "success"
			}
			if (runErr == nil) != wantOK {
				return fmt.Errorf("часть %s, коды %+v: %v; %s", part, tc, runErr, output)
			}
		}
		got, err := os.ReadFile(trace)
		if err != nil {
			return err
		}
		want := ".github/scripts/run-unit.py main ci-test-evidence/unit/main\n.github/scripts/run-unit.py census ci-test-evidence/unit/census\n.github/scripts/run-unit.py aggregate ci-test-evidence/unit\n"
		if string(got) != want {
			return fmt.Errorf("запуски потеряны или подменены: %s", got)
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
	t.Log("перепись: независимые части 2; обязательный агрегат 1; сочетаний кодов/статусов 8; выбор unit для ** подтверждён")
}

func TestDeferredWorkCIShortPartitionInjections(t *testing.T) {
	raw := deferredCIWorkflow(t)
	cases := []struct{ name, old, new string }{
		{"нет основной части", "python3 .github/scripts/run-unit.py main", "echo .github/scripts/run-unit.py main"},
		{"нет Census", "python3 .github/scripts/run-unit.py census", "echo .github/scripts/run-unit.py census"},
		{"часть зависит от соседа", "needs: [changes]\n    name: unit — Census 11", "needs: [changes, unitmain]\n    name: unit — Census 11"},
		{"агрегат теряет часть", "needs: [changes, unitmain, unitcensus]", "needs: [changes, unitmain]"},
		{"код переписи скрыт", "python3 .github/scripts/run-unit.py aggregate ci-test-evidence/unit || rc=$?", "python3 .github/scripts/run-unit.py aggregate ci-test-evidence/unit || true"},
		{"результат main скрыт", `[ "$MAIN_RESULT" != success ]`, `[ success != success ]`},
		{"результат Census скрыт", `[ "$CENSUS_RESULT" != success ]`, `[ success != success ]`},
		{"неверный результат job", "MAIN_RESULT: ${{ needs.unitmain.result }}", "MAIN_RESULT: success"},
		{"агрегат необязателен", "- name: обязательное объединение compiled inventory и фактических событий", "- continue-on-error: true\n        name: обязательное объединение compiled inventory и фактических событий"},
		{"подмена обязательного имени", "name: пробы -race -short (числовой вердикт)", "name: необязательная перепись"},
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

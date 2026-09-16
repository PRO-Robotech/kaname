// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// chart_raise_has_a_holder_test.go — ПОДЪЁМ ЧАРТА ДЕРЖИТ ЗАДАНИЕ КОНВЕЙЕРА, а
// не память о том, что однажды его поднимали руками.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// `security.md` §«Production-mode», п. 3 требует ПАРУ: `values.prod` обязан
// реально подниматься, а не только рендериться. Рендер держит страж
// (`deploy/render-guard.sh`), подъём — не держал НИКТО: задание монорепо снято
// вместе с выносом службы, а рецепт продолжал называть его существующим.
//
// Класс, ради которого гейт заведён, назван в корпусе прямо: чарт, который
// рендерится и НЕ ПОДНИМАЕТСЯ, — отдельный дефект, и рендер-зелёный его не
// видит by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР СУДИТ ИСПОЛНЯЕМУЮ ЧАСТЬ, А НЕ ТЕКСТ
//
// Имя скрипта стоит в этом дереве и в ПРОЗЕ — в шапке самого скрипта, в
// комментариях процессов, в этом файле. Предикат по подстроке краснел бы на
// собственном объяснении и зеленел бы на задании, которое скрипт лишь упоминает.
// Поэтому процессы читаются РАЗОБРАННЫМ YAML, а внутри тела `run:` строка
// считается вызовом, только если она не комментарий.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он не утверждает, что подъём ПРОШЁЛ: это свойство прогона, а не дерева.
// Он утверждает, что у подъёма есть ПРОИЗВОДИТЕЛЬ и что его исход читается
// тремя категориями, — то есть что «условие не создано» не будет подано
// вердиктом о дереве.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// chartStandScript — координата подъёмщика, от корня дерева.
const chartStandScript = ".github/scripts/stand-chart.sh"

// workflowsDirRel — где лежат процессы конвейера.
const workflowsDirRel = ".github/workflows"

// raiseCensus — объём осмотренного. Печатается ВСЕГДА: «находок ноль» обязано
// быть отличимо от «прочитано ноль».
type raiseCensus struct {
	Files    int
	Jobs     int
	Steps    int
	UpCalls  int
	Asserts  int
	Teardown int
	// Unmet — шагов подъёма, чей разбор исхода отличает «условие не создано».
	Unmet int
}

// auditChartRaise — предикат. Возвращает находки и перепись; пустые находки при
// непустой переписи означают «держатель есть».
func auditChartRaise(workflows map[string]string) ([]string, raiseCensus, error) {
	var c raiseCensus
	var found []string

	for name, body := range workflows {
		c.Files++
		var doc struct {
			Jobs map[string]struct {
				Steps []struct {
					Name string `yaml:"name"`
					Run  string `yaml:"run"`
				} `yaml:"steps"`
			} `yaml:"jobs"`
		}
		if err := yaml.Unmarshal([]byte(body), &doc); err != nil {
			return nil, c, err
		}
		for job, j := range doc.Jobs {
			c.Jobs++
			for _, st := range j.Steps {
				c.Steps++
				for _, verb := range callVerbs(st.Run) {
					switch verb {
					case "up":
						c.UpCalls++
						if !distinguishesUnmet(st.Run) {
							found = append(found, name+": задание "+job+", шаг «"+st.Name+
								"» зовёт подъём и НЕ отличает «условие не создано» (код 75) от находки: "+
								"неподнявшийся кластер был бы подан вердиктом о дереве")
						} else {
							c.Unmet++
						}
					case "assert":
						c.Asserts++
					case "down":
						c.Teardown++
					}
				}
			}
		}
	}
	return found, c, nil
}

// callVerbs — команды подъёмщика, ВЫЗВАННЫЕ телом шага.
//
// Строка-комментарий вызовом не является: иначе гейт зеленел бы на задании,
// которое скрипт лишь упоминает, — и краснел бы на объяснении самого себя.
func callVerbs(run string) []string {
	var out []string
	for _, line := range strings.Split(run, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, chartStandScript)
		if idx < 0 {
			continue
		}
		rest := strings.Fields(line[idx+len(chartStandScript):])
		if len(rest) == 0 {
			continue
		}
		out = append(out, strings.Trim(rest[0], "\"'"))
	}
	return out
}

// distinguishesUnmet — отличает ли разбор исхода третью категорию.
//
// Признак — ветвь по коду 75 в разборе шага. Его отсутствие означает, что
// неподнявшийся кластер доедет красным как находка о дереве.
func distinguishesUnmet(run string) bool {
	for _, line := range strings.Split(run, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") {
			continue
		}
		if strings.HasPrefix(t, "75)") || strings.Contains(t, " 75)") {
			return true
		}
	}
	return false
}

// readWorkflows — процессы дерева. Пустая карта — отказ у вызывающего.
func readWorkflows(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог процессов %s не прочитан: %v", dir, err)
	}
	out := map[string]string{}
	for _, e := range entries {
		if e.IsDir() || (!strings.HasSuffix(e.Name(), ".yml") && !strings.HasSuffix(e.Name(), ".yaml")) {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь собран из корня собственного дерева
		if rerr != nil {
			t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s не прочитан: %v", e.Name(), rerr)
		}
		out[e.Name()] = string(raw)
	}
	return out
}

// TestChartRaiseIsHeldByAPipelineJob — гейт по дереву.
func TestChartRaiseIsHeldByAPipelineJob(t *testing.T) {
	root := serviceRootFrom(mustWDForChart(t))
	if root == "" {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень дерева не установлен")
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(chartStandScript))); err != nil {
		t.Fatalf("подъёмщика %s в дереве нет (%v): держателю нечем поднимать, и гейт "+
			"судил бы отсутствие своего же предмета", chartStandScript, err)
	}

	workflows := readWorkflows(t, filepath.Join(root, filepath.FromSlash(workflowsDirRel)))
	found, census, err := auditChartRaise(workflows)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: процесс не разобран: %v", err)
	}

	t.Logf("перепись: процессов прочитано %d · заданий %d · шагов %d · вызовов подъёма %d "+
		"(из них отличают «условие не создано» %d) · сверок посадки %d · сносов %d",
		census.Files, census.Jobs, census.Steps, census.UpCalls, census.Unmet,
		census.Asserts, census.Teardown)

	if census.Files == 0 || census.Steps == 0 {
		t.Fatalf("обход пуст: процессов %d, шагов %d — вердикта о держателе нет",
			census.Files, census.Steps)
	}
	if census.UpCalls == 0 {
		t.Fatalf("подъём чарта не зовёт НИ ОДНО задание конвейера: `values.prod` обязан " +
			"реально подниматься (security.md §«Production-mode», п. 3), а рендер-зелёный " +
			"чарта, который не поднимается, не видит by construction")
	}
	if census.Asserts == 0 {
		t.Fatalf("подъём зовут, а посадку не сверяет никто: «под Ready» доказательством " +
			"посадки НЕ является — процесс мог подняться в другой")
	}
	if census.Teardown == 0 {
		t.Fatalf("снос стенда не зовёт ни одно задание: обрыв по пределу времени оставил бы " +
			"кластер поднятым")
	}
	if len(found) > 0 {
		t.Fatalf("исход подъёма разобран неверно:\n  %s", strings.Join(found, "\n  "))
	}
}

func mustWDForChart(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	return wd
}

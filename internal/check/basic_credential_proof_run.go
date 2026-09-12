// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_proof_run.go — доказательство формы базового удостоверения
// обязано ПРОИЗВОДИТЬСЯ ПРОГОНОМ, а не просто лежать в дереве
// (`PRO-Robotech/kacho#1253`).
//
// Порт с монорепо (`internal/repohygiene/basiccredentialproofrun_test.go`,
// снят вынесением службы — `kacho#2597`). Осталось дословно: имя функции
// гейта, сам разбор `run:`-тел workflow и текст находки. Изменилось: пути без
// префикса `services/iam/`, конвейер — `.github/workflows/` СВОЕГО репозитория.
//
// # Предмет
//
// Во всём сквозном прогоне не было НИ ОДНОГО зелёного утверждения, читающего
// секрет базового удостоверения из УСПЕШНОГО ответа. Проверка, которую никто
// не зовёт, ничего не производит: её зелёное существует только в чужой
// голове.
//
// # Читается ИСПОЛНЯЕМАЯ часть, а не текст
//
// YAML разбирается, берутся тела `run:`, и из них выбрасываются строки
// оболочечных комментариев. Гейт по подстроке краснел бы на собственном
// объяснении и зеленел бы на шаге, откуда вызов сняли, а комментарий оставили.
package check

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// runBodiesDoc — то немногое из workflow, что нужно этому гейту.
type runBodiesDoc struct {
	Jobs map[string]struct {
		Steps []struct {
			Name string `yaml:"name"`
			Run  string `yaml:"run"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

// ExecutableRunBodies — тела `run:` без строк оболочечных комментариев.
func ExecutableRunBodies(raw string) ([]string, int, error) {
	var doc runBodiesDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, 0, err
	}
	var out []string
	steps := 0
	for _, job := range doc.Jobs {
		for _, st := range job.Steps {
			if strings.TrimSpace(st.Run) == "" {
				continue
			}
			steps++
			var code []string
			for _, ln := range strings.Split(st.Run, "\n") {
				if strings.HasPrefix(strings.TrimSpace(ln), "#") {
					continue
				}
				code = append(code, ln)
			}
			out = append(out, strings.Join(code, "\n"))
		}
	}
	return out, steps, nil
}

// InvocationsOf — сколько тел `run:` действительно зовут названный скрипт.
func InvocationsOf(script string, bodies []string) int {
	n := 0
	for _, b := range bodies {
		if strings.Contains(b, script) {
			n++
		}
	}
	return n
}

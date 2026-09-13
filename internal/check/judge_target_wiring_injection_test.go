// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// judge_target_wiring_injection_test.go — доказательство, что гейт провязки
// судьи СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейства
// `modulemanifestcheckwiring` и `modelcanoncheckwiring`).
//
// Фикстура ОДНА на оба семейства намеренно: они различаются именем цели, а не
// механизмом, и второе доказательство копией разошлось бы с первым молча.
//
// # Законный близнец у КАЖДОЙ оси
//
// Односторонняя проверка зеленела бы на дереве, где сломано всё сразу. Поэтому
// рядом с каждой находкой стоит вход той же формы, на котором гейт обязан
// МОЛЧАТЬ: вызов, записанный исполняемой строкой, и цель, о которой носитель
// лишь написал прозой.
//
// # Каждая инъекция меняет РОВНО ОДИН факт против своего близнеца
//
// Иначе неизвестно, который из двух дал красное, и вердикт недействителен,
// выглядя обычным зелёным.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// judgeWiringTree — синтетическое дерево: корневой рецепт и задания конвейера.
type judgeWiringTree struct {
	makefile  string
	workflows map[string]string
}

// build — раскладывает дерево во временном каталоге пробы.
func (tr judgeWiringTree) build(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(tr.makefile), 0o600); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	wf := filepath.Join(root, ".github", "workflows")
	if err := os.MkdirAll(wf, 0o750); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	for name, body := range tr.workflows {
		if err := os.WriteFile(filepath.Join(wf, name), []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
	}
	return root
}

// declaringMakefile — рецепт, ОБЪЯВЛЯЮЩИЙ обе цели, вместе с прозой, которая их
// объясняет: в настоящем рецепте имя цели стоит и в шапке, и примером вызова.
const declaringMakefile = `# module-manifest-check — форму манифеста домена судит ОДИН исполнитель.
# Вызов: ` + "`make module-manifest-check`" + `
.PHONY: module-manifest-check
## module-manifest-check — форма манифеста каждого модуля дерева
module-manifest-check:
	@./tools/module-manifest-check.sh

.PHONY: model-canon-check
## model-canon-check — блоки модели сверяются с манифестами [монорепо]
model-canon-check:
	@./tools/model-canon-check.sh
`

// callingWorkflow — носитель, зовущий обе цели ИСПОЛНЯЕМОЙ строкой.
const callingWorkflow = `jobs:
  authz-artifacts:
    steps:
      - name: манифесты модулей — форму судит один загрузчик
        run: |
          rc=0
          make module-manifest-check || rc=$?
      - name: канон модели
        run: |
          rc=0
          make model-canon-check MONOREPO_ROOT="$GITHUB_WORKSPACE/upstream" || rc=$?
`

// intactTree — полностью провязанное дерево: контроль для всех осей.
func intactTree() judgeWiringTree {
	return judgeWiringTree{
		makefile:  declaringMakefile,
		workflows: map[string]string{"ci.yml": callingWorkflow},
	}
}

// judgeWiringFaultsOn — находки гейта по ОДНОЙ цели на синтетическом дереве.
func judgeWiringFaultsOn(t *testing.T, target string, tr judgeWiringTree) []string {
	t.Helper()
	w, err := check.ReadJudgeTargetWiring(tr.build(t), target)
	if err != nil {
		t.Fatalf("фикстура не прочитана: %v", err)
	}
	return check.JudgeTargetWiringFaults(w)
}

// TestJudgeTargetWiringGate_Injection — обе способности по каждой оси.
func TestJudgeTargetWiringGate_Injection(t *testing.T) {
	t.Parallel()

	both := []string{ModuleManifestCheckTarget, ModelCanonCheckTarget}

	// ── КОНТРОЛЬ: всё цело — гейт обязан молчать ────────────────────────────
	//
	// Стоит первым и не формальность: без него всякая находка ниже объяснялась
	// бы гейтом, который краснеет на любом входе.
	for _, target := range both {
		if got := judgeWiringFaultsOn(t, target, intactTree()); len(got) != 0 {
			t.Fatalf("КОНТРОЛЬ (%s): на провязанном дереве гейт нашёл %d — он краснеет на "+
				"исправном входе, и ни одна находка ниже ничего не доказывает:\n  %s",
				target, len(got), strings.Join(got, "\n  "))
		}
	}
	t.Log("контроль: провязанное дерево — 0 находок по обеим целям")

	// ── ОСЬ 1: конвейер цель не зовёт ──────────────────────────────────────
	//
	// Меняется ровно один факт против контроля: из тела `run:` убран вызов.
	// Вторая цель остаётся званой — иначе неизвестно, о которой из двух красное.
	for _, target := range both {
		tr := intactTree()
		tr.workflows = map[string]string{"ci.yml": strings.ReplaceAll(
			callingWorkflow, "make "+target, "go build ./...")}
		got := judgeWiringFaultsOn(t, target, tr)
		if len(got) != 1 {
			t.Fatalf("ось «конвейер не зовёт» (%s): ожидалась ровно 1 находка, получено %d:\n  %s",
				target, len(got), strings.Join(got, "\n  "))
		}
		if !strings.Contains(got[0], target) || !strings.Contains(got[0], "НИ ОДИН шаг конвейера") {
			t.Errorf("находка не называет предмет и цель: %s", got[0])
		}
		// Соседняя цель звана — на ней гейт обязан молчать. Без этой половины
		// красное могло бы приходить от общего сбоя разбора.
		other := ModelCanonCheckTarget
		if target == ModelCanonCheckTarget {
			other = ModuleManifestCheckTarget
		}
		if rest := judgeWiringFaultsOn(t, other, tr); len(rest) != 0 {
			t.Errorf("инъекция задела СОСЕДНЮЮ цель %s (%d находок) — красное пришло не от "+
				"проверяемого факта:\n  %s", other, len(rest), strings.Join(rest, "\n  "))
		}
		t.Logf("инъекция «конвейер не зовёт» (%s): 1 находка, соседняя цель молчит", target)
	}

	// ── ОСЬ 2: ПРОЗА вместо провязки ───────────────────────────────────────
	//
	// Несущая ось. Имя цели встречается в комментариях, которые её же объясняют,
	// и гейт, ищущий имя подстрокой, зеленел бы на собственном объяснении —
	// оставаясь зелёным при СНЯТОЙ провязке.
	{
		tr := intactTree()
		tr.workflows = map[string]string{"ci.yml": `jobs:
  authz-artifacts:
    steps:
      - name: что-то другое
        run: |
          # здесь когда-то звали: make module-manifest-check
          # и рядом: make model-canon-check
          go build ./...
`}
		for _, target := range both {
			got := judgeWiringFaultsOn(t, target, tr)
			if len(got) != 1 {
				t.Fatalf("ось «проза вместо провязки» (%s): ожидалась 1 находка, получено %d — "+
					"гейт зачёл комментарий за вызов и остался бы зелёным при снятой провязке:\n  %s",
					target, len(got), strings.Join(got, "\n  "))
			}
		}
		t.Log("инъекция «проза вместо провязки»: комментарий за вызов НЕ зачтён ни по одной цели")
	}

	// ── ОСЬ 3: имя цели в НЕИСПОЛНЯЕМОМ поле шага ─────────────────────────
	//
	// Комментарием такая строка не является — её не отбросил бы текстовый обход,
	// — а вызовом не становится: заголовок шага и его условие не исполняет ничто.
	// Отличить это от провязки умеет только разбор.
	{
		tr := intactTree()
		tr.workflows = map[string]string{"ci.yml": `jobs:
  authz-artifacts:
    steps:
      - name: 'снято: make module-manifest-check'
        if: "contains('make model-canon-check', 'x')"
        run: go build ./...
`}
		for _, target := range both {
			got := judgeWiringFaultsOn(t, target, tr)
			if len(got) != 1 {
				t.Fatalf("ось «имя цели в неисполняемом поле» (%s): ожидалась 1 находка, "+
					"получено %d — гейт зачёл заголовок шага за вызов:\n  %s",
					target, len(got), strings.Join(got, "\n  "))
			}
		}
		t.Log("инъекция «имя цели в заголовке шага и в условии»: за вызов НЕ зачтено")
	}

	// ── ОСЬ 4: обратное направление — зовут цель, которой рецепт не объявляет ─
	//
	// Без этой оси гейт был бы односторонним и пропускал бы провязку в пустоту:
	// шаг зовёт имя, которого в рецепте нет, и выглядит исполненным.
	{
		tr := intactTree()
		tr.makefile = "# провязка снята вместе с целями\n.PHONY: build\nbuild:\n\tgo build ./...\n"
		for _, target := range both {
			got := judgeWiringFaultsOn(t, target, tr)
			if len(got) != 1 {
				t.Fatalf("ось «зовут необъявленную цель» (%s): ожидалась 1 находка, получено %d:\n  %s",
					target, len(got), strings.Join(got, "\n  "))
			}
			if !strings.Contains(got[0], "позеленеет ни на чём") {
				t.Errorf("обратное направление не сработало (%s): %s", target, got[0])
			}
		}
		t.Log("инъекция «зовут необъявленную цель»: обратное направление названо")
	}

	// ── ОСЬ 5: ни объявления, ни вызова — распознавание сломано либо цель сняли ─
	{
		tr := judgeWiringTree{
			makefile:  "build:\n\tgo build ./...\n",
			workflows: map[string]string{"ci.yml": "jobs:\n  x:\n    steps:\n      - run: go build ./...\n"},
		}
		for _, target := range both {
			got := judgeWiringFaultsOn(t, target, tr)
			if len(got) != 1 || !strings.Contains(got[0], "распознавание сломано") {
				t.Fatalf("ось «ни объявления, ни вызова» (%s): ожидалась 1 находка с этим "+
					"предметом, получено %d:\n  %s", target, len(got), strings.Join(got, "\n  "))
			}
		}
		t.Log("инъекция «ни объявления, ни вызова»: молчание не выдано за провязку")
	}

	// ── ПУСТОЙ ОБХОД — не «находок нет», а «прочитано ноль» ────────────────
	{
		if _, err := check.ReadJudgeTargetWiring(t.TempDir(), ModuleManifestCheckTarget); err == nil {
			t.Error("дерево без рецепта прочиталось без ошибки — «ноль находок» стало бы " +
				"неотличимо от «ноль прочитанного»")
		}
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "Makefile"), []byte(declaringMakefile), 0o600); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		if _, err := check.ReadJudgeTargetWiring(root, ModuleManifestCheckTarget); err == nil {
			t.Error("дерево без каталога заданий прочиталось без ошибки — обход беспредметен, " +
				"а вердикт выглядел бы зелёным")
		}
	}

	// ── НЕРАЗБИРАЕМЫЙ НОСИТЕЛЬ не молчит ──────────────────────────────────
	//
	// Файл, который не разобрался, НЕ проверен, и это отдельная находка: без
	// неё сломанный YAML тихо вычитал бы носителя из обхода.
	{
		tr := intactTree()
		tr.workflows = map[string]string{
			"ci.yml":     callingWorkflow,
			"broken.yml": "jobs:\n  x:\n   - это не YAML: [\n",
		}
		got := judgeWiringFaultsOn(t, ModuleManifestCheckTarget, tr)
		if len(got) != 1 || !strings.Contains(got[0], "НЕ проверен") {
			t.Fatalf("неразбираемый носитель не назван: получено %d:\n  %s",
				len(got), strings.Join(got, "\n  "))
		}
		t.Log("инъекция «неразбираемый носитель»: файл назван НЕ проверенным, а не вычтен молча")
	}
}

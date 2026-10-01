// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notify_wiring_test.go — NTF1-D08 по дереву kaname: единый рабочий процесс
// исполняет `make notifications-check BASE=HEAD^1` и `make notify-tree-gates`
// на запросе и на `push`; снятый шаг — красный (З31).
//
// ТОНКИЙ ВЫЗЫВАЮЩИЙ. Ведомость обязательных вызовов, разбор YAML рабочих
// процессов, разбор тел `run:` словами оболочки и перечень запретов живут в
// одной функции corelib — `treehygiene.AuditNotifyWiring`. Здесь только
// корень дерева kaname: копия ведомости или правил в этом дереве разошлась бы
// с corelib молча (УК50, CX1-49 (а)).
//
// Гейт НЕ пропускается при -short: шаг `go test` конвейера идёт с -short, и
// пропуск снял бы единственного исполнителя провязки молча.
package check_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/treehygiene"
)

// notifyWorkflowsDir — каталог рабочих процессов дерева от его корня.
const notifyWorkflowsDir = ".github/workflows"

// notifyWiring — исход гейта D08 по каталогу рабочих процессов dir и Makefile
// дерева root. Отказ исполнения — «проверка НЕ ИСПОЛНЯЛАСЬ», а не находка.
func notifyWiring(t *testing.T, dir, root string) treehygiene.WiringReport {
	t.Helper()
	r, err := treehygiene.AuditNotifyWiring(dir, filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: гейт вызова NTF-1 не исполнился: %v", err)
	}
	t.Log(r.String())
	return r
}

// TestNTF1D08_KanameCIRunsTheNotifyChecks — D08 по дереву kaname: по каждой
// записи ведомости ровно один шаг в едином рабочем процессе, находок ноль.
func TestNTF1D08_KanameCIRunsTheNotifyChecks(t *testing.T) {
	root := notifyTreeRoot(t)
	r := notifyWiring(t, filepath.Join(root, filepath.FromSlash(notifyWorkflowsDir)), root)
	logCorelibPin(t, root)
	if r.Workflows == 0 || r.Steps == 0 {
		t.Fatalf("пустой обход — не вердикт: рабочих процессов %d, шагов %d", r.Workflows, r.Steps)
	}
	for _, f := range r.Findings {
		t.Errorf("NTF1-D08 · %s", f)
	}
	for _, rec := range treehygiene.NotifyWiringLedger() {
		if r.Found[rec] != 1 {
			t.Errorf("NTF1-D08 · «%s»: шагов %d, ожидается ровно один — второй шаг той же записи "+
				"исполнял бы проверку дважды и снимался бы порознь", rec, r.Found[rec])
		}
	}
}

// TestNTF1D08_InjectionInKanameIsFound — D08 (9): инъекция (1) в kaname —
// шаг `notifications-check` снят из копии рабочих процессов дерева — находка
// «задания нет» с записью ведомости и файлом. Близнец — та же копия без
// снятия: гейт молчит. Копия и близнец различаются ровно одним шагом.
func TestNTF1D08_InjectionInKanameIsFound(t *testing.T) {
	root := notifyTreeRoot(t)
	src := filepath.Join(root, filepath.FromSlash(notifyWorkflowsDir))
	rec := treehygiene.NotifyWiringLedger()[0]
	if !strings.Contains(rec, "notifications-check") {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: первая запись ведомости %q — не notifications-check", rec)
	}

	t.Run("близнец — копия рабочих процессов без снятия", func(t *testing.T) {
		dir, removed := copyWorkflowsWithout(t, src, "")
		if removed != 0 {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: близнец снял %d шагов", removed)
		}
		r := notifyWiring(t, dir, root)
		for _, f := range r.Findings {
			t.Errorf("близнец обязан молчать: %s", f)
		}
	})

	t.Run("(9) шаг notifications-check снят — задания нет", func(t *testing.T) {
		dir, removed := copyWorkflowsWithout(t, src, rec)
		if removed != 1 {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: снято шагов %d, ожидается 1 — инъекции не о том", removed)
		}
		r := notifyWiring(t, dir, root)
		want := "«" + rec + "»: задания нет"
		found := slices.ContainsFunc(r.Findings, func(f treehygiene.Finding) bool {
			return strings.HasPrefix(f.Why, want) && strings.Contains(f.Position, "ci.yml")
		})
		if !found || len(r.Findings) != 1 {
			t.Fatalf("ожидается ровно одна находка %q с файлом ci.yml, получено %d:\n%v",
				want, len(r.Findings), r.Findings)
		}
	})
}

// copyWorkflowsWithout копирует рабочие процессы src во временный каталог,
// снимая шаги, чьё тело `run:` равно drop (пусто — не снимать; файл всё равно
// проходит разбор и Marshal, как у инъекции). Шаг снимается
// разбором YAML, а не правкой текста: правка текста попадала бы и в прозу
// комментариев, где та же запись объяснена.
func copyWorkflowsWithout(t *testing.T, src, drop string) (string, int) {
	t.Helper()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %s не читается: %v", src, err)
	}
	dst := t.TempDir()
	removed := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(src, e.Name())) // #nosec G304 -- файл рабочего процесса дерева
		if err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
		// Каждый файл рабочего процесса идёт путём «разбор → Marshal» и у
		// близнеца, и у инъекции: копии различаются ровно снятым шагом, а не
		// ещё и формой записи (кавычки, отступы, комментарии после Marshal).
		if strings.HasSuffix(e.Name(), ".yml") || strings.HasSuffix(e.Name(), ".yaml") {
			var doc yaml.Node
			if err := yaml.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %s не разбирается YAML: %v", e.Name(), err)
			}
			if drop != "" {
				removed += dropRunSteps(&doc, drop)
			}
			if raw, err = yaml.Marshal(&doc); err != nil {
				t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %s не записывается YAML: %v", e.Name(), err)
			}
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o600); err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: %v", err)
		}
	}
	return dst, removed
}

// dropRunSteps снимает из каждого задания шаги с телом `run:`, равным drop
// (после снятия краевых пробелов), и возвращает их число.
func dropRunSteps(doc *yaml.Node, drop string) int {
	if len(doc.Content) == 0 {
		return 0
	}
	jobs := yamlMapGet(doc.Content[0], "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return 0
	}
	removed := 0
	for i := 1; i < len(jobs.Content); i += 2 {
		steps := yamlMapGet(jobs.Content[i], "steps")
		if steps == nil || steps.Kind != yaml.SequenceNode {
			continue
		}
		kept := steps.Content[:0]
		for _, s := range steps.Content {
			if run := yamlMapGet(s, "run"); run != nil && strings.TrimSpace(run.Value) == drop {
				removed++
				continue
			}
			kept = append(kept, s)
		}
		steps.Content = kept
	}
	return removed
}

func yamlMapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

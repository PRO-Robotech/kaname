// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// history_question_vertex_corpus_injection_test.go — ПЕРЕПИСЬ ГЕЙТА ВЕРШИНЫ
// ВОПРОСА ВИДИТ ИСПОЛНЯЕМЫЙ ФАЙЛ БЕЗ РАСШИРЕНИЯ (задача PRO-Robotech/kaname#371).
//
// Слепая зона была измерена: `scripts/hooks/pre-push` и `scripts/hooks/commit-msg`
// задают вопросы об истории, а перепись по суффиксам их не читала, — тогда как
// `scripts/hooks/install.sh` рядом читался и судился. Отличает исполняемый файл от
// прочего без расширения его ПЕРВАЯ СТРОКА `#!`, и проба держит обе стороны:
// файл с `#!` входит в перепись и даёт вопрос, файл без неё — не входит.
package check_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestHistoryCorpusReadsAnExtensionlessScriptByItsShebang(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Вызов записан ДОСЛОВНО в форме, стоящей в `scripts/hooks/commit-msg`.
	call := "    if [ \"$(git log -1 --format='%an <%ae> %at' HEAD 2> /dev/null)\" = \"$a\" ]; then :; fi\n"
	files := map[string]string{
		"scripts/hooks/pre-push": "#!/usr/bin/env bash\n" + call,
		// ЗАКОННЫЙ БЛИЗНЕЦ: тот же вызов, тот же каталог, нет первой строки `#!` —
		// это не исполняемый сценарий, и в перепись он не входит.
		"scripts/hooks/NOTES": call,
		// Опорный файл с суффиксом: перепись по суффиксам не сломана.
		"scripts/hooks/install.sh": "#!/usr/bin/env bash\n" + call,
	}
	for rel, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	for _, args := range [][]string{{"init", "--quiet", "."}, {"add", "-A"}} {
		c := exec.Command("git", args...)
		c.Dir = dir
		out, err := c.CombinedOutput()
		require.NoErrorf(t, err, "проба НЕ ИСПОЛНЯЛАСЬ: git %v\n%s", args, out)
	}

	corpus := readHistoryCorpus(t, dir, dir)
	require.Contains(t, corpus, "scripts/hooks/pre-push",
		"исполняемый файл без расширения (первая строка `#!`) не вошёл в перепись — слепая зона kaname#371")
	require.Contains(t, corpus, "scripts/hooks/install.sh", "перепись по суффиксам сломана")
	require.NotContains(t, corpus, "scripts/hooks/NOTES",
		"файл без расширения и без `#!` прочитан как сценарий — перепись расширена не по признаку")

	qs, c := check.ScanHistoryQuestions(corpus, historyTrunkRefs)
	require.Equal(t, 2, c.Head, "вопрос в сценарии без расширения не прочитан: %v", qs)
	findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
	require.Len(t, findings, 2)
	require.Contains(t, findings[0]+findings[1], "scripts/hooks/pre-push:2")
}

// TestHistoryVertexFindingNamesTheMergeRuleInForce — ТЕКСТ НАХОДКИ ЧАСТЬ СВОЙСТВА:
// он называет действующее правило вливания (коммит слияния, решение владельца
// 2026-09-22), а не снятое (схлопывание).
func TestHistoryVertexFindingNamesTheMergeRuleInForce(t *testing.T) {
	t.Parallel()
	qs, _ := scanOne(t, "internal/x/a_test.go", goSource(headVertexCallFromTheTree))
	findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "коммитом слияния",
		"находка не называет действующее правило вливания")
	require.NotContains(t, findings[0], "схлопыванием",
		"находка называет причиной снятое правило вливания")
}

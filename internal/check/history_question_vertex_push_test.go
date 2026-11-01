// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestHistoryVertexPushLedgerUsesActualHook судит тот же вход, что гейт дерева.
// Точная перепись ловит рост и снятие вызовов; семантику отправляемого tip держат
// исполняемые пробы самого хука, а не число записей этой ведомости.
func TestHistoryVertexPushLedgerUsesActualHook(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	const rel = "scripts/hooks/pre-push"
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(prefix), rel))
	require.NoError(t, err)
	require.NotEmpty(t, src)

	ledger := map[string]vertexWaiver{}
	for key, w := range vertexLedger() {
		if strings.HasPrefix(key, rel+"#") {
			ledger[key] = w
		}
	}
	require.Len(t, ledger, 3)
	judge := func(body []byte) ([]string, int, []string) {
		qs, c := check.ScanHistoryQuestions(map[string][]byte{rel: body}, historyTrunkRefs)
		require.Equal(t, 1, c.FilesRead)
		require.GreaterOrEqual(t, c.Questions, 4)
		return judgeHistoryVertices(qs, ledger)
	}
	t.Run("настоящий хук с доводами молчит", func(t *testing.T) {
		findings, applied, stale := judge(src)
		require.Empty(t, findings)
		require.Empty(t, stale)
		require.Equal(t, 3, applied)
	})
	t.Run("новый незарегистрированный запрос краснеет", func(t *testing.T) {
		mutant := append(append([]byte{}, src...), []byte("\ngit log --oneline HEAD\n")...)
		findings, applied, stale := judge(mutant)
		require.Equal(t, 3, applied)
		require.Empty(t, stale)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], rel+":")
		require.Contains(t, findings[0], "глагол log")
	})
	t.Run("рост зарегистрированного глагола краснеет", func(t *testing.T) {
		mutant := append(append([]byte{}, src...), []byte("\ngit merge-base --is-ancestor HEAD HEAD\n")...)
		findings, applied, stale := judge(mutant)
		require.Equal(t, 2, applied)
		require.Empty(t, stale)
		require.Len(t, findings, 1)
		require.Contains(t, findings[0], "прощает 1 вызов(ов), а их в файле 2")
	})
	t.Run("снятый вызов делает запись устаревшей", func(t *testing.T) {
		lines := strings.Split(string(src), "\n")
		removed := 0
		for i, line := range lines {
			if strings.Contains(line, "git cat-file -e") {
				lines[i] = ""
				removed++
			}
		}
		require.Equal(t, 1, removed)
		qs, c := check.ScanHistoryQuestions(map[string][]byte{rel: []byte(strings.Join(lines, "\n"))}, historyTrunkRefs)
		require.Equal(t, 3, c.Questions)
		findings, applied, stale := judgeHistoryVertices(qs, ledger)
		require.Empty(t, findings)
		require.Equal(t, 2, applied)
		require.Equal(t, []string{rel + "#cat-file"}, stale)
	})
}

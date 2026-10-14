// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// history_question_vertex_parent_test.go — КАКОЙ РОДИТЕЛЬ коммита слияния несёт
// соседние полосы: замер, а не память (задача PRO-Robotech/kaname#371).
//
// Посылка гейта и текст его находки называют родителя, через которого в ствол
// приходит то, что легло от соседних полос, пока полоса жила. Слово «первый» или
// «второй» здесь — утверждение о поведении git при действующем правиле вливания
// (`merge --no-ff` на стволе), и оно проверяется опытом: на синтетическом
// репозитории соседняя полоса садится в ствол раньше, затем ствол вливает эту
// полосу коммитом слияния, и спрашивается, предком КАКОГО родителя стал коммит
// соседа. Найденное слово сверяется с шапкой разбора и с текстом находки.
//
// Положительный контроль — коммит соседа достижим ровно из одного родителя: иначе
// «назван верный родитель» зеленело бы и на опыте, где соседа нет вовсе.

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"
)

// neighbourCarryingParentClaim — утверждение о родителе в прозе: слово перед
// «родитель», за которым сказано, что он несёт соседние полосы.
var neighbourCarryingParentClaim = regexp.MustCompile(
	`(первый|второй) родитель(?: коммита слияния)? несёт то, что легло (?:в ствол )?от соседних`)

// measureNeighbourCarryingParent — какой родитель коммита слияния на стволе
// несёт коммит соседней полосы: «первый» либо «второй».
func measureNeighbourCarryingParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	env := append(gitenv.Env(),
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@invalid")
	run := func(args ...string) (string, error) {
		c := gitenv.Command(dir, args...)
		c.Env = env
		out, err := c.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	git := func(args ...string) string {
		t.Helper()
		out, err := run(args...)
		if err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: git %v: %v\n%s", args, err, out)
		}
		return out
	}
	write := func(name string) {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(name+"\n"), 0o600))
		git("add", name)
	}

	git("init", "--quiet", "-b", "main", ".")
	write("base.txt")
	git("commit", "--quiet", "-m", "основание")

	git("checkout", "--quiet", "-b", "lane")
	write("lane.txt")
	git("commit", "--quiet", "-m", "полоса")

	git("checkout", "--quiet", "main")
	write("neighbour.txt")
	git("commit", "--quiet", "-m", "соседняя полоса легла в ствол")
	neighbour := git("rev-parse", "HEAD")

	git("merge", "--quiet", "--no-ff", "-m", "#1 merge lane", "lane")

	carriedBy := func(parent string) bool {
		_, err := run("merge-base", "--is-ancestor", neighbour, "HEAD^"+parent)
		return err == nil
	}
	first, second := carriedBy("1"), carriedBy("2")
	require.Truef(t, first != second,
		"проба НЕ ИСПОЛНЯЛАСЬ: коммит соседа достижим из первого родителя=%v, из второго=%v — "+
			"ровно один из двух обязан его нести", first, second)
	if first {
		return "первый"
	}
	return "второй"
}

// TestMergeParentThatCarriesNeighboursIsNamedTruthfully — шапка разбора и текст
// находки называют ТОТ родитель, который замер нашёл несущим соседние полосы.
func TestMergeParentThatCarriesNeighboursIsNamedTruthfully(t *testing.T) {
	t.Parallel()
	measured := measureNeighbourCarryingParent(t)

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "history_question_vertex.go", nil, parser.ParseComments)
	require.NoError(t, err)
	var prose strings.Builder
	for _, cg := range file.Comments {
		prose.WriteString(cg.Text())
		prose.WriteString("\n")
	}
	header := strings.Join(strings.Fields(prose.String()), " ")
	claims := neighbourCarryingParentClaim.FindAllStringSubmatch(header, -1)
	require.NotEmptyf(t, claims,
		"проба НЕ ИСПОЛНЯЛАСЬ: в history_question_vertex.go нет утверждения о родителе, несущем соседние полосы")
	for _, c := range claims {
		require.Equalf(t, measured, c[1],
			"history_question_vertex.go утверждает «%s», а замер на `merge --no-ff` нашёл: соседние полосы несёт %s родитель",
			c[0], measured)
	}

	qs, _ := scanOne(t, "internal/x/a_test.go", goSource(headVertexCallFromTheTree))
	findings, _, _ := judgeHistoryVertices(qs, map[string]vertexWaiver{})
	require.Len(t, findings, 1)
	found := neighbourCarryingParentClaim.FindAllStringSubmatch(strings.Join(strings.Fields(findings[0]), " "), -1)
	require.NotEmptyf(t, found, "текст находки не называет родителя, несущего соседние полосы:\n%s", findings[0])
	for _, c := range found {
		require.Equalf(t, measured, c[1],
			"текст находки утверждает «%s», а замер нашёл: соседние полосы несёт %s родитель", c[0], measured)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// trunk_verdict_holder_injection_test.go — ГЕЙТ СПОСОБЕН УПАСТЬ И СПОСОБЕН
// СМОЛЧАТЬ (задача PRO-Robotech/kaname#62).
//
// Инъекция идёт НАСТОЯЩИМ входом: объявление процесса читается из дерева, и
// возвращаемый дефект вносится в его КОПИЮ — по одному факту за раз. Каждой
// половине «краснеет» отвечает половина «молчит»: на дереве как есть находок
// ноль, и это утверждается первым.
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

// trunkWorkflowSource — объявление процесса из дерева.
func trunkWorkflowSource(t *testing.T) string {
	t.Helper()
	root, prefix := platformtree.RequireCorpus(t)
	if prefix != "" {
		root = filepath.Join(root, filepath.FromSlash(prefix))
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(trunkWorkflowRel))) // #nosec G304 -- координата объявлена постоянной
	require.NoError(t, err, "инъекция беспредметна: объявление процесса не прочитано")
	return string(raw)
}

func auditOf(t *testing.T, raw string) []string {
	t.Helper()
	findings, _, err := check.AuditTrunkHolderWiring(raw)
	require.NoError(t, err, "инъекция доказывала бы разбор, а не гейт")
	return findings
}

// TestTrunkHolderGateCanStaySilent — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ.
//
// Без него всё нижеследующее зеленело бы на гейте, который краснеет всегда.
func TestTrunkHolderGateCanStaySilent(t *testing.T) {
	t.Parallel()
	findings, census, err := check.AuditTrunkHolderWiring(trunkWorkflowSource(t))
	require.NoError(t, err)
	require.Emptyf(t, findings, "на дереве как есть гейт нашёл %d: %v", len(findings), findings)
	require.True(t, census.HolderSeen)
	require.Equal(t, census.Jobs-1, census.Needed,
		"перечень зависимостей держателя не покрывает состав заданий — тогда молчание "+
			"гейта ничего не стоит")
	require.GreaterOrEqual(t, census.SelfTests, 1)
	require.GreaterOrEqual(t, census.Verdicts, 1)
}

// TestTrunkHolderGateCanFail — ПОЛОВИНА «КРАСНЕЕТ», по оси на подпробу.
func TestTrunkHolderGateCanFail(t *testing.T) {
	t.Parallel()
	raw := trunkWorkflowSource(t)

	t.Run("задание держателя снято — красное ствола снова без читателя", func(t *testing.T) {
		// Один факт: задание переименовано, то есть держателя в процессе нет.
		got := auditOf(t, strings.Replace(raw, "\n  "+check.TrunkHolderJob+":\n",
			"\n  trunkverdictretired:\n", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "в процессе НЕТ")
	})

	t.Run("заведено задание, которого держатель не видит", func(t *testing.T) {
		// Один факт: у процесса стало на одно задание больше. Ровно так перечень
		// `needs` и стареет — молча, при исправном во всём остальном процессе.
		got := auditOf(t, raw+"\n  newjob:\n    name: заведённое после держателя\n"+
			"    runs-on: ubuntu-latest\n    steps:\n      - run: echo ok\n")
		require.Len(t, got, 1)
		require.Contains(t, got[0], "НЕ ВИДИТ исхода заданий: newjob")
	})

	t.Run("вызов вердикта снят — провязка стала формой без содержания", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"          .github/scripts/trunk-verdict-holder.sh \\",
			"          true \\", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "не зовётся ни одним шагом")
	})

	t.Run("самопроверка снята — молчание держателя нечем отличить от мёртвого", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"run: .github/scripts/trunk-verdict-holder.sh --self-test",
			"run: echo пропущено", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "--self-test не зовётся")
	})

	t.Run("условие потеряло always() — держатель снят на красном стволе", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"if: always() && github.event_name == 'push'",
			"if: github.event_name == 'push'", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "always()")
	})

	t.Run("условие не сужено по стволу", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			" && github.ref == 'refs/heads/main'", "", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "не сужено по стволу")
	})

	t.Run("право писать задачи снято у задания", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"      contents: read\n      issues: write\n",
			"      contents: read\n", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "issues: write")
	})

	t.Run("право писать задачи выдано ВСЕМУ процессу", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"permissions:\n  contents: read\n",
			"permissions:\n  contents: read\n  issues: write\n", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "ВСЕМУ процессу")
	})

	// ЗАКОННЫЙ БЛИЗНЕЦ ФОРМЫ: имя держателя, стоящее в КОММЕНТАРИИ шага, вызовом
	// не является. Гейт, считающий его вызовом, зеленел бы на собственном
	// объяснении — ровно тот класс, который он и ловит.
	t.Run("имя в комментарии вызовом не считается", func(t *testing.T) {
		got := auditOf(t, strings.Replace(raw,
			"          .github/scripts/trunk-verdict-holder.sh \\",
			"          # .github/scripts/trunk-verdict-holder.sh — объяснение\n          true \\", 1))
		require.Len(t, got, 1)
		require.Contains(t, got[0], "не зовётся ни одним шагом")
	})
}

// TestTrunkHolderGateRefusesAnUnparsableDeclaration — беспредметный вход.
func TestTrunkHolderGateRefusesAnUnparsableDeclaration(t *testing.T) {
	t.Parallel()
	_, _, err := check.AuditTrunkHolderWiring("{ обрезано")
	require.Error(t, err, "неразобранное объявление принято за чистое — молчание стало бы вердиктом")

	_, _, err = check.AuditTrunkHolderWiring("name: ci\non: push\n")
	require.Error(t, err, "процесс без заданий принят за чистый: ноль заданий есть «ноль "+
		"прочитанного», а не «ноль находок»")
}

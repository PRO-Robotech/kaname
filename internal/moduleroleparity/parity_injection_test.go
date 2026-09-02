// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// parity_injection_test.go — доказательство того, что сверка СПОСОБНА упасть, и
// того, что она молчит на законном близнеце.
//
// # Почему инъекция подаётся ЯДРУ, а не дереву
//
// Вход этого гейта — две стороны сверки, и обе он получает извне: одну от
// применителя, другую из живой базы. Значит инъекция настоящим входом здесь —
// это подача ядру пары наборов, а не правка манифеста в дереве: правка дерева
// добавила бы к каждому утверждению подъём контейнера и цепочку миграций, ничего
// не доказав сверх.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Каждый случай снимает ОДНО свойство у входа, чьи остальные свойства целы, и
// рядом стоит контроль — тот же вход без снятия. Форма «завести ещё один
// элемент» здесь не годится: новый элемент нарушил бы всё, что требуется от
// элементов вообще, и красное пришло бы от соседа.
package moduleroleparity_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/moduleroleparity"
)

// role — законная роль обеих сторон: сверка на ней обязана молчать.
func role(name, description string, verbs ...string) moduleroleparity.Role {
	return moduleroleparity.Role{
		ID:          "rol" + name,
		Name:        name,
		Description: description,
		Rules: domain.Rules{{
			Module:    "loadbalancer",
			Resources: []string{"targetGroups"},
			Verbs:     verbs,
		}},
	}
}

// declaredAndLive — модуль, чьё объявление сходится с базой.
func declaredAndLive(rs ...moduleroleparity.Role) moduleroleparity.ModuleState {
	return moduleroleparity.ModuleState{
		Module:       "loadbalancer",
		ManifestFile: "services/nlb/manifest.yaml",
		Declared:     append([]moduleroleparity.Role(nil), rs...),
		Live:         append([]moduleroleparity.Role(nil), rs...),
	}
}

func TestDiffFallsOnlyOnWhatItJudges(t *testing.T) {
	base := role("loadbalancer.operator", "NLB operator (viewer on LB hierarchy)", "get", "list")
	second := role("loadbalancer.target_manager", "NLB target manager (composition only)",
		"addTargets", "get")

	t.Run("КОНТРОЛЬ: объявление сходится с базой — находок нет", func(t *testing.T) {
		require.Empty(t, moduleroleparity.Diff(
			[]moduleroleparity.ModuleState{declaredAndLive(base, second)}, nil))
	})

	t.Run("КОНТРОЛЬ: пустая ведомость на согласном дереве — не поломка", func(t *testing.T) {
		// Пустая ведомость и есть ЦЕЛЬ #1891. Падение на её достижении толкало бы
		// держать запись ради зелёного, то есть работало бы против себя.
		require.Empty(t, moduleroleparity.Diff(
			[]moduleroleparity.ModuleState{declaredAndLive(base)},
			[]moduleroleparity.Postponement{}))
	})

	t.Run("модуль не объявил живых ролей и не стоит в ведомости", func(t *testing.T) {
		st := declaredAndLive(base)
		st.Declared = nil
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"не объявил НИ ОДНОЙ", "loadbalancer.operator")
	})

	t.Run("КОНТРОЛЬ к нему: тот же модуль назван ведомостью — молчание", func(t *testing.T) {
		st := declaredAndLive(base)
		st.Declared = nil
		require.Empty(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st},
			[]moduleroleparity.Postponement{{Module: "loadbalancer", Why: "#1904"}}))
	})

	t.Run("объявленной роли нет в базе", func(t *testing.T) {
		st := declaredAndLive(base)
		st.Declared = append(st.Declared, second)
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"а в живой базе её нет", "loadbalancer.target_manager")
	})

	t.Run("живая роль не объявлена, хотя раздел есть", func(t *testing.T) {
		st := declaredAndLive(base)
		st.Live = append(st.Live, second)
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"не объявлена манифестом", "loadbalancer.target_manager")
	})

	t.Run("назначение расходится", func(t *testing.T) {
		st := declaredAndLive(base)
		st.Declared = []moduleroleparity.Role{
			role("loadbalancer.operator", "NLB operator (что-то другое)", "get", "list"),
		}
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"назначение расходится", "loadbalancer.operator")
	})

	t.Run("право расходится ПОРЯДКОМ, а не составом", func(t *testing.T) {
		// Порядок значим: `rules` кладётся дословно, и переставленный набор дал бы
		// другую строку. Сверка, сортирующая перед сравнением, здесь бы смолчала.
		st := declaredAndLive(base)
		st.Declared = []moduleroleparity.Role{
			role("loadbalancer.operator", "NLB operator (viewer on LB hierarchy)", "list", "get"),
		}
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"право расходится", "loadbalancer.operator")
	})

	t.Run("идентификатор расходится", func(t *testing.T) {
		st := declaredAndLive(base)
		other := base
		other.ID = "rolddddddddddddddddd"
		st.Declared = []moduleroleparity.Role{other}
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st}, nil),
			"идентификатор расходится", "loadbalancer.operator")
	})

	t.Run("ведомость истекает: модуль уже объявил свои роли", func(t *testing.T) {
		requireFinding(t, moduleroleparity.Diff(
			[]moduleroleparity.ModuleState{declaredAndLive(base)},
			[]moduleroleparity.Postponement{{Module: "loadbalancer", Why: "#1904"}}),
			"запись потеряла предмет", "loadbalancer")
	})

	t.Run("ведомость истекает: у модуля нет живых ролей", func(t *testing.T) {
		st := declaredAndLive()
		requireFinding(t, moduleroleparity.Diff([]moduleroleparity.ModuleState{st},
			[]moduleroleparity.Postponement{{Module: "loadbalancer", Why: "#1904"}}),
			"откладывать нечего", "loadbalancer")
	})

	t.Run("ведомость называет модуль, которого нет в дереве", func(t *testing.T) {
		requireFinding(t, moduleroleparity.Diff(
			[]moduleroleparity.ModuleState{declaredAndLive(base)},
			[]moduleroleparity.Postponement{{Module: "nlb", Why: "написание каталога, а не модуля"}}),
			"которого нет ни в одном манифесте", "nlb")
	})
}

// requireFinding — находка есть, она ОДНА и она называет предмет.
//
// Одна, а не «хотя бы одна»: инъекция, снявшая одно свойство, обязана дать одно
// красное. Две означали бы, что снятие задело соседа, и тогда красное пришло бы
// не от проверяемого.
func requireFinding(t *testing.T, findings []string, want, subject string) {
	t.Helper()
	require.Lenf(t, findings, 1, "ожидалась ровно одна находка, получено %d:\n%s",
		len(findings), strings.Join(findings, "\n"))
	require.Containsf(t, findings[0], want, "находка не назвала предмет: %s", findings[0])
	require.Containsf(t, findings[0], subject, "находка не назвала виновника: %s", findings[0])
}

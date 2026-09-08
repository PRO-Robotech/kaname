// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// labelledCounter reads ONE labelled series out of the registry. Absent series read as 0
// — which is exactly the state the test below has to be able to distinguish from a
// present-but-zero one, so the caller asserts on presence separately.
func labelledCounter(t *testing.T, r *Registry, name string, labels map[string]string) (value float64, present bool) {
	t.Helper()
	mfs, err := r.reg.Gather()
	require.NoError(t, err)
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			match := true
			for _, lp := range m.GetLabel() {
				if want, ok := labels[lp.GetName()]; ok && want != lp.GetValue() {
					match = false
					break
				}
			}
			if match && len(m.GetLabel()) == len(labels) {
				return m.GetCounter().GetValue(), true
			}
		}
	}
	return 0, false
}

// TestRegisterPostCommitRecorder_RunsAndFailuresAreBothLive — the recorder must emit a
// series for a step that SUCCEEDED as well as for one that failed.
//
// The failure count alone would not close the gap it exists for: a step that never ran —
// unwired, short-circuited, or reached by no traffic at all — also reports zero failures,
// and those two states are precisely the ones that must be told apart. Counting runs is
// what makes "never refused" different from "never reached".
func TestRegisterPostCommitRecorder_RunsAndFailuresAreBothLive(t *testing.T) {
	reg := NewRegistry()
	rec := reg.NewRegisterPostCommitRecorder()

	// Шаги берутся ИЗ ЗАКРЫТОГО НАБОРА (RegisterPostCommitSteps). Здесь стояли
	// `tuple_write`/`tuple_delete` — шаги записи и снятия кортежей у внешнего
	// движка прав. Они пережили свой предмет дважды: движка нет, и в объявленном
	// наборе их тоже не было — то есть последнее утверждение файла («клетка
	// закрытого набора существует до первого наблюдения») спрашивало про клетку,
	// которой набор не объявлял, и краснело бы на любом верном коллекторе.
	rec.ObserveRegisterPostCommit("forward_additive", "ok")
	rec.ObserveRegisterPostCommit("forward_additive", "ok")
	rec.ObserveRegisterPostCommit("forward_guarded", "error")
	rec.ObserveRegisterPostCommit("residual_read", "ok")

	const name = "kaname_register_postcommit_steps_total"

	v, ok := labelledCounter(t, reg, name, map[string]string{"step": "forward_additive", "outcome": "ok"})
	require.True(t, ok, "a SUCCESSFUL run must produce a series — otherwise a step that "+
		"never ran is indistinguishable from one that never failed")
	require.Equal(t, 2.0, v)

	v, ok = labelledCounter(t, reg, name, map[string]string{"step": "forward_guarded", "outcome": "error"})
	require.True(t, ok, "a FAILED post-commit step must be counted, not only logged")
	require.Equal(t, 1.0, v)

	v, ok = labelledCounter(t, reg, name, map[string]string{"step": "residual_read", "outcome": "ok"})
	require.True(t, ok)
	require.Equal(t, 1.0, v)

	// A step never observed carries a series AT ZERO.
	//
	// Здесь стояло обратное утверждение — «необнаблюдённый шаг не должен
	// фабриковать нулевую точку» — и оно закрепляло чтение, которого не хватало.
	// Отсутствие серии отвечало на ДВА разных вопроса сразу: «шаг ни разу не
	// исполнялся» и «коллектор не провязан», — а различать их и есть причина, по
	// которой считаются запуски, а не только отказы. Ноль — не фабрикация: он
	// утверждает «клетка существует, и в неё ни разу не попадали», что и требуется
	// от наблюдаемости ветки, написанной, но ни разу не исполненной.
	v, ok = labelledCounter(t, reg, name, map[string]string{"step": "residual_withdraw", "outcome": "error"})
	require.True(t, ok, "клетка закрытого набора обязана существовать до первого наблюдения")
	require.Zero(t, v, "необнаблюдённая клетка стоит в нуле")

	require.Equal(t, 4.0, gatherCounter(t, reg, name), "every observation reaches the registry")
}

// TestRegisterPostCommitRecorder_ZeroIsVisibleNotAbsent — каждая клетка закрытого
// набора лейблов присутствует В НУЛЕ с момента сборки коллектора.
//
// Предмет — ровно тот, ради которого счётчик заводился, и в прежней редакции он
// оставался незакрытым. Отсутствие серии отвечало сразу на ДВА вопроса: «шаг ни
// разу не исполнялся» и «коллектор вообще не провязан», — а различать их и было
// целью. Замер это подтвердил на живом стенде: доказанный вход материализации не
// сработал НИ РАЗУ на 367 регистрациях, и установить это удалось только потому,
// что сосед по набору серию имел; сам по себе доказанный вход выглядел как
// несуществующий код.
//
// С предварительной инициализацией «ноль» становится утверждением, а не тишиной:
// серия есть ⟺ коллектор провязан; серия равна нулю при растущем соседе ⟺ ветка
// написана и не исполнялась. Второе — находка, симметрично правилу «ноль
// доставленных строк за жизнь очереди».
func TestRegisterPostCommitRecorder_ZeroIsVisibleNotAbsent(t *testing.T) {
	reg := NewRegistry()
	rec := reg.NewRegisterPostCommitRecorder()

	const name = "kaname_register_postcommit_steps_total"

	for _, step := range RegisterPostCommitSteps {
		for _, outcome := range RegisterPostCommitOutcomes {
			v, ok := labelledCounter(t, reg, name, map[string]string{"step": step, "outcome": outcome})
			require.Truef(t, ok, "серии {step=%q, outcome=%q} нет до первого наблюдения: "+
				"«шаг не исполнялся» неотличимо от «коллектор не провязан», а это и есть "+
				"вопрос, ради которого счётчик заведён", step, outcome)
			require.Zerof(t, v, "клетка {step=%q, outcome=%q} инициализирована не нулём", step, outcome)
		}
	}

	// Положительный контроль: предварительная инициализация не должна подменять
	// счёт. Без него проба зеленела бы и на коллекторе, который только и делает,
	// что объявляет нули.
	rec.ObserveRegisterPostCommit(RegisterPostCommitSteps[0], "ok")
	v, ok := labelledCounter(t, reg, name, map[string]string{"step": RegisterPostCommitSteps[0], "outcome": "ok"})
	require.True(t, ok)
	require.Equal(t, 1.0, v, "наблюдение считается поверх инициализированного нуля")
}

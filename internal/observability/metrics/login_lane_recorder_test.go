// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

// TestLoginLane_F3_48_CellsExistWithZeroBeforeTheFirstEvent — клетки исходов
// входа по причине · исходов проверяющего · «сессии нет» по виду · отказов формы
// · отказов по частоте по оси · проверок утечек · отказов записи на выходе ·
// переписываний по причине существуют с нулём на свежем реестре; после одного
// события ровно одна клетка выросла на единицу.
func TestLoginLane_F3_48_CellsExistWithZeroBeforeTheFirstEvent(t *testing.T) {
	reg := NewRegistry()
	rec := reg.LoginLaneRecorder()

	cells := []struct {
		metric string
		label  string
		values []string
	}{
		{LoginOutcomesMetric, "outcome", loginOutcomeNames()},
		{PasswordVerificationOutcomesMetric, "outcome", passwordverify.OutcomeNames()},
		{HumanSessionNoSessionMetric, "reason", noSessionReasonNames()},
		{LoginFormRefusalsMetric, "refusal", []string{"missing", "rejected"}},
		{LoginRateLimitRefusalsMetric, "scope", []string{"address", "source"}},
		{PasswordBreachCheckMetric, "outcome", breachOutcomeNames()},
		{PasswordMaterialRewriteMetric, "outcome", rewriteOutcomeNames()},
	}
	total := 0
	for _, c := range cells {
		for _, v := range c.values {
			value, present := labelledCounter(t, reg, c.metric, map[string]string{c.label: v})
			require.Truef(t, present, "клетки %s{%s=%q} нет до первого события", c.metric, c.label, v)
			require.Zero(t, value)
			total++
		}
	}
	value, present := plainValue(t, reg, LogoutStoreFailuresMetric)
	require.True(t, present)
	require.Zero(t, value)
	value, present = plainValue(t, reg, LoginSourceUnknownMetric)
	require.True(t, present, "ряд «вопрос без источника» существует с нулём до первого события")
	require.Zero(t, value)
	t.Logf("перепись: клеток с нулём %d + 2 ряда без меток", total)
	rec.SourceUnknownObserved()
	value, _ = plainValue(t, reg, LoginSourceUnknownMetric)
	require.Equal(t, 1.0, value)

	rec.LoginObserved(humansession.LoginOutcomeMismatched)
	value, _ = labelledCounter(t, reg, LoginOutcomesMetric, map[string]string{"outcome": "mismatched"})
	require.Equal(t, 1.0, value, "ровно одна клетка выросла на единицу")
	value, _ = labelledCounter(t, reg, LoginOutcomesMetric, map[string]string{"outcome": "issued"})
	require.Zero(t, value)
	rec.VerificationObserved(passwordverify.OutcomeCapacityExhausted)
	value, _ = labelledCounter(t, reg, PasswordVerificationOutcomesMetric, map[string]string{"outcome": "capacity-exhausted"})
	require.Equal(t, 1.0, value)
	rec.LogoutStoreFailureObserved()
	value, _ = plainValue(t, reg, LogoutStoreFailuresMetric)
	require.Equal(t, 1.0, value)

	require.Same(t, rec, reg.LoginLaneRecorder(), "экземпляр один — второй уронил бы старт повторной регистрацией")
}

func loginOutcomeNames() []string {
	out := []string{}
	for _, o := range humansession.LoginOutcomes() {
		out = append(out, string(o))
	}
	return out
}

func noSessionReasonNames() []string {
	out := []string{}
	for _, o := range humansession.NoSessionReasons() {
		out = append(out, string(o))
	}
	return out
}

func breachOutcomeNames() []string {
	out := []string{}
	for _, o := range humansession.BreachCheckOutcomes() {
		out = append(out, string(o))
	}
	return out
}

func rewriteOutcomeNames() []string {
	out := []string{}
	for _, o := range humansession.RewriteOutcomes() {
		out = append(out, string(o))
	}
	return out
}

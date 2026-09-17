// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// second_factor_test.go — строка способа входа после Ф12 (PRO-Robotech/kacho#1281,
// приёмка `second-factor-totp-and-recovery-codes.md`, Р1; Ф12-40 уровня I):
// словарь видов — три имени, взятые у словаря способов предъявления; состояние
// строки — `pending` · `active`, и `pending` бывает только у `totp`; последний
// принятый шаг — только у `totp`; строка `pending` способом входа не является.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestLoginMethodKinds_AreThreeAndComeFromTheAssuranceVocabulary — Ф12-40:
// словарь вида — три имени, побайтово равные именам словаря способов
// предъявления (второго объявления имён домен не заводит).
func TestLoginMethodKinds_AreThreeAndComeFromTheAssuranceVocabulary(t *testing.T) {
	kinds := domain.LoginMethodKinds()
	require.Equal(t, []domain.LoginMethodKind{
		domain.LoginMethodPassword, domain.LoginMethodTOTP, domain.LoginMethodLookupSecret,
	}, kinds)
	require.Equal(t, assurance.MethodPassword.String(), string(domain.LoginMethodPassword))
	require.Equal(t, assurance.MethodTOTP.String(), string(domain.LoginMethodTOTP))
	require.Equal(t, assurance.MethodLookupSecret.String(), string(domain.LoginMethodLookupSecret))
	for _, k := range kinds {
		require.NoError(t, k.Validate())
	}
	// Ключ доступа — не строка этой таблицы (его хранилище — Ф7).
	require.Error(t, domain.LoginMethodKind(assurance.MethodWebAuthn.String()).Validate())
	require.Error(t, domain.LoginMethodKind(assurance.MethodRecoveryCode.String()).Validate())
	t.Logf("перепись: видов %d, словарь способов предъявления %d", len(kinds), len(assurance.Methods()))
}

// TestLoginMethod_StateIsRequiredAndPendingBelongsOnlyToTOTP — Р1: состояние
// обязательно; `pending` — только у кода по времени; шаг — только у него же.
func TestLoginMethod_StateIsRequiredAndPendingBelongsOnlyToTOTP(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)
	const user = "usr0000000000000sf01"

	lawful := []domain.LoginMethod{
		{UserID: user, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive},
		{UserID: user, Kind: domain.LoginMethodTOTP, Verifier: v, State: domain.LoginMethodStatePending},
		{UserID: user, Kind: domain.LoginMethodTOTP, Verifier: v, State: domain.LoginMethodStateActive, AcceptedStep: 0, StepAccepted: true},
		{UserID: user, Kind: domain.LoginMethodLookupSecret, Verifier: v, State: domain.LoginMethodStateActive},
	}
	for i, m := range lawful {
		require.NoError(t, m.Validate(), "законная строка #%d обязана проходить", i)
	}

	cases := map[string]struct {
		m    domain.LoginMethod
		want string
	}{
		"состояния нет":         {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodPassword, Verifier: v}, "login_method.state"},
		"состояние вне словаря": {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodTOTP, Verifier: v, State: "enrolled"}, "login_method.state"},
		"пароль в pending":      {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStatePending}, "login_method.state"},
		"набор кодов в pending": {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodLookupSecret, Verifier: v, State: domain.LoginMethodStatePending}, "login_method.state"},
		"шаг у набора кодов":    {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodLookupSecret, Verifier: v, State: domain.LoginMethodStateActive, StepAccepted: true}, "login_method.accepted_step"},
		"шаг у пароля":          {domain.LoginMethod{UserID: user, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive, StepAccepted: true, AcceptedStep: 5}, "login_method.accepted_step"},
	}
	for name, c := range cases {
		err := c.m.Validate()
		require.Error(t, err, "%s: строка обязана быть отвергнута", name)
		require.Contains(t, err.Error(), c.want, "%s: отказ обязан называть поле", name)
		require.False(t, strings.Contains(err.Error(), probeMaterial), "%s: отказ не вправе нести материал", name)
	}
}

// TestLoginMethod_PendingRowIsNotEnrolled — Ф12-01/40: строка `pending` не
// делает фактор заведённым; `active` — делает.
func TestLoginMethod_PendingRowIsNotEnrolled(t *testing.T) {
	v, err := domain.NewLoginVerifier(probeMaterial)
	require.NoError(t, err)
	pending := domain.LoginMethod{UserID: "usr0000000000000sf02", Kind: domain.LoginMethodTOTP, Verifier: v, State: domain.LoginMethodStatePending}
	active := pending
	active.State = domain.LoginMethodStateActive
	require.False(t, pending.Enrolled())
	require.True(t, active.Enrolled())
}

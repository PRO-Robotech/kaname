// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rewrap_test.go — переобёртка хранимого секрета кода по времени под первый
// ключ перечня (kaname#259 п.3).
//
// Свойство, ради которого она заведена, судится ИСХОДОМ СВЕРКИ, а не формой
// значения: после переобёртки проверяющий на одном НОВОМ ключе принимает код
// того же секрета, а проверяющий на одном ПРЕЖНЕМ ключе не открывает
// материала вовсе — «прежний ключ снят, и каждый секрет открывается».
package totpverify_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// TestRewrapKeepsTheSecretAndMovesItUnderTheFirstKey — секрет, обёрнутый
// прежним ключом, после переобёртки принимается проверяющим на ОДНОМ новом
// ключе тем же кодом и не открывается проверяющим на ОДНОМ прежнем.
func TestRewrapKeepsTheSecretAndMovesItUnderTheFirstKey(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	stored, err := newVerifier(t, wrapper(t, 1)).Wrap(s)
	require.NoError(t, err)

	moved, alreadyFirst, err := newVerifier(t, wrapper(t, 2, 1)).Rewrap(stored)
	require.NoError(t, err, "секрет прежнего ключа переобёртывается")
	require.False(t, alreadyFirst, "секрет прежнего ключа не назван уже обёрнутым первым")
	require.NotEqual(t, stored.Reveal(), moved.Reveal(), "переобёрнутое — новое значение")

	step := totpverify.StepAt(probeBase)
	code := probeCode(secretBytes(t, s), step)
	res := newVerifier(t, wrapper(t, 2)).Verify(moved, totpverify.NoAcceptedStep(), code, probeBase)
	require.Equal(t, totpverify.OutcomeMatched, res.Outcome, "новый ключ один открывает тот же секрет")
	require.Equal(t, step, res.Step)

	res = newVerifier(t, wrapper(t, 1)).Verify(moved, totpverify.NoAcceptedStep(), code, probeBase)
	require.Equal(t, totpverify.OutcomeMaterialUnreadable, res.Outcome, "прежний ключ один не читает переобёрнутого")
}

// TestRewrapLeavesASecretOfTheFirstKeyAsItIs — законный близнец: секрет,
// обёрнутый первым ключом, возвращается тем же значением — писать нечего.
func TestRewrapLeavesASecretOfTheFirstKeyAsItIs(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	v := newVerifier(t, wrapper(t, 2, 1))
	stored, err := v.Wrap(s)
	require.NoError(t, err)

	same, alreadyFirst, err := v.Rewrap(stored)
	require.NoError(t, err)
	require.True(t, alreadyFirst, "секрет первого ключа опознан уже обёрнутым им")
	require.Equal(t, stored.Reveal(), same.Reveal(), "значение не тронуто")
}

// TestRewrapRefusesAnUnreadableSecret — секрет, которого не открывает ни один
// ключ перечня, и материал, не являющийся base64 обёртки, — отказ одним
// словом «не читается»: вызывающий считает такие строки отдельно и ничего в
// них не пишет. Пустой материал — отказ другого слова: строки второго фактора
// без материала схема не допускает.
func TestRewrapRefusesAnUnreadableSecret(t *testing.T) {
	s, err := totpverify.NewSecret()
	require.NoError(t, err)
	foreign, err := newVerifier(t, wrapper(t, 3)).Wrap(s)
	require.NoError(t, err)
	v := newVerifier(t, wrapper(t, 2, 1))

	_, _, err = v.Rewrap(foreign)
	require.ErrorIs(t, err, totpverify.ErrSecretUnreadable, "чужой ключ")

	garbled, err := domain.NewLoginVerifier("not base64 of a wrapping!")
	require.NoError(t, err)
	_, _, err = v.Rewrap(garbled)
	require.ErrorIs(t, err, totpverify.ErrSecretUnreadable, "материал не base64")

	_, _, err = v.Rewrap(domain.LoginVerifier{})
	require.Error(t, err)
	require.False(t, errors.Is(err, totpverify.ErrSecretUnreadable), "пустой материал — не «не читается»: его нечем было обернуть")
}

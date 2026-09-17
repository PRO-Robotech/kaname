// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_cost_class_test.go — КЛАСС СТОИМОСТИ проверочного значения: формат
// вместе с набором параметров (ID-PW-1 Р4; решение kaname#188 — огибающая по
// потолку ФАКТИЧЕСКОЙ популяции).
//
// Предмет проб — то, что держит сам тип, а не дисциплина вызывающего:
//
//  1. ключ класса ДЕТЕРМИНИРОВАН: одна и та же пара «формат, параметры» даёт
//     один ключ независимо от порядка обхода карты, иначе один класс
//     калибровался бы дважды, а карта классов расходилась бы молча;
//  2. класс годен только с ПОЛНЫМ набором параметров своего формата: параметр,
//     не названный, означал бы «ноль», а класс с нулём в стоимости — не класс;
//  3. чужой формат и чужой параметр — отказ, а не молчание.
package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func bcryptClass(cost uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: cost}}
}

func argon2Class(memory, iterations, parallelism uint32) domain.PasswordCostClass {
	return domain.PasswordCostClass{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: memory, domain.CostParamArgon2Iterations: iterations,
			domain.CostParamArgon2Parallelism: parallelism}}
}

// TestPasswordCostClass_KeyIsDeterministicAndDistinguishesClasses — ключ один
// на класс и разный у разных классов: и между форматами, и внутри формата.
func TestPasswordCostClass_KeyIsDeterministicAndDistinguishesClasses(t *testing.T) {
	t.Parallel()

	a := argon2Class(65536, 3, 4)
	same := argon2Class(65536, 3, 4)
	require.Equal(t, a.Key(), same.Key(), "один класс — один ключ")
	require.Equal(t, "argon2id memory=65536 iterations=3 parallelism=4", a.Key(), "ключ читается человеком в порядке параметров формата")
	require.Equal(t, "memory=65536,iterations=3,parallelism=4", a.ParamsLabel())

	b := bcryptClass(12)
	require.Equal(t, "2a cost=12", b.Key())
	require.Equal(t, "cost=12", b.ParamsLabel())

	require.NotEqual(t, a.Key(), argon2Class(32768, 3, 4).Key(), "память вдвое ниже — другой класс того же формата")
	require.NotEqual(t, a.Key(), b.Key())
	require.NotEqual(t, b.Key(), bcryptClass(14).Key())
}

// TestPasswordCostClass_ValidateRequiresTheWholeParameterSetOfItsFormat —
// полный набор — годен; недостающий параметр, чужой параметр, чужой формат —
// отказ с именем.
func TestPasswordCostClass_ValidateRequiresTheWholeParameterSetOfItsFormat(t *testing.T) {
	t.Parallel()

	require.NoError(t, argon2Class(65536, 3, 4).Validate(), "положительный контроль")
	require.NoError(t, bcryptClass(4).Validate(), "положительный контроль")

	missing := argon2Class(65536, 3, 4)
	delete(missing.Params, domain.CostParamArgon2Parallelism)
	err := missing.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), string(domain.CostParamArgon2Parallelism))

	foreign := bcryptClass(12)
	foreign.Params[domain.CostParamArgon2Memory] = 1
	err = foreign.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), string(domain.CostParamArgon2Memory))

	unknown := domain.PasswordCostClass{Format: "pbkdf2", Params: map[domain.PasswordHashCostParam]uint32{"rounds": 1}}
	err = unknown.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "pbkdf2")
}

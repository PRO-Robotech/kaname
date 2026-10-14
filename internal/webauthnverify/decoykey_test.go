// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package webauthnverify

// decoykey_test.go — приманка выравнивания времени обязана быть ГОДНЫМ ключом
// своего семейства.
//
// # Почему это не самоочевидно
//
// Негодная приманка не даёт ни одного видимого отказа: вызывающий подставляет
// её вместо ненайденного ключа, сверка отвечает отказом — и отвечает им же,
// когда ключ разобрать не удалось. Снаружи оба случая неразличимы by
// construction (в том и смысл единого отказа), поэтому сломанная приманка
// живёт сколько угодно, а выравнивание времени, ради которого она заведена,
// не работает: разбор негодного ключа стоит НЕ столько же, сколько сверка
// подписи настоящим.
//
// Проверяемое свойство поэтому не «отказ пришёл», а «ключ разбирается и
// называет то самое семейство».

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecoyKey_IsAValidKeyOfItsDeclaredAlgorithm — по приманке на каждое
// объявленное семейство: разбирается тем же разбором, что ключ строки, и
// называет то семейство, которое у неё просили.
func TestDecoyKey_IsAValidKeyOfItsDeclaredAlgorithm(t *testing.T) {
	known := KnownAlgorithms()
	require.NotEmpty(t, known, "словарь алгоритмов пуст — обход не состоялся, и молчание это не чистота")
	t.Logf("перепись: семейств в словаре %d", len(known))
	for _, alg := range known {
		d, err := NewDecoyKey(alg)
		require.NoErrorf(t, err, "приманка семейства %d не отчеканена", alg)
		require.Equalf(t, alg, d.Algorithm(), "приманка называет семейство %d, просили %d", d.Algorithm(), alg)
		require.NotEmptyf(t, d.Public(), "приманка семейства %d без открытого ключа", alg)

		parsed, _, perr := parseCOSEKey(d.Public())
		require.NoErrorf(t, perr, "приманка семейства %d не разбирается тем разбором, которым читается ключ строки", alg)
		require.Equalf(t, alg, parsed, "разбор приманки называет семейство %d, чеканили %d", parsed, alg)
	}
}

// TestDecoyKey_RefusesAnAlgorithmOutsideTheDictionary — вторая сторона оси:
// семейство вне словаря отвергается ОТКАЗОМ ПОСТРОЕНИЯ, а не пустой приманкой.
// Без этой половины первая зеленела бы на чеканке, отвечающей чем угодно.
func TestDecoyKey_RefusesAnAlgorithmOutsideTheDictionary(t *testing.T) {
	// Значение заведомо вне словаря: словарь закрыт тремя семействами.
	_, err := NewDecoyKey(Algorithm(-1))
	require.Error(t, err, "семейство вне словаря обязано отказывать в построении")
	require.Contains(t, err.Error(), "outside the dictionary")
}

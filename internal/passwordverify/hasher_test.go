// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package passwordverify_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

func declaredArgon2id(memory, iterations, parallelism uint32) passwordverify.Declared {
	return passwordverify.Declared{
		Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory:      memory,
			domain.CostParamArgon2Iterations:  iterations,
			domain.CostParamArgon2Parallelism: parallelism,
		},
	}
}

type countingObserver struct {
	seen map[passwordverify.Outcome]int
}

func (c *countingObserver) VerificationObserved(o passwordverify.Outcome) {
	if c.seen == nil {
		c.seen = map[passwordverify.Outcome]int{}
	}
	c.seen[o]++
}

// TestHasher_F3_41_WritesTheDeclaredFormatAndTheVerifierReadsItBack — значение,
// написанное хешером, несёт параметры ручки (PWV-07.2) и читается проверяющим
// того же файла: «совпал» на том же пароле, «не совпал» на другом; объявление
// отвечает объявленному (`MeetsDeclared`).
func TestHasher_F3_41_WritesTheDeclaredFormatAndTheVerifierReadsItBack(t *testing.T) {
	declared := declaredArgon2id(65536, 3, 4)
	h, err := passwordverify.NewHasher(declared)
	require.NoError(t, err)
	v, err := h.Hash("correct horse battery staple")
	require.NoError(t, err)
	require.False(t, v.IsZero())

	obs := &countingObserver{}
	verifier, err := passwordverify.New(2, obs)
	require.NoError(t, err)
	res := verifier.Verify(v, "correct horse battery staple")
	require.Equal(t, passwordverify.OutcomeMatched, res.Outcome)
	require.Equal(t, domain.PasswordHashFormatArgon2id, res.Format)
	require.Equal(t, uint32(65536), res.Params[domain.CostParamArgon2Memory])
	require.Equal(t, uint32(3), res.Params[domain.CostParamArgon2Iterations])
	require.Equal(t, uint32(4), res.Params[domain.CostParamArgon2Parallelism])
	require.Equal(t, passwordverify.OutcomeMismatched, verifier.Verify(v, "wrong").Outcome)

	meets, err := verifier.MeetsDeclared(v, declared)
	require.NoError(t, err)
	require.True(t, meets, "значение хешера отвечает своему объявлению")
	meets, err = verifier.MeetsDeclared(v, declaredArgon2id(131072, 3, 4))
	require.NoError(t, err)
	require.False(t, meets, "объявление строже — значение ему не отвечает (PWV-11.4)")

	v2, err := h.Hash("correct horse battery staple")
	require.NoError(t, err)
	require.NotEqual(t, v.Reveal(), v2.Reveal(), "соль случайна: два значения одного пароля различны")
}

// TestHasher_F3_41_RefusesAnUndeclaredOrUnwritableFormat — страж ручки у хешера
// тот же, что у стража старта: только читаемый формат, потолок, пол, незаданный
// параметр — отказ, а не молчаливая подстановка.
func TestHasher_F3_41_RefusesAnUndeclaredOrUnwritableFormat(t *testing.T) {
	_, err := passwordverify.NewHasher(passwordverify.Declared{
		Format: domain.PasswordHashFormatBcrypt,
		Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamBcryptCost: 12},
	})
	require.Error(t, err, "bcrypt только читаемый (PWV-16.1)")
	_, err = passwordverify.NewHasher(declaredArgon2id(1<<30, 3, 4))
	require.Error(t, err, "выше потолка (PWV-16.2)")
	_, err = passwordverify.NewHasher(declaredArgon2id(1024, 3, 4))
	require.Error(t, err, "ниже пола (PWV-16.3)")
	_, err = passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id})
	require.Error(t, err, "параметры не заданы (PWV-16.4)")
	h, err := passwordverify.NewHasher(declaredArgon2id(65536, 3, 4))
	require.NoError(t, err, "записываемый между полом и потолком — старт (PWV-16.5)")
	_, err = h.Hash("")
	require.Error(t, err, "пустой пароль не хешируется")
}

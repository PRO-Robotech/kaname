// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_repo_limit_test.go — авторитет о базовом секрете не
// собирается без объявленного предела на обращение к базе (задача kaname#379).
//
// Предел — у оператора, а не у вызывающего: вызывающих у авторитета больше
// одного (глаголы внутреннего слушателя и полоса докер-реестра), и предел,
// выставленный у каждого по отдельности, у одного из них рано или поздно не
// появится — молча. Поэтому отказ здесь — отказ ПОСТРОЕНИЯ: авторитет без
// предела не существует вовсе.
package pg_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// basicAuthorityCallLimit — предел на обращение, с которым пробы пакета
// собирают авторитет. Меньше предела корня: проба, упирающаяся в предел, не
// должна ждать его полностью, а величину корня утверждает проба сборки корня.
const basicAuthorityCallLimit = time.Second

// newBasicAuthority собирает авторитет так, как его собирает корень: над
// пулом и с объявленным пределом.
func newBasicAuthority(t testing.TB, pool *pgxpool.Pool) *kanamepg.BasicCredentialRepo {
	t.Helper()
	repo, err := kanamepg.NewBasicCredentialRepo(pool, basicAuthorityCallLimit)
	require.NoError(t, err, "авторитет с объявленным положительным пределом обязан собираться")
	return repo
}

// TestNewBasicCredentialRepo_RefusesAnUndeclaredCallLimit — нулевой и
// отрицательный предел отвергаются построением; положительный принимается.
func TestNewBasicCredentialRepo_RefusesAnUndeclaredCallLimit(t *testing.T) {
	for _, limit := range []time.Duration{0, -time.Second} {
		repo, err := kanamepg.NewBasicCredentialRepo(nil, limit)
		require.Errorf(t, err, "предел %s принят — обращение к базе шло бы без своего предела", limit)
		require.Nilf(t, repo, "предел %s отвергнут, а авторитет всё равно отдан", limit)
	}
	// Законный близнец: та же сборка с объявленным пределом проходит.
	repo, err := kanamepg.NewBasicCredentialRepo(nil, basicAuthorityCallLimit)
	require.NoError(t, err)
	require.NotNil(t, repo)
}

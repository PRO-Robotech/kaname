// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// family_reason_vocabulary_integration_test.go — словарь причин отзыва семейства
// в ДОМЕНЕ и в СХЕМЕ — одно множество (задача PRO-Robotech/kaname#396).
//
// Словарь закрыт дважды: `domain.FamilyRevocationReasons()` и ограничение
// `token_families_revoked_reason_ck`. Разойтись им есть чем: слово, добавленное
// в домен без ограничения, проходит пробы домена и отвергается базой на первом
// же отзыве — то есть отзыв семейства по этой причине не исполняется ни при
// каком входе, а слово, снятое из домена без ограничения, оставляет в схеме
// возможность, которой никто не пишет. Судится множество ограничения, каким его
// видит база после всей цепочки миграций, а не текст одной из них: последнее
// слово о нём принадлежит последней миграции, переписавшей ограничение.

import (
	"regexp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

var checkLiteral = regexp.MustCompile(`'([^']*)'::text`)

func TestIntegration_FamilyReasonVocabularyIsOneSetInDomainAndSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx, pool := catalogPool(t)

	var def string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT pg_get_constraintdef(c.oid)
		  FROM pg_constraint c
		  JOIN pg_class r ON r.oid = c.conrelid
		  JOIN pg_namespace n ON n.oid = r.relnamespace
		 WHERE n.nspname = 'kaname' AND r.relname = 'token_families'
		   AND c.conname = 'token_families_revoked_reason_ck'`).Scan(&def),
		"ограничение словаря причин не найдено по имени")

	var schema []string
	for _, m := range checkLiteral.FindAllStringSubmatch(def, -1) {
		schema = append(schema, m[1])
	}
	require.NotEmpty(t, schema, "НЕ ВЫПОЛНИЛОСЬ: разбор ограничения не нашёл ни одного слова: %s", def)

	var dom []string
	for _, r := range domain.FamilyRevocationReasons() {
		dom = append(dom, string(r))
	}
	slices.Sort(schema)
	slices.Sort(dom)
	t.Logf("осмотрено: слов в схеме %d, в домене %d", len(schema), len(dom))
	require.Equal(t, dom, schema,
		"словарь причин отзыва семейства в домене и в схеме — разные множества: отзыв по слову "+
			"только домена отвергается базой, слово только схемы не пишет никто")
}

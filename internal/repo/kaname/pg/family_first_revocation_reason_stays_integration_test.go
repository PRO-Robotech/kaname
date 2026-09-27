// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// family_first_revocation_reason_stays_integration_test.go — ПЕРВАЯ ПРИЧИНА
// ОТЗЫВА СЕМЕЙСТВА ОСТАЁТСЯ, в каком бы порядке ни пришли повтор кода и
// просьба клиента (задача PRO-Robotech/kaname#406; приёмка
// `docs/engineering/acceptance/client-revocation-has-its-own-family-revocation-reason.md`,
// сценарий KN-FRV-05).
//
// Журнал называет того, кто отозвал первым. Второй отзыв того же семейства —
// пустой исход, а не отказ, и причину первого он не переписывает, иначе запись
// называла бы того, кто пришёл позже. Держит это условие `revoked_at IS NULL`
// в операторе писателя; проба утверждает, что новое слово `client-revoke`
// этого свойства не обходит ни первым, ни вторым.
//
// Одновременную пару того же свойства держит
// `TestOAuthCeremonyWritersKeepTheirOutcomeUnderEitherDefault`; здесь порядок
// последовательный, и дельта двух подслучаев — ровно порядок двух отзывов.
//
// Сцены одной базы заводятся метками РАЗНОЙ длины: свёртка носителя сессии
// `ceremonyScene` выводится из длины метки, и две сцены одной длины
// столкнулись бы на уникальности носителя.
package pg_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestOAuthCeremonyRepo_KN_FRV_05_TheFirstRevocationReasonStaysInEitherOrder —
// первая причина остаётся и при «повтор кода, затем просьба клиента», и при
// обратном порядке.
func TestOAuthCeremonyRepo_KN_FRV_05_TheFirstRevocationReasonStaysInEitherOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)

	// Дано: два живых семейства P и Q в двух сценах одной базы.
	p := ceremonyScene(t, ctx, pool, "frvp")
	q := ceremonyScene(t, ctx, pool, "frvqq")
	issueCeremonyCode(t, ctx, repo, p, 0x5a1)
	issueCeremonyCode(t, ctx, repo, q, 0x5a2)
	for _, sc := range []domain.CeremonyContext{p, q} {
		reason, present := familyReason(t, pool, sc.FamilyID)
		require.True(t, present, "Дано: семейство %s заведено выдачей кода", sc.FamilyID)
		require.Nil(t, reason, "Дано: семейство %s живо", sc.FamilyID)
	}

	for _, c := range []struct {
		name          string
		family        string
		first, second domain.FamilyRevocationReason
	}{
		{"05/1 повтор кода, затем просьба клиента", p.FamilyID,
			domain.FamilyRevokedByCodeReplay, domain.FamilyRevokedByClientRevocation},
		{"05/2 просьба клиента, затем повтор кода", q.FamilyID,
			domain.FamilyRevokedByClientRevocation, domain.FamilyRevokedByCodeReplay},
	} {
		t.Run(c.name, func(t *testing.T) {
			rows, err := repo.RevokeFamily(ctx, c.family, c.first)
			require.NoError(t, err, "первый отзыв (%s) обязан пройти", c.first)
			require.EqualValues(t, 1, rows, "первый отзыв обязан отметить ровно одну строку")

			rows, err = repo.RevokeFamily(ctx, c.family, c.second)
			require.NoError(t, err, "второй отзыв (%s) обязан быть пустым исходом, а не отказом", c.second)
			require.EqualValues(t, 0, rows, "второй отзыв не вправе отметить строку ещё раз")

			reason, present := familyReason(t, pool, c.family)
			require.True(t, present, "семейство %s обязано остаться строкой", c.family)
			require.NotNil(t, reason, "семейство %s обязано быть отозвано", c.family)
			require.Equal(t, string(c.first), *reason, "журнал обязан называть того, кто отозвал первым")
		})
	}
}

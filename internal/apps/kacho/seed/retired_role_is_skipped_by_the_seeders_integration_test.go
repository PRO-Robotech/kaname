// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed_test

// retired_role_is_skipped_by_the_seeders_integration_test.go — ДОСЕВ СТАРТА
// ПРОПУСКАЕТ снятую роль, а не упирается в её ключ живости.
//
// Задача продукта #1913, находка `system-design-reviewer` при ревью отзыва роли.
//
// # Предмет — СТЫК, а не одна из сторон
//
// Обе стороны верны по отдельности, и неверна их РАЗНИЦА
// (`architecture.md` §«Параллельные полосы одного механизма»):
//
//	отзыв роли      помечает строку `live = false` и НЕ трогает ни `is_system`,
//	                ни `rules`: форма отзыва — пометка, а не удаление;
//	досев старта    отбирает роли предикатом `is_system AND rules …`, о живости
//	                не спрашивая, — и до появления ключей живости это было
//	                безобидно.
//
// С ключами `role_rule_selectors_role_live_fk` и `role_verb_role_live_fk` вставка
// проекции под снятой ролью отвергается `23503`. Радиус — не одна роль: досев
// селекторов идёт ВНУТРИ транзакции досева владельческих выдач, поэтому отказ
// откатывает ВСЮ её, включая посев субъектов-владельцев и эмиссию кортежей
// иерархии — для ВСЕХ системных ролей.
//
// Хуже того, состояние ПОСТОЯННО: снятая роль сохраняет `is_system` и `rules`
// навсегда, поэтому следующий старт даёт то же самое, а журнал обещает повтор
// («sweep/next boot will retry»). Это `security.md` §Hardening, п. 8 дословно:
// мягкий проход не отличает настройку от сбоя.
//
// # Что здесь утверждается
//
// Снятая роль ПРОПУСКАЕТСЯ: её строк проекции нет, и досев проходит целиком.
// Живая роль рядом — положительный контроль: без него «прошло» зеленело бы на
// досеве, не делающем ничего.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// retireProbeRole помечает роль снятой ровно так, как это делает производитель:
// сперва проекции, потом пометка — порядок держит ключ.
func retireProbeRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) {
	t.Helper()
	for _, table := range []string{"role_verb", "role_rule_ref", "role_rule_selectors",
		"access_binding_target_members"} {
		_, err := pool.Exec(ctx,
			`DELETE FROM kacho_iam.`+table+` WHERE role_id = $1`, id)
		require.NoErrorf(t, err, "снятие проекции %s", table)
	}
	_, err := pool.Exec(ctx, `
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба', retired_by = 'проба'
		 WHERE id = $1`, id)
	require.NoError(t, err, "пометка роли снятой")
}

// TestRetiredRoleIsSkippedBySelectorSeeding — досев селекторов не упирается в
// снятую роль.
//
// Утверждается ПАРА: досев проходит, и строк снятой роли не появилось. Одного
// «прошёл» мало — он был бы верен и у досева, не написавшего ничего.
func TestRetiredRoleIsSkippedBySelectorSeeding(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Docker")
	}
	ctx, pool := newReseedPool(t)

	live := seedProbeSystemRole(t, ctx, pool, "rol-skip-live", "iam.skiplive", materializingRules)
	gone := seedProbeSystemRole(t, ctx, pool, "rol-skip-gone", "iam.skipgone", materializingRules)

	// Роль снимается ПОСЛЕ посева: до ключей живости она ничем не отличалась.
	retireProbeRole(t, ctx, pool, gone)

	err := bootSeedLanes(ctx, pool)
	require.NoError(t, err,
		"досев старта отказал на снятой роли: её проекция отвергнута ключом живости, "+
			"и откат унёс ЧУЖУЮ работу — посев владельческих выдач для всех системных "+
			"ролей. Снятая роль обязана быть ПРОПУЩЕНА, а не отвергнута")

	var goneSelectors, goneVerbs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, gone).
		Scan(&goneSelectors))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, gone).Scan(&goneVerbs))
	assert.Zero(t, goneSelectors, "у снятой роли появились селекторы: право вернулось")
	assert.Zero(t, goneVerbs, "у снятой роли появилась проекция глаголов: право вернулось")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него утверждения выше зеленели бы на досеве,
	// не написавшем ни строки.
	var liveSelectors, liveVerbs int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_rule_selectors WHERE role_id = $1`, live).
		Scan(&liveSelectors))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_verb WHERE role_id = $1`, live).Scan(&liveVerbs))
	assert.Positive(t, liveSelectors,
		"живая роль не получила селекторов — досев не сделал ничего, и пропуск снятой "+
			"выше ничего не утверждает")
	assert.Positive(t, liveVerbs, "живая роль не получила проекции глаголов — то же самое")

	t.Logf("перепись: у живой роли селекторов %d, пар %d; у снятой — %d и %d",
		liveSelectors, liveVerbs, goneSelectors, goneVerbs)
}

// TestRetiredRoleIsSkippedByOwnerBindingBackfill — досев ВЛАДЕЛЬЧЕСКИХ ВЫДАЧ не
// откатывается из-за снятой роли.
//
// Полоса отдельная и проба отдельная: досев селекторов идёт ВНУТРИ этой
// транзакции, поэтому его отказ уносит работу, к ролям отношения не имеющую, —
// посев субъектов-владельцев. Утверждается именно она, а не селекторы.
func TestRetiredRoleIsSkippedByOwnerBindingBackfill(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Docker")
	}
	ctx, pool := newReseedPool(t)

	_ = seedProbeSystemRole(t, ctx, pool, "rol-bf-live", "iam.bflive", materializingRules)
	gone := seedProbeSystemRole(t, ctx, pool, "rol-bf-gone", "iam.bfgone", materializingRules)
	retireProbeRole(t, ctx, pool, gone)

	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "bf")

	require.NoError(t, bootBindingsAndVerbs(ctx, pool),
		"досев владельческих выдач откатился из-за снятой роли: радиус отказа — вся "+
			"транзакция, а не одна роль")

	// НЕСУЩЕЕ: чужая работа той же транзакции ДОЕХАЛА.
	var owners int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_bindings WHERE resource_id = $1`, accID).
		Scan(&owners))
	assert.Positive(t, owners,
		"владельческой выдачи у аккаунта нет: откат унёс работу, которая к снятой роли "+
			"не имеет отношения вовсе")
	t.Logf("перепись: владельческих выдач у аккаунта %d", owners)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// reconcile_skips_a_retired_role_integration_test.go — РЕКОНСАЙЛЕР пропускает
// снятую роль, а не упирается в её ключ живости.
//
// Задача продукта #1913, находка `db-architect-reviewer` при ревью отзыва роли.
//
// # Предмет — третий экземпляр ОДНОГО класса
//
// Отзыв есть ПОМЕТКА: `rules` у снятой роли остаются прежними навсегда. Всякий,
// кто отбирает роли предикатом без живости, достаёт снятую и вычисляет по её
// правилам непустой желаемый состав — а его вставку отвергает ключ
// `access_binding_target_members_role_live_fk` (`23503`).
//
// Двух других писателей — досев селекторов и пересчёт проекции глаголов — эта
// линия уже сузила. Реконсайлер третий, и он опаснее обоих: он идёт на ПУТИ
// ЗАПРОСА, а `23503` в его полосе не классифицируется нигде и уезжает
// обёрнутым.
//
// # Пропуск верен ПО СУЩЕСТВУ, а не только по последствиям
//
// Снятая роль не даёт НИЧЕГО — это и есть случай «нет покрытия», который
// реконсайлер уже обрабатывает пустой доменной ролью. Оживление возвращает роль
// в множество само, поэтому своего восстановителя составу цели заводить не надо.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// TestReconcileSkipsARetiredRole — проход по выдаче на снятую роль ПРОХОДИТ и
// снимает материализованный состав.
//
// Утверждается ТРОЙКА, и ни одно из трёх не выводится из двух других:
// материализация до снятия непуста (положительный контроль — без него всё
// последующее зеленело бы на пустом множестве); проход после снятия не
// отказывает; состав снят.
func TestReconcileSkipsARetiredRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие С ПРЕДЕЛОМ, а не отложенное: проба, упавшая внутри открытой
	// транзакции, соединение не вернёт, и `defer pool.Close()` ждал бы его вечно,
	// унося вердикт ВСЕГО пакета — то есть стирая и ту находку, которая
	// сработала. Гейт `TestPoolCloseInTestsIsBounded` держит это по дереву.
	pgtest.ClosePoolAtEnd(t, pool)

	fx := setupGamma(t, ctx, pool, "retsk")
	rec, _ := newReconciler(pool)

	rule := forwardAnchorRule()
	fp := rule.Fingerprint()
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, "retskrole", domain.Rules{rule})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)

	now := time.Now()
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRet", string(fx.prj), string(fx.accID), nil, now)

	require.NoError(t, rec.ReconcileBindingForward(ctx, bid))

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: состав материализован. Без него утверждения ниже
	// зеленели бы на выдаче, не давшей ни одной строки.
	_, ok := memberStatusByRule(t, ctx, pool, bid, fp, "compute.instance", "iRet")
	require.True(t, ok,
		"состав цели не материализован до снятия — предмета для пробы не создано")

	// СНЯТИЕ роли: проекции прочь, потом пометка. Порядок держит ключ.
	for _, table := range []string{"role_verb", "role_rule_ref", "role_rule_selectors",
		"access_binding_target_members"} {
		_, derr := pool.Exec(ctx,
			`DELETE FROM kacho_iam.`+table+` WHERE role_id = $1`, string(roleID))
		require.NoErrorf(t, derr, "снятие проекции %s", table)
	}
	_, err = pool.Exec(ctx, `
		UPDATE kacho_iam.roles
		   SET live = false, retired_at = now(), retired_reason = 'проба', retired_by = 'проба'
		 WHERE id = $1`, string(roleID))
	require.NoError(t, err, "пометка роли снятой")

	// НЕСУЩЕЕ: проход не отказывает.
	require.NoError(t, rec.ReconcileBindingForward(ctx, bid),
		"проход по выдаче на СНЯТУЮ роль отказал: её правила целы, поэтому желаемый "+
			"состав вычисляется непустым, а вставку отвергает ключ живости — и 23503 в "+
			"этой полосе не классифицируется нигде")

	var members int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.access_binding_target_members WHERE role_id = $1`,
		string(roleID)).Scan(&members))
	assert.Zero(t, members,
		"состав цели снятой роли материализован заново: право вернулось через "+
			"реконсайлер, минуя отзыв")
	t.Logf("перепись: строк состава цели у снятой роли %d", members)
}

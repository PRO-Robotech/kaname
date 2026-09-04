// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// selector_liveness_refusal_reaches_the_caller_integration_test.go — текст
// СТРАЖА ЖИВОСТИ селектора доезжает до вызывающего ЧЕРЕЗ ПИСАТЕЛЯ (#2011).
//
// # Что здесь утверждается и чего не утверждает соседняя проба
//
// Проба приведения (`pgmaperr_selector_liveness_lane_test.go`) подаёт отказ
// СИНТЕТИЧЕСКИЙ: она знает, что́ приведение сделает с данным сообщением, и не
// знает, производит ли базa это сообщение вовсе. Проба триггера
// (`role_rule_selector_types_live_integration_test.go`) знает обратное: она
// читает отказ СЫРЫМ, минуя писателя и приведение.
//
// Между ними шов, и дефект #2011 жил ровно в нём: обе стороны были зелены, а
// вызывающий получал «Illegal argument: value violates a constraint». Здесь
// пробегается ВСЯ цепочка — писатель роли → отказ базы → приведение — и
// утверждается то, что увидит арендатор.
//
// # Почему `compute.disk`, а не снятие глаголом
//
// Строка снята ПОСЕВОМ миграции, то есть предпосылка не зависит ни от порядка
// проб, ни от применителя: снимать нечего, ждать нечего, гонки нет. Предмет
// пробы — текст отказа, и заводить ради него применение значило бы смешать с
// ним второй предмет.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// replaceSelectorsThrough — правка правил роли НАСТОЯЩИМ писателем в своей
// транзакции записи. Своя, а не проба-обёртка: приведение отказа принадлежит
// писателю, и вокруг него его не воспроизвести.
func replaceSelectorsThrough(t *testing.T, repo *kachopg.Repository,
	role domain.RoleID, fp string, types []string) error {
	t.Helper()
	ctx := t.Context()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	if rerr := w.RolesW().ReplaceRuleSelectors(ctx, role, []domain.RuleSelector{{
		RuleFP: fp, Arm: domain.ArmAnchor, ObjectTypes: types,
	}}); rerr != nil {
		_ = w.Rollback(ctx)
		return rerr
	}
	return w.Commit(ctx)
}

func TestSelectorLivenessRefusalReachesTheCallerWithElementAndRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	// ПРЕДПОСЫЛКА — факт каталога, а не наше допущение о нём: снятой строки нет ⇒
	// отвергать нечего, и всё ниже вакуумно.
	var retired int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kacho_iam.catalog_resource
		 WHERE dotted = 'compute.disk' AND NOT live`).Scan(&retired))
	require.Equalf(t, 1, retired, "ПРЕДПОСЫЛКА НАРУШЕНА: снятой строки compute.disk в каталоге нет")

	role := catalogRole(t, ctx, pool, "n1refusal")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип проходит. Без него утверждение ниже
	// зеленело бы на писателе, отвергающем всякую запись.
	require.NoError(t,
		replaceSelectorsThrough(t, repo, role, "fp-live", []string{"compute.instance"}),
		"контроль: живой тип отвергнут — писатель судит не то, что объявляет")

	err := replaceSelectorsThrough(t, repo, role, "fp-dead", []string{"compute.disk"})
	require.Error(t, err, "селектор со СНЯТЫМ типом записан")
	require.ErrorIs(t, err, iamerr.ErrInvalidArg,
		"класс отказа не «вход негоден»: вызывающему сказано не то, что делать дальше")

	got := iamerr.StripSentinel(err)
	t.Logf("вызывающий видит: %q", got)

	require.Containsf(t, got, "compute.disk",
		"отказ не называет ЭЛЕМЕНТ (%q) — автор правила пойдёт перечитывать массив целиком", got)
	require.Containsf(t, got, string(role),
		"отказ не называет РОЛЬ (%q) — при правке нескольких ролей одним заходом чинить нечего", got)
	require.NotEqualf(t, "Illegal argument: value violates a constraint", got,
		"вызывающий получил ОБЩИЙ текст: обе координаты потеряны приведением")

	// Текст доезжает ДОСЛОВНО тем, каким его составил производитель: второго
	// объявления этого текста в дереве не заводится.
	require.Truef(t, strings.HasPrefix(got, "object_types: "),
		"текст не тот, что производит страж живости (%q)", got)
}

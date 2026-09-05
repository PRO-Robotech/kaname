// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_roles_apply_integration_test.go — ВТОРАЯ половина предиката #2010:
// роль, объявленная ТОЛЬКО доставленным манифестом, после прохода пути старта
// лежит в базе.
//
// # Чем эта проба отличается от соседней и почему её было мало
//
// Применитель ролей уже доведён до настоящего Postgres
// (`services/iam/internal/repo/kacho/pg/module_roles_applier_integration_test.go`)
// и прогнан по всем манифестам дерева сверкой `moduleroleparity`. Обе зелены — и
// обе оставались зелёными ровно тогда, когда объявленная роль до базы НЕ
// доезжала: они зовут применитель САМИ, а на пути старта его не звал никто.
//
// Здесь позван КОД ПУТИ СТАРТА — `buildModuleRoleRights` и
// `applyDeliveredModuleRoles`, — то есть ровно то, чего не было. Подставлять
// сюда свой производитель правил либо свой исполнитель транзакций значило бы
// проверять свою подстановку: репозиторий настоящий, мост настоящий, каталожный
// факт собран из ЖИВЫХ строк базы, каталог прав — встроенный.
//
// # Утверждается ПАРА, а не «строка появилась»
//
// Отрицательный контроль стоит ПЕРВЫМ: до применения строки роли в базе нет.
// Без него утверждение «строка есть» зеленело бы и на роли, которую записала
// миграция, — то есть ровно на том состоянии, ради ухода от которого заведён
// манифест. Положительный контроль — вторым: после применения строка есть, её
// имя и назначение приехали из объявления, а проекция объявленных сегментов
// легла в той же транзакции.
//
// Проба РОНЯЕТСЯ дефектом #2010 by construction: сделай
// `applyDeliveredModuleRoles` пустым — и «после применения» станет равно «до».

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// bootRolesTestDSN — свежая база с проигранной цепочкой миграций iam и с
// `search_path`, который ставит себе сам сервис.
//
// Без него запрос пробы ищет `roles` в `public` и получает «отношения не
// существует» — отказ, который читается как дефект продукта, а является
// дефектом ПРОБЫ: схема сервиса `kacho_iam`, и адресуется она путём поиска, а не
// именем в каждом запросе.
//
// Клауза берётся у ОБЩЕГО помощника, а не собирается здесь: собранная на месте,
// она разошлась бы с ним молча — и разошлась бы именно там, где расхождение не
// видно, потому что обе формы дают рабочее соединение на исправном дереве.
func bootRolesTestDSN(t testing.TB) string {
	t.Helper()
	return pgtest.WithSearchPath(pgtest.NewDB(t), "kacho_iam,public")
}

// bootRolesOnLiveBase — то, что собирает путь старта, собранное ТЕМИ ЖЕ
// вызовами: живой пул, настоящий репозиторий, каталожный факт из живых строк,
// встроенный каталог прав.
func bootRolesOnLiveBase(t *testing.T) (
	context.Context, *pgxpool.Pool, *moduleroles.Applier, *slog.Logger,
) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, bootRolesTestDSN(t))
	require.NoError(t, err)
	// Закрытие — С ПРЕДЕЛОМ: проба, упавшая внутри открытой транзакции,
	// соединение не вернёт, и отложенное закрытие ждало бы его вечно, унося
	// вердикт ВСЕГО пакета.
	pgtest.ClosePoolAtEnd(t, pool)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	// Каталожный факт — из ЖИВЫХ строк, ровно как на старте: там их читает страж
	// паритета, здесь тот же читатель. Литерал сюда подставлять нельзя — проба
	// перестала бы утверждать что-либо о базе.
	live, lerr := kachopg.NewCatalogRepo(pool).ReadLiveCatalog(ctx)
	require.NoError(t, lerr, "живые строки каталога обязаны читаться: без них "+
		"производитель правил роли не собирается вовсе")

	reg, rerr := seed.LoadPermissionRegistry(ctx, logger)
	require.NoError(t, rerr)

	rights, actions, unattributed, berr := buildModuleRoleRights(live, reg)
	require.NoError(t, berr, "производитель правил роли обязан собраться на живом каталоге")
	t.Logf("производитель правил: действий каталога %d · записей вне формы модуля %d",
		actions, unattributed)
	require.NotZero(t, actions, "ноль действий каталога — полнота поимённого перечня "+
		"считалась бы по НУЛЮ классов, то есть тривиально: вердикт был бы беспредметен")

	return ctx, pool, moduleroles.NewApplier(moduleroles.NewRepoTxRunner(kachopg.New(pool, nil)), rights), logger
}

// countBootRoleRows — строк роли по её идентификатору.
func countBootRoleRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM roles WHERE id = $1`, string(id)).Scan(&n))
	return n
}

// countBootRuleRefs — строк проекции объявленных сегментов у роли.
func countBootRuleRefs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM role_rule_ref WHERE role_id = $1`, string(id)).Scan(&n))
	return n
}

// TestIAM2010_BootPathWritesARoleDeclaredOnlyByTheDeliveredManifest — предикат
// снятия #2010 целиком.
func TestIAM2010_BootPathWritesARoleDeclaredOnlyByTheDeliveredManifest(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool, applier, logger := bootRolesOnLiveBase(t)

	// Имя несёт номер задачи: роль заведомо не из миграции, и совпасть с
	// посеянной она не может.
	const roleID = "vpc.probe2010.admin"
	id := domain.SystemRoleID(domain.RoleName(roleID))

	declared := &manifest.Manifest{
		Module: "vpc",
		Roles: []manifest.Role{{
			ID:          roleID,
			Description: "Роль, объявленная ТОЛЬКО доставленным манифестом.",
			Tier: &manifest.Tier{
				TierType: domain.ScopeTypeClusterDotted,
				TierID:   domain.ClusterSingletonID,
			},
			Rules: []manifest.Rule{{
				Module: "vpc", Resources: []string{"network"}, Classes: []string{"get"},
			}},
		}},
	}

	// ── Отрицательный контроль: до применения строки НЕТ ────────────────────
	//
	// Он первый и он несущий: без него утверждение «строка есть» зеленело бы на
	// роли, записанной миграцией, — то есть на том самом состоянии, уход от
	// которого и есть предмет манифеста.
	require.Zero(t, countBootRoleRows(t, ctx, pool, id),
		"роль %s не объявлена ни одной миграцией — до применения её быть не может; "+
			"строка здесь означала бы, что проба утверждает о чужом писателе", roleID)

	// ── Путь старта: применение доставленного ───────────────────────────────
	require.NoError(t,
		applyDeliveredModuleRoles(ctx, logger, applier, []*manifest.Manifest{declared}),
		"применение доставленного манифеста обязано пройти: отказ здесь есть ОТКАЗ ПУСКА")

	// ── Положительный контроль: строка есть, и она приехала из ОБЪЯВЛЕНИЯ ────
	assert.Equal(t, 1, countBootRoleRows(t, ctx, pool, id),
		"роль, объявленная доставленным манифестом, после прохода пути старта обязана "+
			"лежать в базе — ровно этого не было до #2010: применитель существовал и не был позван")

	var name, description string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT name, description FROM roles WHERE id = $1`, string(id)).Scan(&name, &description))
	assert.Equal(t, roleID, name, "имя роли берётся из объявления ДОСЛОВНО: "+
		"иное написание дало бы другой id и разорвало бы выдачи")
	assert.Equal(t, "Роль, объявленная ТОЛЬКО доставленным манифестом.", description,
		"объявленное назначение обязано доехать до строки")

	assert.Equal(t, 1, countBootRuleRefs(t, ctx, pool, id),
		"проекция объявленного сегмента пишется в ТОЙ ЖЕ транзакции, что строка роли: "+
			"без неё правило пережило бы свой референт")

	// ── Повторный проход старта — ШТАТНЫЙ режим ─────────────────────────────
	//
	// Под перезапускается по любой причине, и применение обязано быть
	// идемпотентным: иначе первый же перезапуск роняет пуск.
	require.NoError(t,
		applyDeliveredModuleRoles(ctx, logger, applier, []*manifest.Manifest{declared}),
		"повторный проход пути старта обязан пройти: под перезапускается штатно")
	assert.Equal(t, 1, countBootRoleRows(t, ctx, pool, id),
		"повторный проход не заводит второй строки")
	assert.Equal(t, 1, countBootRuleRefs(t, ctx, pool, id),
		"повторный проход не удваивает проекцию сегментов")
}

// TestIAM2010_BootPathRefusesWhenTheRightsProducerCannotBeBuilt — премиса
// сборки: производитель правил либо годен, либо не существует.
//
// Отказ, а не пустой производитель: перечень, полный по НУЛЮ классов, полон
// тривиально, и поимённое право свелось бы к пустому набору классов — то есть
// молча. Это отрицательный близнец положительного контроля выше, и он меняет
// РОВНО один факт: каталог прав не подан.
func TestIAM2010_BootPathRefusesWhenTheRightsProducerCannotBeBuilt(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, bootRolesTestDSN(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	live, lerr := kachopg.NewCatalogRepo(pool).ReadLiveCatalog(ctx)
	require.NoError(t, lerr)

	// Положительный близнец — тот же живой каталог с поданным реестром — стоит в
	// пробе выше и там зелен; здесь снят РОВНО реестр.
	_, _, _, berr := buildModuleRoleRights(live, nil)
	require.Error(t, berr, "производитель правил, собранный БЕЗ каталога прав, обязан "+
		"быть отказом, а не пустым перечнем: полнота по нулю классов тривиальна")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// permissions_window_test.go — класс B приёмки
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md`
// (§2.1 класс B, §2.4 окно, §4.3 и §4.5, сценарии KAN-SEED-1-10 и -11).
//
// # ПРЕДМЕТ
//
// Имя системной роли — КЛЮЧ ДИСПЕТЧЕРИЗАЦИИ: по нему `PermissionsForRole`
// решает, во что разворачиваются права. Переименование строки в базе и разбор в
// коде разъезжаются на время перехода, и разъезжаются МОЛЧА: на неизвестном
// имени разбор возвращает `nil`, то есть «прав нет» — синтаксически верный
// ответ, неотличимый от честного «у этой роли прав не объявлено».
//
// Поэтому окно утверждается ОБЕИМИ сторонами сразу, а не одной: прежнее
// написание обязано продолжать разворачиваться (манифесты чужих продуктов ещё
// не переведены, П3), объявленное — разворачиваться уже (строку переводит
// миграция этой же волны).
package seed_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	seedpkg "github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TestPermissionsForRole_WindowAcceptsBothSpellings — KAN-SEED-1-10/-11: оба
// написания каждой из двух ролей разворачиваются ОДИНАКОВО.
//
// Сверяется РАВЕНСТВО двух ответов, а не непустота каждого: непустота зеленела
// бы на разборе, который вернул одно и то же по случайной причине, а предмет
// окна — именно то, что обе полосы ведут в одну.
func TestPermissionsForRole_WindowAcceptsBothSpellings(t *testing.T) {
	reg, err := seedpkg.LoadPermissionRegistry(context.Background(), slog.Default())
	require.NoError(t, err, "каталог прав не загружен — о разборе имени не известно ничего")

	for _, rename := range domain.SeedIdentityWindow() {
		if rename.Previous != "kacho-system.admin" && rename.Previous != "kacho-system.viewer" {
			continue // окно шире класса B: аккаунт и служебная запись разбором прав не читаются
		}
		previous := reg.PermissionsForRole(rename.Previous)
		declared := reg.PermissionsForRole(rename.Declared)

		require.NotEmpty(t, previous,
			"прежнее написание %q перестало разворачиваться: манифесты чужих продуктов "+
				"ещё присылают его (П3), и «прав нет» неотличимо от честного ответа",
			rename.Previous)
		require.NotEmpty(t, declared,
			"объявленное написание %q не разворачивается: строку переводит миграция этой "+
				"же волны, и после перевода роль осталась бы без прав",
			rename.Declared)
		require.Equal(t, previous, declared,
			"написания %q и %q разворачиваются ПО-РАЗНОМУ — это два объявления об одном "+
				"предмете, и расходятся они молча", rename.Previous, rename.Declared)
	}
}

// TestPermissionsForRole_ThirdSpellingIsNotAccepted — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к
// окну: оно расширяет приём ровно на объявленные пары.
//
// Без этой пробы утверждение выше зеленело бы на разборе, который отвечает
// «права есть» на ЛЮБОЕ имя, — то есть на снятой диспетчеризации.
func TestPermissionsForRole_ThirdSpellingIsNotAccepted(t *testing.T) {
	reg, err := seedpkg.LoadPermissionRegistry(context.Background(), slog.Default())
	require.NoError(t, err)

	for _, name := range []string{"system", "kacho-system", "system.admin.viewer", "admin"} {
		require.Nil(t, reg.PermissionsForRole(name),
			"имя %q развернулось в права, хотя окно его не объявляет: приём расширен "+
				"шире пары написаний", name)
	}
}

// TestSeedIdentitySpellings_IsSymmetricAndNarrow — окно объявлено ОДИН раз, и
// отношение симметрично.
//
// Асимметричное окно приняло бы манифест чужого продукта и отвергло свой
// собственный, уже переведённый, — а перевод идёт своим порядком (П3).
func TestSeedIdentitySpellings_IsSymmetricAndNarrow(t *testing.T) {
	window := domain.SeedIdentityWindow()
	require.NotEmpty(t, window, "окно пусто — утверждать о нём нечего")

	for _, rename := range window {
		require.NotEqual(t, rename.Previous, rename.Declared,
			"запись окна %q беспредметна: прежнее написание равно объявленному", rename.Previous)
		require.NotEmpty(t, rename.Subject,
			"запись окна %q не называет читателя, ради которого существует — "+
				"послабление без предмета не истечёт само", rename.Previous)

		require.ElementsMatch(t, []string{rename.Previous, rename.Declared},
			domain.SeedIdentitySpellings(rename.Previous))
		require.ElementsMatch(t, []string{rename.Previous, rename.Declared},
			domain.SeedIdentitySpellings(rename.Declared))
	}

	// Имя вне окна возвращается ОДНИМ элементом: окно ничего не решает про
	// остальные имена, и расширять запрос по ним значило бы резолвить чужую
	// строку.
	require.Equal(t, []string{"module-quota-readers"},
		domain.SeedIdentitySpellings("module-quota-readers"))
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// module_catalog_confirmation_shape_integration_test.go — СОСТАВ ПОДТВЕРЖДЕНИЯ:
// чему оно обязано быть слепо и к чему чувствительно.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.5; сценарии `IAM-MA-1-16` и `-17` — их предикат.
// Задача продукта #1034.
//
// # Что здесь утверждается
//
// НЕОБХОДИМОЕ УСЛОВИЕ для подтверждения, каким бы ни был его алгоритм:
//
//	`-16`  движение АРЕНДАТОРСКИХ ролей подтверждение НЕ обесценивает — иначе
//	       план протухал бы от чужого цикла создания и удаления роли, то есть
//	       от действия, к каталогу отношения не имеющего
//	`-17`  смена ФОРМЫ живой строки каталога подтверждение обесценивает — иначе
//	       применение сделало бы не то, что показал план
//
// Пара `-16`/`-17` и есть предикат правильности состава: порознь каждая половина
// выполнима тривиально — подтверждением-константой (слепо ко всему) либо
// подтверждением по всей базе (чувствительно ко всему).
//
// # Почему шестиТАБЛИЧНЫЙ отпечаток соседней пробы в подтверждение НЕ ГОДИТСЯ
//
// `stateFingerprint` (`module_catalog_applier_integration_test.go`) считает по
// шести таблицам, включая проекции ролей: его предмет — «изменилось ли хоть
// что-нибудь», и для атомарности это верный вопрос. Как подтверждение он неверен,
// и здесь это ИЗМЕРЯЕТСЯ, а не объявляется: он меняется от заведения
// арендаторской роли, то есть провалил бы `-16` на первом же арендаторе.
//
// # Что здесь ЗЕЛЕНО, и чего здесь НЕТ
//
// Проба зелена и до работы, и после — она характеризующая: утверждается свойство
// ТАБЛИЦ, а не производителя. Самого подтверждения здесь нет: `expected_state`
// принадлежит use-case глагола, у которого путь старта подтверждения не несёт
// вовсе (`ApplyAll` его не получает и получить не может), поэтому требовать его
// от применителя значило бы утверждать неверное. Сценарии `-13`, `-14`, `-18`
// этой пробой НЕ покрыты: у подтверждения нет входной поверхности.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestModuleStateIsBlindToTenantMovementAndSensitiveToCatalogForm — предикат
// состава подтверждения, обе половины сразу.
func TestModuleStateIsBlindToTenantMovementAndSensitiveToCatalogForm(t *testing.T) {
	t.Run("движение арендаторских ролей состояния модуля не меняет", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		catRepo := kachopg.NewCatalogRepo(pool)
		repo := kachopg.New(pool, nil)

		census, err := seed.AssertCatalogParity(ctx, catRepo)
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
		snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
		require.NoError(t, err, "снимок каталога")

		baseModule := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
		baseWide := stateFingerprint(t, ctx, pool)

		tn := seedVerdictTenant(t, ctx, pool)
		roleID, pairs := declareRole(t, ctx, pool, repo, snap,
			tn.accountID, tn.userID, anchoredModule, spareResource)
		require.NotEmpty(t, pairs, "проекция роли пуста: движения не произошло, и сверять нечего")
		t.Logf("арендаторская роль заведена: пар проекции %d", len(pairs))

		createdModule := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
		createdWide := stateFingerprint(t, ctx, pool)

		// КОНТРОЛЬ НЕВАКУУМНОСТИ: движение действительно произошло. Без него
		// «состояние не изменилось» выполнялось бы потому, что не изменилось
		// НИЧЕГО.
		require.NotEqual(t, baseWide, createdWide,
			"заведение арендаторской роли не сдвинуло НИ ОДНОЙ из шести таблиц: "+
				"движения не было, и утверждение о слепоте вакуумно")
		require.Equal(t, baseModule, createdModule,
			"заведение арендаторской роли изменило состояние КАТАЛОГА модуля: "+
				"подтверждение такого состава протухало бы от чужого арендатора (`-16`)")

		// Вторая половина того же движения — удаление.
		_, err = pool.Exec(ctx, `DELETE FROM kacho_iam.roles WHERE id = $1`, roleID)
		require.NoError(t, err, "удалить арендаторскую роль")
		deletedModule := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
		deletedWide := stateFingerprint(t, ctx, pool)
		require.NotEqual(t, createdWide, deletedWide,
			"удаление арендаторской роли не сдвинуло НИ ОДНОЙ из шести таблиц: движения не было")
		require.Equal(t, baseModule, deletedModule,
			"удаление арендаторской роли изменило состояние КАТАЛОГА модуля (`-16`)")

		t.Logf("перепись: состояние каталога модуля неизменно на всех трёх снимках; "+
			"шеститабличный отпечаток сменился дважды (%s → %s → %s) — "+
			"как подтверждение он не годится",
			shortHash(baseWide), shortHash(createdWide), shortHash(deletedWide))
	})

	t.Run("смена формы живой строки каталога состояние модуля меняет", func(t *testing.T) {
		ctx, pool := catalogPool(t)

		_, err := seed.AssertCatalogParity(ctx, kachopg.NewCatalogRepo(pool))
		require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")

		base := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)

		// Форма строки — то, что читает `WHERE` писателя: имя типа модели прав у
		// ресурса. Правится прямым SQL: продуктом это состояние не производится
		// (§5.1 приёмки, Н10), и завести его иначе нечем.
		tag, err := pool.Exec(ctx, `
			UPDATE kacho_iam.catalog_resource SET object_type = $3
			 WHERE module = $1 AND resource = $2 AND live`,
			anchoredModule, spareResource, "vpc_probe_retyped")
		require.NoError(t, err, "сменить имя типа модели прав у живой строки")
		require.EqualValues(t, 1, tag.RowsAffected(), "правка не задела ни одной живой строки")

		retyped := moduleCatalogSnapshot(t, ctx, pool, anchoredModule)
		require.NotEqual(t, base, retyped,
			"смена имени типа модели прав состояния каталога модуля не изменила: "+
				"подтверждение такого состава приняло бы план, показанный для ДРУГОГО каталога (`-17`)")
		t.Logf("перепись: смена формы одной строки сменила состояние модуля (%s → %s)",
			shortHash(base), shortHash(retyped))
	})
}

// shortHash — первые знаки отпечатка, для читаемости переписи. Сверка идёт по
// полному значению; здесь только вывод.
func shortHash(v string) string {
	if len(v) <= 8 {
		return v
	}
	return v[:8]
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_audit_third_population_integration_test.go — СЛЕД НЕСЁТ ТРЕТЬЮ
// ПОПУЛЯЦИЮ ПОСЛЕДСТВИЙ, потому что больше её не несёт ничто.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.6 «Третья популяция потолком НЕ ограничивается» и §2.7
// строка «что несёт». Задача продукта #1034, предмет вырезания — #1942.
//
// # Почему это ОТДЕЛЬНАЯ проба, а не строка в пробе следа
//
// Предмет здесь не «след существует» (это `-29`) и не «след называет автора»
// (это `-31`), а НЕОБРАТИМОЕ, у которого нет ни потолка, ни ведомости.
//
//	переселение   ограничено ПАРОЙ потолков (§2.6) и записано в
//	              `role_grant_orphan` — то есть у него две независимые опоры
//	вырезание     потолка НЕ имеет (потолок здесь запрещал бы починку) и
//	              ведомости не имеет ВОВСЕ: предикат `grep -c orphan` по телу
//	              оператора вырезания даёт ноль. Что вырезано, не помнит ничто
//
// Значит запись аудита есть ЕДИНСТВЕННЫЙ след третьей популяции. План печатает
// три величины, `Apply` возвращает фактические — и если след их не несёт,
// оператор получает уверенность, что след останется, при том что следа нет.
// Частичная посадка здесь хуже никакой.
//
// # Почему утверждается РАВЕНСТВО переписи, а не «ключи есть»
//
// Ключ с нулём неотличим от ключа, потерявшего величину по дороге: обе стороны
// собираются в одном месте, и «ноль» — самое частое законное значение. Сверка
// идёт с ПЕРЕПИСЬЮ применения, а рядом стоит требование непустоты — иначе
// равенство нулей зеленело бы на следе, не несущем ничего.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// TestAppliedAuditRowCarriesAllThreeConsequencePopulations — след несёт ОБЕ
// величины переселения и ВСЕ ТРИ величины вырезания, и все пять равны переписи.
func TestAppliedAuditRowCarriesAllThreeConsequencePopulations(t *testing.T) {
	ctx, pool := catalogPool(t)
	ctx = verbCallerCtx(ctx)
	catRepo := kachopg.NewCatalogRepo(pool)
	repo := kachopg.New(pool, nil)
	applier := verbApplierOver(t, pool)

	census, err := seed.AssertCatalogParity(ctx, catRepo, seed.ImageAnchor())
	require.NoError(t, err, "предпосылка не создана: посеянный каталог уже разошёлся с опорой")
	snap, err := catalog.NewSnapshot(census.Live, catRepo, nil, nil)
	require.NoError(t, err, "снимок каталога")

	// Арендаторская роль, чьё правило называет снимаемый ресурс: она даёт вход
	// ОБЕИМ популяциям переселения И третьей — селектор правила называет ту же
	// строку каталога.
	tn := seedVerdictTenant(t, ctx, pool)
	_, pairs := declareRole(t, ctx, pool, repo, snap,
		tn.accountID, tn.userID, anchoredModule, spareResource)
	require.NotEmpty(t, pairs, "проекция роли пуста: последствий не будет, и след был бы о нулях")

	rules, verbs, selectors := tenantProjectionsNaming(t, ctx, pool, anchoredModule, spareResource)
	t.Logf("перепись фикстуры ДО: правил %d, выдач %d, селекторов %d", rules, verbs, selectors)
	require.Positive(t, selectors, "ТРЕТЬЯ популяция беспредметна: селектор правила не записан")

	rep, aerr := applier.Apply(ctx, verbRequest(t, ctx, pool,
		shippedManifest(t, anchoredModule, spareResource)))
	require.NoError(t, aerr, "сужающее применение отвергнуто: %s", rep)
	t.Logf("перепись применения: %s", rep)

	// Контроль невакуумности: обе группы величин НЕПУСТЫ. Без него равенство
	// ниже выполнялось бы сравнением нулей с нулями.
	require.Positive(t, rep.Resettled.RuleRefs+rep.Resettled.RoleVerbs,
		"переселения не было: сверка следа с переписью была бы о нулях")
	require.Positive(t, rep.PrunedSelectorRows+rep.PrunedSelectorRowsDropped+rep.PrunedSelectorTypes,
		"вырезания не было: ТРЕТЬЯ популяция не двинулась, и утверждать о ней нечего")

	payload := lastAuditPayload(t, ctx, pool, moduleCatalogAppliedEvent)
	t.Logf("запись аудита: %v", payload)

	// Числа приезжают из JSON, где целое становится float64.
	num := func(key string) int {
		v, ok := payload[key]
		require.Truef(t, ok, "запись аудита не несёт ключа %q: величина последствия потеряна", key)
		f, ok := v.(float64)
		require.Truef(t, ok, "ключ %q не число: %T", key, v)
		return int(f)
	}

	// ПЕРВАЯ и ВТОРАЯ популяции — у них есть ведомость сирот, но след обязан
	// называть их наравне с третьей: разбирающий последствия читает ОДНУ запись.
	require.Equal(t, rep.Resettled.RuleRefs, num("resettled_rule_refs"),
		"след разошёлся с переписью по объявлениям правила")
	require.Equal(t, rep.Resettled.RoleVerbs, num("resettled_role_verbs"),
		"след разошёлся с переписью по выдачам глаголов")

	// ТРЕТЬЯ популяция — ЕДИНСТВЕННЫЙ её след. Все три величины, а не «сколько-то
	// тронуто»: «строка укорочена» и «строка снята целиком» суть события разного
	// рода, а число элементов не выводится ни из того, ни из другого.
	require.Equal(t, rep.PrunedSelectorRows, num("pruned_selector_rows"),
		"след не несёт числа УКОРОЧЕННЫХ строк селекторов")
	require.Equal(t, rep.PrunedSelectorRowsDropped, num("pruned_selector_rows_dropped"),
		"след не несёт числа СНЯТЫХ ЦЕЛИКОМ строк селекторов")
	require.Equal(t, rep.PrunedSelectorTypes, num("pruned_selector_types"),
		"след не несёт числа ВЫРЕЗАННЫХ элементов: вырезанное не помнит больше ничто")

	// Вход глагола запись тоже несёт: без него не восстановить, что оператор
	// подтверждал и какие потолки называл, когда права были отобраны.
	require.Equal(t, verbCallerPrincipal.ID, payload["actor"], "след не называет автора действия")
	require.Equal(t, modulecatalog.SourceVerb, payload["source"], "след не называет полосу применения")
	require.NotEmpty(t, payload["expected_state"], "след не несёт подтверждения, под которым применяли")
	require.EqualValues(t, generousCeiling, payload["max_resettled_rule_refs"],
		"след не несёт потолка первой популяции")
	require.EqualValues(t, generousCeiling, payload["max_resettled_role_verbs"],
		"след не несёт потолка второй популяции")

	t.Logf("след несёт ТРИ величины третьей популяции: укорочено %d снято %d элементов вырезано %d "+
		"— и это единственное место, где они остаются",
		num("pruned_selector_rows"), num("pruned_selector_rows_dropped"), num("pruned_selector_types"))
}

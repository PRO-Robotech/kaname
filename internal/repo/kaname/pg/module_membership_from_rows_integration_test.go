// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_membership_from_rows_integration_test.go — ЧЛЕНСТВО МОДУЛЯ отвечает
// СТРОКАМИ каталога, а не литералом Go.
//
// Приёмка `services/iam/docs/engineering/acceptance/module-withdrawal-is-described.md`
// (APPROVED круга 2), сценарий **IAM-MW-1-10**; задача продукта #1927 — остаток
// #1816. До неё сценарий был помечен «отрицательный к текущему дереву»: правило,
// называющее СНЯТЫЙ модуль, принималось, потому что членство читал литерал
// `domain.knownModules`, а он о снятии не знает ничем.
//
// # Почему это ИНТЕГРАЦИОННАЯ проба, а не юнит
//
// Предмет — ДАННЫЕ: живое множество `kaname.catalog_module` и его чтение тем
// же портом, каким его читает служба. Подделка SQL здесь ничего не доказала бы:
// она отвечала бы то, что в неё положили, а спор ровно о том, откуда приходит
// ответ. Поэтому строка заводится и снимается настоящими операторами, читается
// настоящим `CatalogRepo`, и только потом из неё собирается каталожный факт.
//
// # Почему модуль `probe`, а не один из шести
//
// Проба обязана различать «домен прочитал ПОДАННЫЙ набор» и «домен ответил из
// своего перечня». На любом из шести имён платформы оба ответа совпадают, и
// зелёное получила бы и та реализация, ради снятия которой работа делалась.
// `probe` в каноне отсутствует, и его отсутствие УТВЕРЖДАЕТСЯ ниже, а не
// предполагается: без этой премисы проба зеленела бы молча в тот день, когда имя
// в канон попадёт.
//
// # Что здесь НЕ утверждается
//
// Ни транспорт, ни операция, ни права: правило судится на том же уровне, на
// котором его судит путь запроса (`domain.Rule.Validate`), и о REST-статусе эта
// проба не говорит ничего. Отзыв модуля подаётся АДМИНИСТРАТИВНЫМ путём — теми
// же операторами, какими его будет исполнять глагол (#1034), — ровно как в
// соседнем `module_withdrawal_integration_test.go`.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// membershipProbeModule — имя, которого нет НИ В ОДНОМ Go-литерале дерева. Оно и есть
// разделитель двух ответов: канон его не знает, строки — знают.
const membershipProbeModule = "probe"

// factsFromRows читает живой каталог ТЕМ ЖЕ портом, каким его читает служба, и
// собирает из него каталожный факт.
//
// Своего запроса проба не пишет намеренно: запрос, написанный здесь, отвечал бы
// на СВОЙ вопрос, а утверждать надо о том, что увидит путь запроса.
func factsFromRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *catalog.Facts {
	t.Helper()
	rows, err := kanamepg.NewCatalogRepo(pool).ReadLiveCatalog(ctx)
	require.NoError(t, err, "чтение живого каталога портом службы")
	facts, err := catalog.NewFacts(rows)
	require.NoError(t, err, "сборка каталожного факта из живых строк")
	return facts
}

// ruleNaming — минимально-законное правило, называющее модуль. Ресурс и глагол
// грамматически верны и словарём здесь не судятся: предмет пробы — сегмент
// МОДУЛЯ.
func ruleNaming(module string) domain.Rule {
	return domain.Rule{Module: module, Resources: []string{"thing"}, Verbs: []string{"get"}}
}

// TestIAMMW110_ModuleMembershipIsAnsweredByCatalogRows — IAM-MW-1-10 и его
// зеркало, ОДНИМ прогоном и на одной базе.
//
// Половин две, и порознь ни одна не доказывает предмета: «снятый отвергается»
// зеленело бы на реализации, отвергающей всё, а «заведённый строкой
// принимается» — на реализации, принимающей всё. Поэтому обе половины и
// положительный контроль живого модуля стоят рядом.
func TestIAMMW110_ModuleMembershipIsAnsweredByCatalogRows(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := catalogPool(t)

	// ── ПРЕМИСА: имени нет ни в одном Go-литерале ────────────────────────────
	//
	// Утверждается, а не предполагается. Без неё проба замолчала бы в тот день,
	// когда `probe` попадёт в канон: обе половины стали бы зелёными по причине,
	// к предмету отношения не имеющей.
	canon := authzmap.CatalogSeedModules()
	require.Falsef(t, slices.Contains(canon, membershipProbeModule),
		"премиса сценария: %q не должен быть в каноне (%v) — иначе проба не различает "+
			"«домен прочитал поданный набор» и «домен ответил из своего перечня»",
		membershipProbeModule, canon)
	require.False(t,
		domain.ModuleSetOf(canon...).IsKnownModule(membershipProbeModule),
		"канон обязан отвергать %q — на этом стоит различие двух ответов", membershipProbeModule)

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ДО ЗАВЕДЕНИЯ СТРОКИ ──────────────────────────
	//
	// Строки ещё нет, и путь запроса обязан отвергнуть правило. Без этого шага
	// «принимается после вставки» неотличимо от «принималось всегда».
	before := factsFromRows(t, ctx, pool)
	require.False(t, before.IsKnownModule(membershipProbeModule),
		"строки нет, а факт уже признаёт модуль — читается не каталог")
	err := ruleNaming(membershipProbeModule).Validate(domain.TenantPolicy(), before)
	require.Error(t, err, "правило, называющее незаведённый модуль, обязано отвергаться")
	require.Contains(t, err.Error(), "Illegal argument module (unknown module 'probe')",
		"текст отказа — часть контракта и сдвигаться не вправе")

	livePlatform := before.Modules()
	t.Logf("перепись до заведения: живых модулей %d (%s); канон объявляет %d (%s)",
		len(livePlatform), strings.Join(livePlatform, ", "), len(canon), strings.Join(canon, ", "))
	require.NotEmpty(t, livePlatform, "живой каталог пуст — обход беспредметен")

	// ── ЗАВЕДЕНИЕ СТРОКОЙ ───────────────────────────────────────────────────
	//
	// Ресурсов у модуля нет намеренно: их отсутствие делает снятие ниже
	// представимым (ключ `catalog_resource_module_live_fk` не пускает снять
	// модуль при живом ресурсе), и предмет пробы — сегмент модуля, а не пара.
	_, err = pool.Exec(ctx,
		`INSERT INTO kaname.catalog_module (module) VALUES ($1)`, membershipProbeModule)
	require.NoError(t, err, "заведение модуля строкой")
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM kaname.catalog_module WHERE module = $1`, membershipProbeModule)
	})

	seeded := factsFromRows(t, ctx, pool)
	require.True(t, seeded.IsKnownModule(membershipProbeModule),
		"строка заведена, а факт её не видит — членство отвечает не строками")
	require.NoError(t,
		ruleNaming(membershipProbeModule).Validate(domain.TenantPolicy(), seeded),
		"модуль, заведённый СТРОКОЙ и отсутствующий в любом Go-литерале, обязан "+
			"проходить проверку правила на пути запроса — это и есть предмет #1927")
	require.Len(t, seeded.Modules(), len(livePlatform)+1,
		"живых модулей стало не на один больше — читается не то множество")

	// ── СНЯТИЕ: IAM-MW-1-10 ─────────────────────────────────────────────────
	_, err = pool.Exec(ctx, `
		UPDATE kaname.catalog_module
		   SET live = false, retired_at = now(), retired_reason = 'проба IAM-MW-1-10'
		 WHERE module = $1`, membershipProbeModule)
	require.NoError(t, err, "снятие модуля строкой")

	retired := factsFromRows(t, ctx, pool)
	require.False(t, retired.IsKnownModule(membershipProbeModule),
		"модуль снят строкой, а факт всё ещё признаёт его живым")
	err = ruleNaming(membershipProbeModule).Validate(domain.TenantPolicy(), retired)
	require.Error(t, err,
		"IAM-MW-1-10: правило, называющее СНЯТЫЙ модуль, обязано отвергаться на пути запроса")
	require.Contains(t, err.Error(), "Illegal argument module (unknown module 'probe')",
		"отказ приходит контракт-тоном модуля, а не чужой полосой")

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПОСЛЕ СНЯТИЯ ─────────────────────────────────
	//
	// Живой модуль обязан проходить на ТОМ ЖЕ факте: без этого отрицание выше
	// зеленело бы на реализации, отвергающей каждый модуль.
	live := livePlatform[0]
	require.NoError(t,
		ruleNaming(live).Validate(domain.TenantPolicy(), retired),
		"живой модуль %q отвергнут — отрицание выше получено даром", live)
	t.Logf("перепись после снятия: живых модулей %d; контроль на живом модуле %q пройден",
		len(retired.Modules()), live)
}

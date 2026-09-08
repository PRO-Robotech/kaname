// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_catalog_apply_audit_integration_test.go — ПРИМЕНЕНИЕ КАТАЛОГА
// ОСТАВЛЯЕТ СЛЕД, и след этот называет того, кто применил.
//
// Приёмка `services/iam/docs/engineering/acceptance/plan-confirms-what-apply-withdraws.md`
// (APPROVED круга 4), §2.7; сценарии `IAM-MA-1-29`, `-30`, `-31`.
// Задача продукта #1034.
//
// # Что здесь утверждается
//
//	`-29`  изменившее каталог применение пишет РОВНО ОДНУ запись
//	       `iam.module_catalog.applied` в ТОЙ ЖЕ транзакции; откат ⇒ записи нет
//	`-30`  не изменившее применение записи не пишет
//	`-31`  актор берётся из ПРОВЕРЕННОЙ личности; на запросе без личности
//	       применение отказывает, а `system` автором действия не становится
//
// # Почему актор — отдельный предмет, а не деталь записи
//
// `operations.PrincipalFromContext` на запросе БЕЗ личности возвращает
// `SystemPrincipal()` — это её объявленное поведение, а не дефект. Аудит,
// взявший актора ею, запишет `system` там, где действовал оператор: не пропуск,
// а ЛОЖНОЕ УТВЕРЖДЕНИЕ о том, кто это сделал. Различает состояния только
// `PrincipalFromContextOK` вторым значением, и различие обязано быть
// НАБЛЮДАЕМЫМ — иначе проба зеленела бы на реализации, берущей первую.
//
// # Что здесь КРАСНО, а что ЗЕЛЕНО
//
//	красно   `-29`: записи нет вовсе — применитель аудита не пишет
//	красно   `-31`: применение на контексте БЕЗ личности сегодня ПРОХОДИТ
//	зелено   `-30` и половина `-29` про откат — обе стоят В ПАРЕ с красными:
//	         «записи нет» само по себе выполняется тривиально, пока писателя
//	         не существует, и утверждать его в одиночку значило бы утверждать
//	         пустоту
//
// # Чего здесь НЕТ
//
// О транспорте, правах вызывающего, конверте операции, подтверждении и потолках
// — ничего. `expected_state` и оба потолка приезжают вместе с глаголом, и
// требовать их от применителя, вызванного напрямую, значило бы утверждать о
// поверхности, которой у этого пути нет.

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// moduleCatalogAppliedEvent — вид события, который называет §2.7. Форма
// удовлетворяет `audit_outbox_event_type_check`.
const moduleCatalogAppliedEvent = "iam.module_catalog.applied"

// auditProbePrincipal — ПРОВЕРЕННАЯ личность, от имени которой идёт применение.
//
// Значение отличимо от настоящего намеренно: правдоподобный идентификатор
// (крокфордова строка) совпал бы с чужим и спрятал бы дефект, который сам же и
// кормит. Ни `system`, ни `anonymous` — обе стороны `-31` иначе стали бы
// неразличимы.
var auditProbePrincipal = operations.Principal{
	Type:        "user",
	ID:          "usr-probe-module-catalog-applier",
	DisplayName: "проба применителя каталога",
}

// TestApplyChangingTheCatalogWritesOneAuditRowInItsOwnTransaction — `IAM-MA-1-29`
// и `-30`: изменившее применение оставляет ровно одну запись, не изменившее — ни
// одной, откаченное — ни одной.
//
// КРАСНАЯ проба: сегодня применитель в `audit_outbox` не пишет вовсе, и починка
// боевой базы руками остаётся неотличимой от починки глаголом.
func TestApplyChangingTheCatalogWritesOneAuditRowInItsOwnTransaction(t *testing.T) {
	ctx, pool := catalogPool(t)
	ctx = operations.WithPrincipal(ctx, auditProbePrincipal)
	applier := applierOver(t, pool)

	before := auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent)
	total := auditRowsTotal(t, ctx, pool)
	t.Logf("перепись ДО: записей вида %s — %d, всего строк аудита %d",
		moduleCatalogAppliedEvent, before, total)

	// ИЗМЕНЯЮЩЕЕ применение: манифест перестал объявлять запасной ресурс.
	changing, err := applier.Apply(ctx, shippedManifest(t, anchoredModule, spareResource))
	require.NoError(t, err, "изменяющее применение отвергнуто: %s", changing)
	require.True(t, changing.Changed(), "фикстура не изменила каталог: писать нечего — %s", changing)
	t.Logf("изменяющее применение: %s", changing)

	require.Equalf(t, before+1, auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent),
		"изменившее каталог применение не оставило РОВНО ОДНОЙ записи %s: починка боевой базы "+
			"глаголом неотличима от починки руками", moduleCatalogAppliedEvent)

	payload := lastAuditPayload(t, ctx, pool, moduleCatalogAppliedEvent)
	t.Logf("запись аудита: %v", payload)
	require.Equal(t, anchoredModule, payload["module"], "запись не называет модуль, которого касалось применение")

	// `-30`: повтор того же применения каталог не двигает, значит и записи не
	// пишет. Замок стоит ЗДЕСЬ, а не отдельной пробой: без строки выше он
	// выполнялся бы тривиально при любом применителе.
	settled := auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent)
	repeat, err := applier.Apply(ctx, shippedManifest(t, anchoredModule, spareResource))
	require.NoError(t, err)
	require.False(t, repeat.Changed(), "повтор изменил каталог: идемпотентность нарушена — %s", repeat)
	require.Equal(t, settled, auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent),
		"не изменившее каталог применение оставило запись: след перестал означать изменение")

	// Вторая половина `-29`: откаченное применение записи не оставляет. Отказ
	// настоящий и приходит от СЕРВЕРА — действие `z.bad` нарушает
	// `catalog_verb_undotted`, о котором применитель не знает.
	broken := shippedManifest(t, anchoredModule, spareResource)
	require.NotEmpty(t, broken.Resources, "манифест фикстуры пуст")
	broken.Resources[0].Verbs = append(broken.Resources[0].Verbs, manifest.Verb{Name: "z.bad"})
	_, err = applier.Apply(ctx, broken)
	require.Error(t, err, "применение с негодным действием обязано отказать")
	t.Logf("откаченное применение отвергнуто: %v", err)
	require.Equal(t, settled, auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent),
		"откаченное применение оставило запись аудита: запись живёт НЕ в транзакции применителя")
}

// TestApplyTakesTheActorFromAVerifiedIdentityOnly — `IAM-MA-1-31`: актор берётся
// из проверенной личности, а запрос без личности отвергается — `system` автором
// действия оператора не становится.
//
// Обе половины обязательны и стоят рядом: без положительной отрицание зеленело
// бы на применителе, отвергающем всё; без отрицательной положительная зеленела
// бы на применителе, подставляющем `SystemPrincipal()` каждому.
func TestApplyTakesTheActorFromAVerifiedIdentityOnly(t *testing.T) {
	t.Run("с проверенной личностью — проходит и называет её", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		ctx = operations.WithPrincipal(ctx, auditProbePrincipal)
		// Полоса ГЛАГОЛА, а не старта: предмет пробы — личность ВЫЗЫВАЮЩЕГО, а у
		// пути старта вызывающего нет by construction (применение идёт до подъёма
		// слушателей, запроса не существует) — там актор процессный и назван
		// константой. Позови эта проба путь старта, она утверждала бы о личности
		// там, где её не бывает, и обе её половины стали бы неисполнимы: отказать
		// старту не за что, а назвать чужую личность ему нечем.
		applier := verbApplierOver(t, pool)

		rep, err := applier.Apply(ctx, verbRequest(t, ctx, pool,
			shippedManifest(t, anchoredModule, spareResource)))
		require.NoError(t, err, "применение под проверенной личностью отвергнуто: %s", rep)
		require.True(t, rep.Changed(), "фикстура не изменила каталог: %s", rep)

		payload := lastAuditPayload(t, ctx, pool, moduleCatalogAppliedEvent)
		t.Logf("запись аудита: %v", payload)
		require.Equal(t, auditProbePrincipal.ID, payload["actor"],
			"актор записи не равен проверенной личности вызывающего")
	})

	t.Run("без личности — отказ, и system автором не становится", func(t *testing.T) {
		ctx, pool := catalogPool(t)
		applier := verbApplierOver(t, pool)

		// Контекст БЕЗ личности — тот самый вход, на котором
		// `PrincipalFromContext` молча возвращает `SystemPrincipal()`.
		anonymous := operations.PrincipalFromContext(ctx)
		_, established := operations.PrincipalFromContextOK(ctx)
		t.Logf("перепись входа: личность установлена %t, подставляемая пара %s/%s",
			established, anonymous.Type, anonymous.ID)
		require.False(t, established, "фикстура несёт установленную личность: отрицание стало бы вакуумным")

		// Вход ПОЛНЫЙ намеренно: подтверждение снято, оба потолка названы. Иначе
		// отказ пришёл бы по неполному входу, и проба зеленела бы, ничего не
		// сказав о личности.
		rep, err := applier.Apply(ctx, verbRequest(t, ctx, pool,
			shippedManifest(t, anchoredModule, spareResource)))
		t.Logf("перепись применения: %s", rep)
		require.Error(t, err,
			"применение на запросе БЕЗ проверенной личности ПРОШЛО: аудит некому назвать автором, "+
				"и запись о необратимом отборе прав арендатора осталась бы за подставленным `system`")

		require.Zero(t, auditRowsOfType(t, ctx, pool, moduleCatalogAppliedEvent),
			"на отказе появилась запись аудита")
		require.Zerof(t, auditRowsWithActor(t, ctx, pool, anonymous.ID),
			"аудит назвал автором подставленную личность %q — ложное утверждение о том, кто это сделал",
			anonymous.ID)
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники набора

// auditRowsOfType — сколько строк аудита названного вида.
func auditRowsOfType(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = $1`, eventType).Scan(&n))
	return n
}

// auditRowsTotal — сколько строк аудита всего. Печатается переписью: «ноль
// записей нашего вида» обязано быть отличимо от «аудит не пишет никто».
func auditRowsTotal(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.audit_outbox`).Scan(&n))
	return n
}

// auditRowsWithActor — сколько строк аудита называют этого актора.
func auditRowsWithActor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, actor string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'actor' = $1`, actor).Scan(&n))
	return n
}

// lastAuditPayload — тело последней записи названного вида.
//
// Отсутствие записи — ОТКАЗ пробы с текстом про предмет, а не пустая карта:
// пустая карта прошла бы дальше, и утверждение об акторе сравнивало бы `nil` с
// `nil`, то есть зеленело бы на отсутствии аудита.
func lastAuditPayload(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType string) map[string]any {
	t.Helper()
	var raw []byte
	err := pool.QueryRow(ctx, `
		SELECT event_payload FROM kaname.audit_outbox
		 WHERE event_type = $1 ORDER BY created_at DESC, id DESC LIMIT 1`, eventType).Scan(&raw)
	require.NoErrorf(t, err,
		"записи аудита вида %s нет: применение каталога следа не оставляет", eventType)
	var payload map[string]any
	require.NoError(t, json.Unmarshal(raw, &payload))
	return payload
}

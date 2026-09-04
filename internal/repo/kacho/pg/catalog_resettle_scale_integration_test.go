// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// catalog_resettle_scale_integration_test.go — СНЯТИЕ МОДУЛЯ ПОД ЖИВЫМИ
// АРЕНДАТОРСКИМИ РОЛЯМИ ЗАВЕРШАЕТСЯ, а не снимается сервером по
// `statement_timeout` (задача продукта #1959).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЭТО УТВЕРЖДАЕТ — НАБЛЮДАЕМОЕ, А НЕ ФОРМУ ЗАПРОСА
//
// Проба спрашивает ровно то, что видит оператор установки: применение манифеста,
// снимающего модуль, ПРОХОДИТ при названном числе ролей. Форму оператора она не
// называет и назвать не вправе: перепиши переселение иначе, сохранив свойство, —
// проба обязана остаться зелёной, иначе она держит реализацию, а не контракт.
//
// Утверждение не вакуумно: рядом стоит перепись переселённого. Применитель,
// который «завершается», ничего не сняв и никого не переселив, её роняет — а
// «прошло» без переписи было бы неотличимо от «нечего было делать».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИМЕННО ДВЕ ТЫСЯЧИ РОЛЕЙ
//
// Это точка, в которой замер #1959 наблюдал ПОРОГ: снятие модуля при 1000 ролях
// занимало 12.6 с, при 2000 — снималось сервером `57014`, транзакция откатывалась
// целиком, и повтор давал то же самое. Меньшее число оставило бы пробу зелёной на
// дефекте, большее удорожило бы её, ничего не добавив к вердикту.
//
// Порог — платформенная константа пула (`pkg/db/pool.go`, `statement_timeout`), а
// не настройка стенда, и проба её НЕ трогает: подняв её, она мерила бы свою
// правку вместо продукта.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЦЕНА ПРОБЫ НАЗВАНА, А НЕ ОСТАВЛЕНА К ОБНАРУЖЕНИЮ
//
// Посев — 2000 ролей × 6 ресурсов × 5 глаголов в ОБЕ популяции проекции, то есть
// 120 000 строк; снятие переселяет 100 000 из них. Это самая дорогая проба пакета,
// и она такая по существу: дефект живёт только на популяции, которой у дешёвой
// пробы нет by construction.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// resettleScaleRoles — число арендаторских ролей, каждая из которых называет ВСЕ
// ресурсы модуля обеими популяциями проекции.
const resettleScaleRoles = 2000

// TestModuleWithdrawalCompletesUnderTenantRolesAtScale — снятие модуля под
// живыми ролями завершается.
func TestModuleWithdrawalCompletesUnderTenantRolesAtScale(t *testing.T) {
	if testing.Short() {
		t.Skip("нужна Postgres")
	}

	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)

	// Каталог заводится ДО посева: проекция ссылается на живую строку каталога, и
	// без неё посев отвергнет ключ.
	rep, err := applier.Apply(ctx, costManifest(costResources))
	require.NoError(t, err, "заведение каталога модуля")
	require.Equal(t, costResources, rep.WrittenResources, "каталог заведён не целиком: %s", rep)

	refs, verbs := seedCostRoles(t, ctx, pool, resettleScaleRoles)
	t.Logf("посеяно при %d ролях: объявлений %d, выдач %d", resettleScaleRoles, refs, verbs)

	// Снят ВЕСЬ модуль, кроме одного ресурса, — предел сверху для одного
	// применения: больше проекций одним манифестом задеть нельзя, применитель
	// трогает только свой модуль.
	retired := costResources - 1
	wantPerPopulation := resettleScaleRoles * costVerbs * retired

	t0 := time.Now()
	wipe, err := applier.Apply(ctx, costManifest(1))
	took := time.Since(t0)

	if err != nil {
		code, _ := pgCode(err)
		if code == "57014" {
			t.Fatalf("ПОРОГ: снятие модуля при %d ролях снято сервером по statement_timeout "+
				"за %s — транзакция откачена, каталог прежний, повтор даст то же самое. "+
				"Снятие модуля на установке этого размера НЕИСПОЛНИМО, а не медленно",
				resettleScaleRoles, took)
		}
		require.NoError(t, err, "снятие модуля под живыми ролями за %s", took)
	}
	t.Logf("снятие модуля при %d ролях завершилось за %s: %s", resettleScaleRoles, took, wipe)

	// Перепись: применитель, «завершившийся» вхолостую, роняет пробу здесь.
	require.Equal(t, retired, wipe.RetiredResources, "снят не весь модуль: %s", wipe)
	require.Equal(t, wantPerPopulation, wipe.Resettled.RuleRefs,
		"переселено объявлений не по числу ролей: %s", wipe)
	require.Equal(t, wantPerPopulation, wipe.Resettled.RoleVerbs,
		"переселено выдач не по числу ролей: %s", wipe)

	// Переселено, а не отобрано молча: у каждой снятой строки обеих популяций
	// есть след в сиротах.
	var orphans int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE object_type LIKE $1`,
		costModule+".%").Scan(&orphans))
	require.Equal(t, int64(wantPerPopulation*2), orphans,
		"сироты не покрывают обе популяции — право отобрано молча")

	// Проекций снятого модуля не осталось ни в одной популяции.
	for _, q := range []struct {
		name string
		sql  string
		arg  string
	}{
		{"role_rule_ref", `SELECT count(*) FROM kacho_iam.role_rule_ref WHERE module = $1 AND resource <> 'res00'`, costModule},
		{"role_verb", `SELECT count(*) FROM kacho_iam.role_verb WHERE object_type LIKE $1 AND object_type <> $2`, costModule + ".%"},
	} {
		var left int64
		args := []any{q.arg}
		if q.name == "role_verb" {
			args = append(args, costModule+".res00")
		}
		require.NoError(t, pool.QueryRow(ctx, q.sql, args...).Scan(&left))
		require.Zero(t, left, fmt.Sprintf("в %s остались проекции снятых ресурсов", q.name))
	}
}

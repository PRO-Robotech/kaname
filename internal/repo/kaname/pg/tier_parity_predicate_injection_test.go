// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// tier_parity_predicate_injection_test.go — доказательство того, что предикат
// паритета ярусов (`evaluateTierParity`) СПОСОБЕН упасть и способен смолчать.
//
// # Почему это отдельная проба, и почему она без базы
//
// Обе пробы, зовущие предикат по существу, требуют поднятого Postgres и
// пропускаются в `-short`. Значит в быстрой полосе способность предиката упасть
// не проверяет НИЧТО: он мог бы вернуть пустые находки на любом входе, и обе
// интеграционные пробы остались бы зелёными, утверждая «паритет держится».
//
// Здесь популяция синтетическая и подаётся ЦЕЛИКОМ, поэтому проба
// детерминирована и не зависит ни от посева, ни от контейнера.
//
// # Что эта проба НЕ утверждает — и это надо сказать прямо
//
// Она закрепляет ОТВЕТ предиката, а не его МЕСТО: о том, что предикат вообще
// зовётся над строками базы и над строками применителя, она не говорит ничего.
// Место закрывают `TestTierParity_AllSystemRoles_F53` (популяция миграций) и
// MOD-RD-26/27 (популяция применителя). Утверждать здесь «паритет держится»
// значило бы заявить шире сделанного.
//
// # Инъекция обязана ронять ТОЛЬКО проверяемое
//
// Поэтому каждая подложенная строка согласована по всем осям, кроме одной, а
// утверждение рядом требует, чтобы соседние корзины находок остались пустыми.
// Инъекция, роняющая всё сразу, не доказывает, что упало проверяемое.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// parityRoleOf — синтетическая строка популяции: имя плюс СОГЛАСОВАННАЯ пара
// «свёрнутые разрешения ↔ правила» на одной паре (модуль, ресурс).
//
// Согласованная by construction: разрешения производятся из тех же глаголов,
// что и правило, — тем же способом, каким их сворачивает `domain.CompileRules`
// на ветви якоря. Иначе всякая строка популяции роняла бы ещё и свойство 2, и
// ни одна инъекция ниже не называла бы проверяемое.
func parityRoleOf(name, module, resource string, verbs ...string) tierParityRole {
	perms := make([]string, 0, len(verbs))
	for _, v := range verbs {
		perms = append(perms, module+"."+resource+".*."+v)
	}
	return tierParityRole{
		name:  name,
		perms: perms,
		rules: domain.Rules{{Module: module, Resources: []string{resource}, Verbs: verbs}},
	}
}

// TestTierParityPredicateFallsOnAnInjectedDivergenceAndIsSilentOnItsLegalTwin —
// пять прогонов одного предиката: законный близнец, три инъекции по одной оси
// каждая, и вырожденный вход.
func TestTierParityPredicateFallsOnAnInjectedDivergenceAndIsSilentOnItsLegalTwin(t *testing.T) {
	// ── Законный близнец ────────────────────────────────────────────────────
	//
	// `iam.user` несёт ОДИН тир, и это верно: набор типа `iam_user` — `[get
	// list]`, распоряжающегося глагола у него нет (#1128, #1189), поэтому ось
	// семейства сужена до `view`. `vpc.network` несёт все три: у его типа есть и
	// `delete`, и `update`.
	twin := []tierParityRole{
		parityRoleOf("iam.user.view", "iam", "user", "get", "list"),
		parityRoleOf("vpc.network.admin", "vpc", "network", "delete"),
		parityRoleOf("vpc.network.edit", "vpc", "network", "update"),
		parityRoleOf("vpc.network.view", "vpc", "network", "get"),
	}
	clean := evaluateTierParity(twin)
	t.Log(clean.Census())
	require.Equal(t, 4, clean.Roles, "перепись обязана назвать объём осмотренного")
	require.Len(t, clean.Families, 2, "семейств обязано быть два: `iam.user` и `vpc.network`")
	assert.Empty(t, clean.TierGaps,
		"законный близнец обязан МОЛЧАТЬ — иначе всякая инъекция ниже краснела бы вхолостую:\n%s",
		strings.Join(clean.TierGaps, "\n"))
	assert.Empty(t, clean.Mismatches, "ярусы согласованы by construction:\n%s",
		strings.Join(clean.Mismatches, "\n"))
	assert.Empty(t, clean.OffAxis, "все имена стоят на оси тиров")
	assert.Equal(t, 1, clean.Narrowed,
		"ось СУЖЕНА ровно у `iam.user`: у `vpc.network` тип обслуживает все три тира")

	// ── Инъекция 1: тир, которому НЕЧЕМ быть ────────────────────────────────
	//
	// Ровно тот вход, ради которого выведена роль `iam.user.admin` (миграция
	// `20260825003504`), и ровно та находка, которой MOD-RD-26 ждёт от
	// применителя.
	unservable := evaluateTierParity(append(append([]tierParityRole{}, twin...),
		parityRoleOf("iam.user.admin", "iam", "user", "get", "list")))
	assert.Len(t, unservable.TierGaps, 1,
		"инъекция обязана дать РОВНО одну находку:\n%s", strings.Join(unservable.TierGaps, "\n"))
	assert.Contains(t, strings.Join(unservable.TierGaps, "\n"), `iam.user: tier "admin"`,
		"находка обязана НАЗВАТЬ семейство и ярус: без имени вызывающему нечего чинить")
	assert.Empty(t, unservable.Mismatches,
		"свойство 2 этой инъекцией не затронуто — иначе красное не называло бы проверяемое:\n%s",
		strings.Join(unservable.Mismatches, "\n"))

	// ── Инъекция 2: обратная сторона того же свойства — тир ОТСУТСТВУЕТ ─────
	holed := evaluateTierParity([]tierParityRole{twin[0], twin[1], twin[3]})
	assert.Len(t, holed.TierGaps, 1,
		"семейство без обслуживаемого тира — грантуемая поверхность с дырой:\n%s",
		strings.Join(holed.TierGaps, "\n"))
	assert.Contains(t, strings.Join(holed.TierGaps, "\n"), `vpc.network: tier "edit" missing`,
		"находка обязана назвать недостающий тир")
	assert.Empty(t, holed.Mismatches, "и только его:\n%s", strings.Join(holed.Mismatches, "\n"))

	// ── Инъекция 3: свойство 2 — ярус правил РАЗОШЁЛСЯ с ярусом разрешений ──
	skewed := append([]tierParityRole{}, twin...)
	skewed[1] = tierParityRole{
		name:  "vpc.network.admin",
		perms: []string{"vpc.network.*.delete"},
		rules: domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}}},
	}
	drift := evaluateTierParity(skewed)
	assert.Empty(t, drift.TierGaps,
		"имена не тронуты — свойство 1 обязано молчать:\n%s", strings.Join(drift.TierGaps, "\n"))
	require.Len(t, drift.Mismatches, 1,
		"расхождение ярусов обязано быть найдено:\n%s", strings.Join(drift.Mismatches, "\n"))
	assert.Contains(t, drift.Mismatches[0], "vpc.network.admin [vpc.network]: legacy=admin rules=viewer",
		"находка обязана назвать роль, пару и ОБА яруса — иначе непонятно, какую сторону чинить")

	// ── Инъекция 4: ПРЕДПОСЫЛКА — имя вне оси уходит из-под свойства 1 ──────
	offAxis := evaluateTierParity(append(append([]tierParityRole{}, twin...),
		parityRoleOf("vpc.network.operator", "vpc", "network", "get")))
	assert.Empty(t, offAxis.TierGaps,
		"имя вне оси семейством не читается — и это ровно та слепая зона, которую обнажает предпосылка")
	assert.Contains(t, offAxis.OffAxis, "vpc.network.operator",
		"предпосылка обязана НАЗВАТЬ имя, ушедшее из-под свойства: иначе оно молча не проверяется никогда")

	// ── Вырожденный вход: находок нет by construction ───────────────────────
	//
	// Ради этого прогона предпосылка и вынесена отдельным вызовом: на пустой
	// популяции ВСЕ утверждения о ярусах истинны вакуумно, и отличить это от
	// «паритет держится» может только перепись.
	empty := evaluateTierParity(nil)
	assert.Empty(t, empty.Families, "пустая популяция не даёт ни одного семейства")
	assert.Empty(t, empty.TierGaps, "и ни одной находки — ровно поэтому «ноль находок» само по себе не вердикт")
	assert.Equal(t, 0, empty.Roles, "перепись обязана назвать ноль прочитанного, а не смолчать")
}

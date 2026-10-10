// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// resetting_access_keys_authz_integration_test.go — РАЗБОР ДОСТУПА к
// `UserService/ResetAccessKeys` вердиктом по закоммиченным строкам на той двери,
// куда приходит каждый запрос платформы (`AuthorizeService.CheckRelation`), —
// LMR-03 уровня I (задача PRO-Robotech/kaname#638; приёмка
// `docs/engineering/acceptance/cloud-administrator-resets-login-methods.md`,
// редакция 5, Р2).
//
// # Предмет
//
// Держатель — только администратор облака: запись каталога гейтит глагол
// отношением `identity_suspender` на `iam_user`, как `ResetSecondFactor`.
// Владелец аккаунта человека `D`, делегированный администратор того же
// аккаунта `D₂`, распорядитель другого аккаунта `O` и сам человек `U` права не
// имеют; на несуществующем well-formed `N` отказ не держателю тот же —
// оракула существования нет. Отношение спрашивается У КАТАЛОГА: до заведения
// записи проба краснеет на предмете, а не на литерале.
//
// # Пара «отрицание + положительное»
//
// Контроль фикстуры — `D₂` держит `v_get` на `U` (как в
// `TestResetSecondFactorAuthzMatrix`), иначе отрицания вакуумны; администратор
// облака держит отношение — иначе отрицания держались бы недостижимостью.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestResetAccessKeysAuthzMatrix — LMR-03 уровня I: `D`, `D₂`, `O`, `U` — «нет»,
// `A` — «да»; не держателю на `N` — тот же отказ.
func TestResetAccessKeysAuthzMatrix(t *testing.T) {
	w := newCIWorld(t)

	const (
		acc        = "acc-rak1"
		otherAcc   = "acc-rak2"
		owner      = "usr-rakown1" // D
		delegated  = "usr-rakdel1" // D₂
		person     = "usr-rakper1" // U
		otherOwner = "usr-rakoth1" // O
		cloudAdmin = "usr-rakcld1" // A
	)
	w.seedAccountWithOwner(t, acc, owner)
	w.seedAccountWithOwner(t, otherAcc, otherOwner)
	w.seedUser(t, delegated, acc)
	w.seedUser(t, person, acc)
	w.seedUser(t, cloudAdmin, acc)

	target := "iam_user:" + person
	absentWellFormed := "iam_user:usr-rakghost01"

	// D₂ — делегированный администратор И держатель пообъектной выдачи чтения.
	seedRoleGrantingUserRead(t, w, "rol-rak1", "acb-rak1", delegated, acc)
	w.factThroughJournal(t, "user:"+delegated, "admin", "account", acc)
	w.factThroughJournal(t, "user:"+owner, "owner", "account", acc)
	w.factThroughJournal(t, "user:"+otherOwner, "owner", "account", otherAcc)
	w.factThroughJournal(t, "user:"+person, "subject", "iam_user", person)
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_root")

	resetRel, resetType := actingAsGateFromCatalog(t, "kaname.cloud.iam.v1.UserService/ResetAccessKeys")
	require.Equalf(t, "identity_suspender", resetRel,
		"ResetAccessKeys гейтится не отношением надзора над личностью (%s) — Р2", resetRel)
	require.Equalf(t, "iam_user", resetType, "ResetAccessKeys гейтится не на объекте личности (%s)", resetType)

	// КОНТРОЛЬ ФИКСТУРЫ: посев живой.
	require.True(t, w.allowed(t, "user:"+delegated, "v_get", target),
		"КОНТРОЛЬ: D₂ обязан держать `v_get` на строке своего члена — иначе отрицания ниже вакуумны")

	for _, c := range []struct{ who, why string }{
		{owner, "D — владелец аккаунта человека"},
		{delegated, "D₂ — делегированный администратор и держатель пообъектной выдачи"},
		{otherOwner, "O — распорядитель другого аккаунта"},
		{person, "U — сам человек"},
	} {
		require.Falsef(t, w.allowed(t, "user:"+c.who, resetRel, target),
			"сброс ключей (%s.%s) достался не держателю — %s (user:%s): личность глобальна, "+
				"сброс отнимает вход во всех её аккаунтах (Р2)", resetType, resetRel, c.why, c.who)
		require.Falsef(t, w.allowed(t, "user:"+c.who, resetRel, absentWellFormed),
			"%s получил иной исход на несуществующем well-formed id — оракул существования (Р2)", c.why)
	}

	require.Truef(t, w.allowed(t, "user:"+cloudAdmin, resetRel, target),
		"администратор облака обязан держать сброс ключей (%s.%s) — иначе отношение не держит никто", resetType, resetRel)
	require.Truef(t, w.allowed(t, "user:"+cloudAdmin, resetRel, absentWellFormed),
		"администратор облака проходит разбор доступа и на несуществующем id: «нет такого человека» — ответ службы (404)")

	t.Logf("перепись LMR-03 (I): гейт %s.%s · не держателей спрошено 4 (D·D₂·O·U) на существующем и отсутствующем · держатель 1", resetType, resetRel)
}

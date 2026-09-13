// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_seed_writer_window_integration_test.go — окно двух написаний у
// ПРИМЕНИТЕЛЯ манифестов (приёмка
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md` §2.4,
// §4.2, §8 шаг 4; сценарии KAN-SEED-1-06 и -07).
//
// # ПОЧЕМУ ОКНО ЖИВЁТ ЗДЕСЬ, А НЕ В БАЗЕ
//
// `accounts_name_unique` глобален: двух аккаунтов с двумя написаниями не бывает
// by construction. Значит переходное состояние невыразимо строкой и живёт у
// того, кто имя ЧИТАЕТ. Читатель здесь — применитель: манифесты пяти чужих
// продуктов правит НЕ эта служба (П3 приёмки), и до их перевода они продолжают
// присылать прежнее написание.
//
// # ЧТО УТВЕРЖДАЕТСЯ, А ЧТО БЫЛО БЫ ВАКУУМОМ
//
// Утверждается, что ОБА написания попадают в ОДНУ строку. «Манифест принят» без
// этого зеленело бы на применителе, который завёл вторую строку с другим именем:
// снаружи посев выглядел бы применённым, а служебная запись модуля жила бы в
// чужом аккаунте.
package pg_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// windowProbeManifest — тот же посев, что у соседней пробы, но написание
// системного аккаунта ОБЪЯВЛЕННОЕ (`system`), а не прежнее.
//
// Служебная запись названа прежним написанием намеренно: её переводит та же
// миграция, что и аккаунт, и здесь предмет — резолв АККАУНТА, а не записи.
const windowProbeManifest = `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: system
      description: "Module SA: kacho-vpc (SEC-C least-priv)"
  joins:
    - serviceAccount: {account: system, name: kacho-vpc}
      group: {account: system, name: module-quota-readers}
      why: "проба окна двух написаний"
`

// TestModuleSeedApplier_WindowResolvesBothSpellingsToOneRow — KAN-SEED-1-06/-07:
// манифест, присланный ОБЪЯВЛЕННЫМ написанием, попадает в ту же строку, что
// прежний, и второй строки не заводит.
func TestModuleSeedApplier_WindowResolvesBothSpellingsToOneRow(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: свойство утверждается прогоном, а не чтением кода")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	var accountsBefore int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.accounts`).Scan(&accountsBefore))

	m, err := manifest.Load([]byte(windowProbeManifest))
	require.NoError(t, err, "проба подаёт манифест, который разбор не принимает — вердикт беспредметен")

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	report, err := applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err,
		"применитель не принял ОБЪЯВЛЕННОЕ написание системного аккаунта: после перевода "+
			"строки её собственное имя перестало бы резолвиться, то есть посев отказал бы "+
			"на каждом старте")

	declared, _ := report.Totals()
	require.NotZero(t, declared,
		"манифест пробы не объявил ни одной строки — утверждать нечего")

	// Ни одной НОВОЙ строки аккаунта: окно резолвит, а не заводит.
	var accountsAfter int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.accounts`).Scan(&accountsAfter))
	require.Equal(t, accountsBefore, accountsAfter,
		"аккаунтов стало %d вместо %d: окно завело вторую строку вместо резолва в одну",
		accountsAfter, accountsBefore)

	// Служебная запись доехала в ТОТ аккаунт, где живут остальные, а не в чужой.
	var sameAccount bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT sa.account_id = a.id
		  FROM kaname.service_accounts sa, kaname.accounts a
		 WHERE sa.name = 'kacho-vpc' AND a.id = sa.account_id`).Scan(&sameAccount))
	require.True(t, sameAccount)
}

// TestModuleSeedApplier_WindowDoesNotWidenToAThirdName — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ:
// окно расширяет приём ровно на объявленную пару.
//
// Без него проба выше зеленела бы на применителе, который резолвит ЛЮБОЕ имя в
// первую попавшуюся строку, — а это и есть тихая запись в чужой аккаунт.
func TestModuleSeedApplier_WindowDoesNotWidenToAThirdName(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	const thirdName = `
apiVersion: iam/v1
module: vpc
resources: []
seed:
  serviceAccounts:
    - name: kacho-vpc
      account: sistem
      description: "Module SA: kacho-vpc (SEC-C least-priv)"
`
	m, err := manifest.Load([]byte(thirdName))
	require.NoError(t, err)

	applier := moduleseed.NewApplier(kanamepg.NewModuleSeedWriteRepo(pool))
	_, err = applier.ApplyAll(ctx, []*manifest.Manifest{m})
	require.Error(t, err,
		"применитель принял имя аккаунта вне окна: приём расширен шире объявленной пары, "+
			"и посев уехал бы в чужую строку молча")
	require.Contains(t, err.Error(), "sistem",
		"отказ не называет имени, которое не резолвится — автор манифеста не узнает, что чинить")
}

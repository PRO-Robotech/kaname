// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта потолка темпа упасть — инъекцией в обе стороны,
// с законными близнецами на каждую форму счёта.
//
// Каждая инъекция меняет РОВНО ОДИН факт против своего близнеца: иначе неизвестно,
// какой из двух дал красное.

// probeFile — обёртка, чтобы фикстуры читались как настоящий файл проб.
func probeFile(body string) string {
	return "package pg_test\n\n" + body
}

// TestRateGateRedsOnAProbeOutgrowingTheCeiling — прямая сторона: четыре аккаунта
// одной личности без поднятия потолка. Это ровно та форма, что упала на конвейере:
// один аккаунт приносит фикстура личности, три заводит цикл.
func TestRateGateRedsOnAProbeOutgrowingTheCeiling(t *testing.T) {
	findings, c, err := auditProbeFile("x_test.go", probeFile(`
func TestPageOfList(t *testing.T) {
	uid := mustSeedUser(t, ctx, pool, "lst")
	for i := 0; i < 3; i++ {
		_ = seedAccount(t, ctx, repo, "listed", uid)
	}
}
`))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "TestPageOfList", "находка обязана НАЗЫВАТЬ пробу")
	require.Contains(t, findings[0], "заводит 4 аккаунтов", "и называть ЧИСЛО, а не только факт")
	require.Contains(t, findings[0], rateCeilingLift, "и называть, что делать дальше")
	require.Equal(t, 1, c.identities)
	require.Equal(t, 1, c.seedCalls)
}

// TestRateGateIsSilentOnTheSameProbeThatLiftsTheCeiling — законный близнец
// предыдущей: ОДИН изменённый факт — вызов поднятия.
func TestRateGateIsSilentOnTheSameProbeThatLiftsTheCeiling(t *testing.T) {
	findings, c, err := auditProbeFile("x_test.go", probeFile(`
func TestPageOfList(t *testing.T) {
	liftRateCeilingOutOfTheWay(t, ctx, pool)
	uid := mustSeedUser(t, ctx, pool, "lst")
	for i := 0; i < 3; i++ {
		_ = seedAccount(t, ctx, repo, "listed", uid)
	}
}
`))
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Equal(t, 1, c.liftingProbes)
}

// TestRateGateIsSilentWhenEachIterationSeedsItsOwnIdentity — законный близнец
// формы `migrate_backfill_p8`: пять аккаунтов на ПЯТЬ разных личностей. Потолок
// темпа считает на личность, поэтому поднимать его тут нечего.
func TestRateGateIsSilentWhenEachIterationSeedsItsOwnIdentity(t *testing.T) {
	findings, c, err := auditProbeFile("x_test.go", probeFile(`
func TestChunkedBackfill(t *testing.T) {
	const accounts = 5
	for i := 0; i < accounts; i++ {
		o := mustSeedUser(t, ctx, pool, "p8chunk")
		seedAccount(t, ctx, repo, "p8-chunk-acc", o)
	}
}
`))
	require.NoError(t, err)
	require.Empty(t, findings, "личность у каждой итерации своя — потолка темпа это не касается")
	require.Equal(t, 1, c.identities)
}

// TestRateGateCountsIdentitiesByScopeNotByName — законный близнец, найденный
// ПЕРВОЙ редакцией гейта на живом дереве: две подпробы, у каждой свой
// `uid := mustSeedUser(…)`. Счёт по имени давал здесь «4 аккаунта одной личности»
// и ложное красное; счёт по области видимости даёт две личности по два.
func TestRateGateCountsIdentitiesByScopeNotByName(t *testing.T) {
	findings, c, err := auditProbeFile("x_test.go", probeFile(`
func TestConcurrentCAS(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-a")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-a", uid)
		_ = acc
	})
	t.Run("b", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-b")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-b", uid)
		_ = acc
	})
}
`))
	require.NoError(t, err)
	require.Empty(t, findings, "две подпробы — две личности, а не одна на четыре аккаунта")
	require.Equal(t, 2, c.identities, "личности опознаются областью видимости")
	require.Equal(t, 2, c.seedCalls)
}

// TestRateGateSeesSeedingInsideASubtest — обратная сторона близнеца выше: в теле
// подпробы гейт заведения ВИДИТ, иначе он молчал бы на всём, что там написано.
func TestRateGateSeesSeedingInsideASubtest(t *testing.T) {
	findings, _, err := auditProbeFile("x_test.go", probeFile(`
func TestConcurrentCAS(t *testing.T) {
	t.Run("a", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-a")
		seedAccount(t, ctx, seedRepo, "one", uid)
		seedAccount(t, ctx, seedRepo, "two", uid)
		seedAccount(t, ctx, seedRepo, "three", uid)
	})
}
`))
	require.NoError(t, err)
	require.Len(t, findings, 1, "четыре аккаунта одной личности внутри подпробы — та же находка")
	require.Contains(t, findings[0], "заводит 4 аккаунтов")
}

// TestRateGateResolvesARangeOverALiteralSet — граница обхода по литералу набора
// разрешима, и без неё четыре заведения читались бы как одно.
func TestRateGateResolvesARangeOverALiteralSet(t *testing.T) {
	findings, _, err := auditProbeFile("x_test.go", probeFile(`
func TestOverASet(t *testing.T) {
	uid := mustSeedUser(t, ctx, pool, "set")
	for _, n := range []string{"a", "b", "c"} {
		seedAccount(t, ctx, repo, n, uid)
	}
}
`))
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "заводит 4 аккаунтов")
}

// TestRateGateIsSilentAtTheCeilingItself — граница предиката названа: потолок
// допускает ТРИ, и три обязаны молчать. Без этой пробы гейт мог бы отвергать
// законное и был бы отключён первым же ложным срабатыванием.
func TestRateGateIsSilentAtTheCeilingItself(t *testing.T) {
	findings, _, err := auditProbeFile("x_test.go", probeFile(`
func TestTwoAccounts(t *testing.T) {
	owner := mustSeedUser(t, ctx, pool, "own")
	accA := seedAccount(t, ctx, repo, "a", owner)
	accB := seedAccount(t, ctx, repo, "b", owner)
	_, _ = accA, accB
}
`))
	require.NoError(t, err)
	require.Empty(t, findings, "три заведения — ровно потолок, отвергать нечего")
}

// TestRateGateReportsAnEmptyWalkInsteadOfPassing — «ноль находок» обязано быть
// отличимо от «ноль прочитанного».
func TestRateGateReportsAnEmptyWalkInsteadOfPassing(t *testing.T) {
	findings, c, err := auditProbeFile("x_test.go", probeFile(`
func TestUnrelated(t *testing.T) {
	_ = 1
}
`))
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, c.seedCalls, "заведений не прочитано — несущая проба обязана упасть на этом")
	require.Zero(t, c.liftingProbes, "поднятий не прочитано — предпосылка гейта исчезла бы незаметно")
	require.Equal(t, 1, c.probes)
}

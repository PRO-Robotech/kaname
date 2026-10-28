// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_withdrawal_revokes_member_access_integration_test.go — снятие роли модуля
// отнимает и ярус на объектах, выданный членами её выдач (kaname#926).
//
// ПРЕДМЕТ. Приёмка снятия (`role-withdrawal-has-a-producer.md` §2.4): выдача на
// снятой роли переживает снятие, но не даёт НИЧЕГО. У вердикта две ветви — по
// выдаче (глаголы роли) и по прямым фактам (ярус на объекте), — и «ничего»
// обязано выполняться на обеих. Проба по глаголу одна ветвь фактов не
// проверяет (TestIAMRW110AGrantOnARetiredRoleYieldsNoVerdict спрашивает `v_get`).
//
// ФОРМА ПРОБЫ. Роль модуля объявляется и снимается НАСТОЯЩИМ применителем
// (moduleroles.Applier), выдача материализуется настоящим полным проходом.
// После снятия и после ещё одного полного прохода (сведения) утверждается
// наблюдаемое: прямых фактов субъекта на объекте нет, вердикт каждого прежде
// выданного отношения — отказ, у выдачи нет ни членов, ни строк реестра членов.
//
// ЗАКОННЫЙ БЛИЗНЕЦ — выдача ДРУГОМУ субъекту на роль того же модуля, которая в
// манифесте осталась: та же область, тот же объект, то же снятие соседней роли —
// её ярус обязан остаться. Без него пустота после снятия была бы неотличима от
// снятия, задевающего всё подряд.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/rightsfixture"
)

// memberLedgerRows — строки реестра, выпущенные ЧЛЕНАМИ выдачи. Строка уровня
// выдачи (`source='binding'`) — указатель иерархии на объект выдачи — доступом
// субъекта не является и здесь не считается.
func memberLedgerRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND source = 'member'`, string(bid)).Scan(&n))
	return n
}

func TestRoleWithdrawalRevokesMemberTierAccess(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, "k926r")
	rec, _ := newReconciler(pool)
	applier := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(fx.repo), rightsfixture.Export())

	const (
		goneName = "compute.rw926gone.admin"
		keepName = "compute.rw926keep.admin"
	)
	rep, err := applier.Apply(ctx, withdrawalManifest(t, "compute", goneName, keepName), moduleroles.BootActorID)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: объявленные роли модуля легли: %s", rep)
	gone := domain.SystemRoleID(domain.RoleName(goneName))
	keep := domain.SystemRoleID(domain.RoleName(keepName))

	other := mustSeedUser(t, ctx, pool, "k926rkeep")
	bid := insertThinBindingScope(t, ctx, fx.repo, fx.member, gone, "project", string(fx.prj), domain.ScopeProject)
	twin := insertThinBindingScope(t, ctx, fx.repo, other, keep, "project", string(fx.prj), domain.ScopeProject)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	require.NoError(t, rec.ReconcileBinding(ctx, bid), "ПРЕДПОСЫЛКА: выдача снимаемой роли материализована")
	require.NoError(t, rec.ReconcileBinding(ctx, twin), "ПРЕДПОСЫЛКА: выдача близнеца материализована")

	subj := "user:" + string(fx.member)
	twinSubj := "user:" + string(other)
	before := subjectFactRelations(t, ctx, pool, subj, "compute_instance", "iRace")
	require.NotEmpty(t, before, "ПРЕДПОСЫЛКА: выдача роли модуля дала прямой факт на объекте")
	for _, r := range before {
		require.Equal(t, relverdict.Allow, raceObjectVerdict(t, ctx, pool, subj, r),
			"ПРЕДПОСЫЛКА: до снятия вердикт отношения %s — разрешение", r)
	}
	require.Positive(t, memberLedgerRows(t, ctx, pool, bid), "ПРЕДПОСЫЛКА: реестр учёл выпущенное членами выдачи")
	twinBefore := subjectFactRelations(t, ctx, pool, twinSubj, "compute_instance", "iRace")
	require.NotEmpty(t, twinBefore, "ПРЕДПОСЫЛКА близнеца: выдача оставляемой роли дала прямой факт на объекте")

	rep, err = applier.Apply(ctx, withdrawalManifest(t, "compute", keepName), moduleroles.BootActorID)
	require.NoError(t, err, "снятие роли применителем: %s", rep)
	live, _, _ := roleLiveness(t, ctx, pool, gone)
	require.False(t, live, "ПРЕДПОСЫЛКА: роль помечена снятой")
	assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatus(t, ctx, pool, bid),
		"выдача переживает снятие роли (приёмка снятия §2.4)")

	afterRetire := subjectFactRelations(t, ctx, pool, subj, "compute_instance", "iRace")
	ledgerAfterRetire := memberLedgerRows(t, ctx, pool, bid)
	require.NoError(t, rec.ReconcileBinding(ctx, bid), "сведение после снятия")
	afterSweep := subjectFactRelations(t, ctx, pool, subj, "compute_instance", "iRace")
	t.Logf("факты субъекта до снятия: %v; после снятия: %v; после сведения: %v; строк реестра членов после снятия: %d",
		before, afterRetire, afterSweep, ledgerAfterRetire)

	assert.Empty(t, afterRetire, "выдача на снятой роли не даёт ничего — прямой факт после снятия обязан исчезнуть")
	assert.Empty(t, afterSweep, "и сведение не оставляет прямого факта снятой роли")
	assert.Zero(t, ledgerAfterRetire, "реестр выдачи на снятой роли не несёт строк её бывших членов")
	members, _, _ := bindingResidue(t, ctx, pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "у выдачи на снятой роли нет членов")
	for _, r := range before {
		assert.Equal(t, relverdict.Deny, raceObjectVerdict(t, ctx, pool, subj, r),
			"после снятия роли вердикт отношения %s обязан быть отказом", r)
	}
	assert.Equal(t, relverdict.Deny, raceObjectVerdict(t, ctx, pool, subj, "v_get"),
		"после снятия роли вердикт глагола обязан быть отказом")

	// Близнец: соседняя роль модуля осталась объявленной — её ярус на месте.
	twinAfter := subjectFactRelations(t, ctx, pool, twinSubj, "compute_instance", "iRace")
	assert.Equal(t, twinBefore, twinAfter, "снятие соседней роли не трогает ярус выдачи на оставшуюся роль")
	for _, r := range twinBefore {
		assert.Equal(t, relverdict.Allow, raceObjectVerdict(t, ctx, pool, twinSubj, r),
			"близнец: вердикт отношения %s на оставшейся роли — разрешение", r)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_ledger_coordinate_integration_test.go — строка реестра выпущенного
// отвечает ровно за координату своего члена (kaname#933): снятие члена никогда не
// забирает строку или факт другой координаты.
//
//  1. КОНКУРЕНЦИЯ: форвард, пишущий реестр члена A (compute.instance:<id>), и полный
//     проход реплики, не знающей типа члена B (vpc.network:<id>, тот же id, та же
//     выдача), идут одновременно. При любом исходе гонки реестр и факт A остаются,
//     реестр и факт B сняты. Близнец — те же стороны по очереди.
//  2. ДВЕ КООРДИНАТЫ, ОДИН КОРТЕЖ (тип переименован с сохранением типа модели): уход
//     первой координаты оставляет факт, который держит строка второй; уход второй
//     снимает факт, лишней строки не остаётся.

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// coordRounds — повторов гонки на свежей фикстуре: исход гонки не задан, и одно
// совпадение порядка инвариант не доказывает.
const coordRounds = 6

type coordRaceProbe struct {
	pool  *pgxpool.Pool
	bid   domain.AccessBindingID
	subj  string
	a     *reconcile.Reconciler
	noNet *reconcile.Reconciler
}

// newCoordRaceProbe — выдача с двумя правилами; материализован только член сети B
// (vpc.network:iRace). Объект инстанса A (compute.instance:iRace) зарегистрирован, но
// его члена ещё нет: его запишет форвард.
func newCoordRaceProbe(t *testing.T, suffix string) *coordRaceProbe {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	a, adapter := newReconciler(pool)
	noNet := reconcile.New(adapter, nil, catalogWithout(t, "vpc.network", false))
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule(), vpcNetworkRule()})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "vpc.network", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	registerUnderProject(t, ctx, pool, fx, "vpc_network:iRace")
	require.NoError(t, a.ReconcileBinding(ctx, bid))

	subj := "user:" + string(fx.member)
	require.Positive(t, ledgerRowsOn(t, ctx, pool, bid, "vpc_network:iRace"), "БЛИЗНЕЦ: реестр сети B есть")
	require.Positive(t, factsOn(t, ctx, pool, subj, "vpc_network", "iRace"), "БЛИЗНЕЦ: факт сети B есть")
	require.Zero(t, ledgerRowsOn(t, ctx, pool, bid, "compute_instance:iRace"), "ПРЕДПОСЫЛКА: реестра инстанса A ещё нет")

	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	registerUnderProject(t, ctx, pool, fx, "compute_instance:iRace")
	return &coordRaceProbe{pool: pool, bid: bid, subj: subj, a: a, noNet: noNet}
}

// assertOnlyNetGone — реестр, член и факт инстанса A на месте; реестр, член и факт
// сети B сняты.
func (p *coordRaceProbe) assertOnlyNetGone(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, "compute.instance", "iRace")
	assert.True(t, ok, "%s: члена инстанса A нет", why)
	assert.Equal(t, string(domain.VerificationActive), st, "%s: статус члена инстанса A", why)
	assert.Positive(t, ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"),
		"%s: снят реестр ЧУЖОЙ координаты (инстанс A с тем же id)", why)
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"),
		"%s: снят прямой факт ЧУЖОЙ координаты (инстанс A с тем же id) — член ACTIVE без доступа", why)
	_, netMember := memberStatusOn(t, ctx, p.pool, p.bid, "vpc.network", "iRace")
	assert.False(t, netMember, "%s: член сети B остался", why)
	assert.Zero(t, ledgerRowsOn(t, ctx, p.pool, p.bid, "vpc_network:iRace"), "%s: реестр сети B остался", why)
	assert.Zero(t, factsOn(t, ctx, p.pool, p.subj, "vpc_network", "iRace"), "%s: факт сети B остался — доступ без члена", why)
}

func TestLedgerCoordinate_ForwardThenFullPass_TwinSequential(t *testing.T) {
	p := newCoordRaceProbe(t, "e933cq")
	ctx := context.Background()
	require.NoError(t, p.a.ReconcileObjectForwardNoStale(ctx, "compute.instance", "iRace"))
	require.NoError(t, p.noNet.ReconcileBinding(ctx, p.bid))
	p.assertOnlyNetGone(t, "по очереди: форвард A, затем полный проход без типа B")
}

func TestLedgerCoordinate_ConcurrentForwardAndFullPassKeepTheOtherCoordinate(t *testing.T) {
	for i := 0; i < coordRounds; i++ {
		p := newCoordRaceProbe(t, fmt.Sprintf("e933cr%d", i))
		ctx := context.Background()
		start := make(chan struct{})
		var wg sync.WaitGroup
		var fwdErr, fullErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			fwdErr = p.a.ReconcileObjectForwardNoStale(ctx, "compute.instance", "iRace")
		}()
		go func() {
			defer wg.Done()
			<-start
			fullErr = p.noNet.ReconcileBinding(ctx, p.bid)
		}()
		close(start)
		wg.Wait()
		require.NoError(t, fwdErr, "раунд %d: форвард инстанса A", i)
		require.NoError(t, fullErr, "раунд %d: полный проход без типа B", i)
		p.assertOnlyNetGone(t, fmt.Sprintf("раунд %d: форвард A одновременно с полным проходом без типа B", i))
		if t.Failed() {
			return
		}
	}
}

// ── 2. Две координаты, один кортеж ─────────────────────────────────────────

// coordOld — координата прежнего точечного имени того же объекта движка: тип
// переименован, тип модели сохранён (`superseded_by`).
var coordOld = reconcile.MemberCoord{ObjectType: "compute.server", ObjectID: "iRace"}

func TestLedgerCoordinate_TwoCoordinatesOneTupleEachHoldsTheFact(t *testing.T) {
	p := newLedgerProbe(t, "e933tc", false)
	ctx := context.Background()
	adapter := kanamepg.NewReconcileAdapter(p.pool, catalogfixture.Source())
	coordNew := reconcile.MemberCoord{ObjectType: "compute.instance", ObjectID: "iRace"}

	var tuples []domain.MembershipTuple
	require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		var err error
		tuples, err = s.LedgerTuplesForMember(ctx, p.bid, coordNew)
		if err != nil {
			return err
		}
		return s.RecordEmittedTuples(ctx, p.bid, coordOld, tuples)
	}))
	require.NotEmpty(t, tuples, "ПРЕДПОСЫЛКА: у координаты члена есть строки реестра")
	require.Equal(t, 2*len(tuples), ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"),
		"один кортеж от двух координат одной выдачи — две строки, а не одна")

	// forgetAndRevoke — снятие ОДНОЙ координаты тем же порядком, что у реконсайлера:
	// своя строка реестра раньше строки снятия (kaname#919).
	forgetAndRevoke := func(coord reconcile.MemberCoord) {
		t.Helper()
		require.NoError(t, adapter.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
			own, err := s.LedgerTuplesForMember(ctx, p.bid, coord)
			if err != nil {
				return err
			}
			rows := make([]reconcile.LedgerRow, 0, len(own))
			for _, tu := range own {
				rows = append(rows, reconcile.LedgerRow{Member: coord, Tuple: tu})
			}
			if err := s.ForgetEmittedTuples(ctx, p.bid, rows); err != nil {
				return err
			}
			return s.EmitTupleDelete(ctx, own)
		}))
	}

	forgetAndRevoke(coordOld)
	assert.Equal(t, len(tuples), ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"),
		"уход прежней координаты забирает только её строки")
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"),
		"уход прежней координаты снял факт, который держит строка нынешней")

	forgetAndRevoke(reconcile.MemberCoord{ObjectType: "compute.instance", ObjectID: "iRace"})
	assert.Zero(t, ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"), "уход обеих координат: строки реестра остались")
	assert.Zero(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"), "уход обеих координат: факт остался")
}

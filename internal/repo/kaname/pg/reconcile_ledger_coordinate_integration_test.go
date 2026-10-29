// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_ledger_coordinate_integration_test.go — строка реестра выпущенного
// отвечает ровно за координату своего члена (kaname#933): снятие члена никогда не
// забирает строку или факт другой координаты.
//
//  1. КОНКУРЕНЦИЯ: форвард, пишущий реестр члена A (compute.instance:<id>), и полный
//     проход реплики, не знающей типа члена B (vpc.network:<id>, тот же id, та же
//     выдача; объект B ушёл из зеркала, член выпал — kaname#937), идут одновременно.
//     При любом исходе гонки реестр и факт A остаются,
//     реестр и факт B сняты. Близнец — те же стороны по очереди.
//  2. ДВЕ КООРДИНАТЫ, ОДИН КОРТЕЖ (тип переименован с сохранением типа модели): уход
//     первой координаты оставляет факт, который держит строка второй; уход второй
//     снимает факт, лишней строки не остаётся.
//  3. ЗАПИСЬ РЕЕСТРА — в транзакции прохода: проход, отказавший после записи,
//     не оставляет ни строки реестра, ни члена, ни факта.

import (
	"context"
	"errors"
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

	// Сеть B уходит из зеркала: её член выпадает по-настоящему. Реплика без типа сети
	// одним незнанием типа члена не снимает (kaname#937) — снимает выпадение.
	_, err = pool.Exec(ctx, `DELETE FROM kaname.resource_mirror WHERE object_type = 'vpc.network' AND object_id = 'iRace'`)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: сеть B снята с зеркала")

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

// ── 3. Запись реестра — в транзакции прохода ────────────────────────────────

var errRecordProbe = errors.New("pass refused by probe after the ledger write")

// failingRecordTx — настоящий исполнитель транзакций, чьё хранилище ПИШЕТ реестр и
// затем отказывает: проход обязан откатиться вместе с записанной строкой.
type failingRecordTx struct{ inner *kanamepg.ReconcileAdapter }

func (f *failingRecordTx) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	return f.inner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &failingRecordStore{ReconcileStore: s})
	})
}

type failingRecordStore struct{ reconcile.ReconcileStore }

func (s *failingRecordStore) RecordEmittedTuplesBatch(ctx context.Context, refs []reconcile.EmittedTupleRef) error {
	if err := s.ReconcileStore.RecordEmittedTuplesBatch(ctx, refs); err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	return errRecordProbe
}

// newForwardRecordProbe — выдача на инстанс iRace, объект зарегистрирован, член ещё не
// материализован.
func newForwardRecordProbe(t *testing.T, suffix string) (*pgxpool.Pool, domain.AccessBindingID, string) {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule()})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	registerUnderProject(t, ctx, pool, fx, "compute_instance:iRace")
	return pool, bid, "user:" + string(fx.member)
}

func TestLedgerWrite_TwinForwardCommitsTheLedger(t *testing.T) {
	pool, bid, subj := newForwardRecordProbe(t, "e933wt")
	a, _ := newReconciler(pool)
	require.NoError(t, a.ReconcileObjectForwardNoStale(context.Background(), "compute.instance", "iRace"))
	members, ledger, facts := bindingResidue(t, context.Background(), pool, bid, subj, "compute_instance", "iRace")
	assert.Positive(t, members, "БЛИЗНЕЦ: член записан")
	assert.Positive(t, ledger, "БЛИЗНЕЦ: реестр записан")
	assert.Positive(t, facts, "БЛИЗНЕЦ: факт сложен")
}

func TestLedgerWrite_RollsBackWithThePass(t *testing.T) {
	pool, bid, subj := newForwardRecordProbe(t, "e933wr")
	r := reconcile.New(&failingRecordTx{inner: kanamepg.NewReconcileAdapter(pool, catalogfixture.Source())}, nil, catalogfixture.Source())
	err := r.ReconcileObjectForwardNoStale(context.Background(), "compute.instance", "iRace")
	require.ErrorIs(t, err, errRecordProbe, "ПРЕДПОСЫЛКА: проход дошёл до записи реестра и отказал")
	members, ledger, facts := bindingResidue(t, context.Background(), pool, bid, subj, "compute_instance", "iRace")
	assert.Zero(t, members, "откат прохода: член остался")
	assert.Zero(t, ledger, "откат прохода: строка реестра пережила транзакцию — запись вне транзакции прохода")
	assert.Zero(t, facts, "откат прохода: факт остался")
}

// ── 4. Строка снятия — только кортежам своей координаты ────────────────────

// deletesOn — строк снятия в журнале на объекте.
func deletesOn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, object string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox WHERE event_type = 'fga.tuple.delete' AND payload ->> 'object' = $1`,
		object).Scan(&n))
	return n
}

// Свёртка оставила бы факт сети по строке её реестра, но строка снятия в журнале —
// это намерение «снять» для всякого потребителя журнала, а не только для свёртки:
// снятие члена инстанса не вправе писать её кортежам сети с тем же id. Близнец —
// строки снятия инстанса появились.
func assertNoDeleteForTheOtherCoordinate(t *testing.T, pass func(p *suffixProbe) error, why string) {
	t.Helper()
	p := newSuffixProbe(t, "e933d"+why[:2], "iRace")
	ctx := context.Background()
	netBefore := deletesOn(t, ctx, p.pool, "vpc_network:iRace")
	instBefore := deletesOn(t, ctx, p.pool, "compute_instance:iRace")
	require.NoError(t, pass(p))
	assert.Greater(t, deletesOn(t, ctx, p.pool, "compute_instance:iRace"), instBefore,
		"%s: БЛИЗНЕЦ: строки снятия инстанса записаны", why)
	assert.Equal(t, netBefore, deletesOn(t, ctx, p.pool, "vpc_network:iRace"),
		"%s: снятие члена инстанса записало строку снятия кортежам ЧУЖОЙ координаты (сеть с тем же id)", why)
}

func TestLedgerCoordinate_ObjectPassWritesNoDeleteForTheOtherCoordinate(t *testing.T) {
	assertNoDeleteForTheOtherCoordinate(t, func(p *suffixProbe) error {
		return p.b.ReconcileObject(context.Background(), "compute.instance", "iRace")
	}, "op проход по объекту")
}

func TestLedgerCoordinate_FullPassWritesNoDeleteForTheOtherCoordinate(t *testing.T) {
	assertNoDeleteForTheOtherCoordinate(t, func(p *suffixProbe) error {
		return p.b.ReconcileBinding(context.Background(), p.bid)
	}, "fp полный проход")
}

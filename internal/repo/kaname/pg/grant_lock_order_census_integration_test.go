// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// grant_lock_order_census_integration_test.go — пробы-близнецы переписи порядка
// захвата строк ВЫДАЧИ (kaname#922): у каждой пары писателей, чьи множества строк
// `access_bindings` пересекаются в конфликтующих режимах, инверсии порядка нет, и
// это утверждается исполнением — двадцать ходов подряд, ноль взаимных блокировок.
//
// # Писатели (запись переписи — docs/changes/kn-922/lock-order-census.md)
//
//	revoke         отзыв (use-case)                 advisory(G) → G FOR UPDATE → G UPDATE
//	delete         удаление (use-case)              advisory(G) → G FOR UPDATE → G DELETE
//	expiry         истечение (ExpireBinding)        advisory(G) → G FOR UPDATE → G UPDATE
//	scope          снос области (RevokeBindingsInScope) по id: advisory(Gi) → Gi FOR UPDATE → DELETE
//	full           полный проход (ReconcileBinding) advisory(G) → G FOR NO KEY UPDATE
//	object         проход по объекту (ReconcileObject) advisory(G…, по id) → G… FOR NO KEY UPDATE
//	update         правка меток (use-case)          G UPDATE (FOR NO KEY UPDATE)
//	objectForward  форвард по объекту (NoStale)      G… FOR KEY SHARE одним оператором по id
//	bindingForward форвард по выдаче                G FOR KEY SHARE
//
// Пары форвардов между собой и с `full`/`object`/`update` в переписи не судятся:
// `FOR KEY SHARE` совместим с `FOR KEY SHARE` и `FOR NO KEY UPDATE`, ждать там
// нечего, и проба порядка о них ничего бы не утверждала.
//
// # Ход — общая точка старта под ДЕРЖАТЕЛЕМ
//
// Держатель берёт advisory-замок выдачи и её строку `FOR UPDATE`. Обе стороны
// встают на нём (утверждается: на замках стоят ровно двое — иначе стороны не
// встретились, и «блокировки нет» получено даром); держатель откатывается, и
// стороны разбираются между собой с одной и той же точки. Порядок их собственных
// замков держатель не меняет: он стоит ПЕРЕД первым из них.
//
// # Что считается
//
// Ноль взаимных блокировок — по счётчику базы (`pg_stat_database.deadlocks`), а не
// только по ответам сторон: путь удаления повторяет жертву взаимной блокировки
// внутри себя (delete_deadlock_retry_budget), и ответ стороны её бы не показал.
// Ответ стороны тоже судится: ABORTED, INTERNAL и UNKNOWN — отказ пробы; законные
// исходы проигравшего (выдачи уже нет либо она уже снята) — нет.

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// grantCensusRepeats — ходов подряд на пару (предикат kaname#922).
const grantCensusRepeats = 20

// grantCensusBudget — предел ожидания любого шага хода.
const grantCensusBudget = 30 * time.Second

// grantWriter — писатель строк выдачи под пробой.
type grantWriter string

const (
	gwRevoke         grantWriter = "revoke"
	gwDelete         grantWriter = "delete"
	gwExpiry         grantWriter = "expiry"
	gwScope          grantWriter = "scope"
	gwFull           grantWriter = "full"
	gwObject         grantWriter = "object"
	gwUpdate         grantWriter = "update"
	gwObjectForward  grantWriter = "objectForward"
	gwBindingForward grantWriter = "bindingForward"
)

// grantMode — режим замка строки выдачи, который писатель берёт.
func grantMode(w grantWriter) string {
	switch w {
	case gwRevoke, gwDelete, gwExpiry, gwScope:
		return "FOR UPDATE"
	case gwFull, gwObject, gwUpdate:
		return "FOR NO KEY UPDATE"
	default:
		return "FOR KEY SHARE"
	}
}

// grantModesConflict — конфликтуют ли режимы двух писателей на одной строке.
func grantModesConflict(a, b grantWriter) bool {
	ma, mb := grantMode(a), grantMode(b)
	if ma == "FOR UPDATE" || mb == "FOR UPDATE" {
		return true
	}
	return ma == "FOR NO KEY UPDATE" && mb == "FOR NO KEY UPDATE"
}

var grantCensusWriters = []grantWriter{
	gwRevoke, gwDelete, gwExpiry, gwScope, gwFull, gwObject, gwUpdate, gwObjectForward, gwBindingForward,
}

// TestGrantLockOrderCensusPairsDoNotDeadlock — пара за парой: ровно те пары, чьи
// режимы конфликтуют. Число пар печатается; ноль пар — отказ (обход пуст).
func TestGrantLockOrderCensusPairsDoNotDeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	pairs := 0
	skipped := 0
	for i, a := range grantCensusWriters {
		for _, b := range grantCensusWriters[i:] {
			if !grantModesConflict(a, b) {
				skipped++
				continue
			}
			pairs++
			t.Run(string(a)+"×"+string(b), func(t *testing.T) { raceGrantPair(t, a, b) })
		}
	}
	t.Logf("перепись пар строк выдачи: писателей %d · пар с конфликтом режимов %d · совместимых пар %d",
		len(grantCensusWriters), pairs, skipped)
	require.Positive(t, pairs, "обход пар пуст — судить нечего")
}

// grantEnv — база одной пары: аккаунт, системная роль правил (её строка не держит
// проект — снос области ей не мешает), реконсайлер, исполнитель операций.
type grantEnv struct {
	pool *pgxpool.Pool
	fx   gammaFixture
	role domain.RoleID
	rec  *reconcile.Reconciler
	ops  operations.Repo
}

// grantTarget — выдача хода: свой проект, свой объект под ним, материализована.
type grantTarget struct {
	prj domain.ProjectID
	bid domain.AccessBindingID
	obj string
}

func newGrantEnv(t *testing.T, suffix string) *grantEnv {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	rec, _ := newReconciler(pool)
	role := seedSystemRulesRole(t, ctx, fx.repo, "sys-"+suffix, domain.Rules{forwardAnchorRule()})
	return &grantEnv{pool: pool, fx: fx, role: role, rec: rec, ops: operations.NewRepo(pool, "kaname")}
}

// target — новая выдача хода i: проект, объект зеркала с цепью предков и
// материализация полным проходом (члены, реестр, прямой факт).
func (e *grantEnv) target(t *testing.T, i int, expired bool) grantTarget {
	t.Helper()
	ctx := context.Background()
	prj := seedProject(t, ctx, e.fx.repo, e.fx.accID, fmt.Sprintf("p922-%02d", i))
	bid := insertThinBindingScope(t, ctx, e.fx.repo, e.fx.member, e.role, "project", string(prj.ID), domain.ScopeProject)
	obj := fmt.Sprintf("i922-%02d", i)
	seedMirrorRow(t, ctx, e.pool, "compute.instance", obj, string(prj.ID), string(e.fx.accID), nil, time.Now())
	require.NoError(t, newRegisterUCWired(e.pool).Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(prj.ID), Relation: "parent", Object: "compute_instance:" + obj,
		ParentProjectId: string(prj.ID), ParentAccountId: string(e.fx.accID),
		SourceVersion: timestamppb.New(time.Now().Add(time.Minute)),
	}))
	require.NoError(t, e.rec.ReconcileBinding(ctx, bid))
	st, ok := memberStatusOn(t, ctx, e.pool, bid, "compute.instance", obj)
	require.Truef(t, ok, "ПРЕДПОСЫЛКА хода %d: член выдачи материализован", i)
	require.Equal(t, string(domain.VerificationActive), st)
	if expired {
		_, err := e.pool.Exec(ctx, `UPDATE kaname.access_bindings
		    SET created_at = now() - interval '2 hours', expires_at = now() - interval '1 hour'
		  WHERE id = $1`, string(bid))
		require.NoError(t, err, "ПРЕДПОСЫЛКА хода %d: срок выдачи в прошлом", i)
	}
	return grantTarget{prj: prj.ID, bid: bid, obj: obj}
}

// run — запуск писателя; исход приходит в канал.
func (e *grantEnv) run(ctx context.Context, w grantWriter, g grantTarget) <-chan error {
	out := make(chan error, 1)
	asOwner := operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: string(e.fx.owner)})
	go func() {
		switch w {
		case gwRevoke:
			op, err := accessbindingapp.NewRevokeAccessBindingUseCase(e.fx.repo, e.ops).
				WithRelationStore(ownerPathOnlyRelations{}, nil).Execute(asOwner, g.bid)
			out <- awaitOpDone(ctx, e.ops, op, err)
		case gwDelete:
			op, err := accessbindingapp.NewDeleteAccessBindingUseCase(e.fx.repo, e.ops).
				WithRelationStore(ownerPathOnlyRelations{}, nil).Execute(asOwner, g.bid)
			out <- awaitOpDone(ctx, e.ops, op, err)
		case gwUpdate:
			op, err := accessbindingapp.NewUpdateAccessBindingUseCase(e.fx.repo, e.ops).
				WithRelationStore(ownerPathOnlyRelations{}, nil).
				Execute(asOwner, g.bid, []string{"labels"}, false, domain.Labels{"census": "922"})
			out <- awaitOpDone(ctx, e.ops, op, err)
		case gwExpiry:
			out <- e.rec.ExpireBinding(ctx, g.bid)
		case gwScope:
			out <- shared.DoWithWriteTxVoid(ctx, e.fx.repo, func(ctx context.Context, w kanamerepo.Writer) error {
				_, _, err := shared.RevokeBindingsInScope(ctx, w, domain.ResourceType("project"), string(g.prj), "Project")
				return err
			})
		case gwFull:
			out <- e.rec.ReconcileBinding(ctx, g.bid)
		case gwObject:
			out <- e.rec.ReconcileObject(ctx, "compute.instance", g.obj)
		case gwObjectForward:
			out <- e.rec.ReconcileObjectForwardNoStale(ctx, "compute.instance", g.obj)
		case gwBindingForward:
			out <- e.rec.ReconcileBindingForward(ctx, g.bid)
		default:
			out <- fmt.Errorf("писатель %q пробе не известен", w)
		}
	}()
	return out
}

// errOpRefused — терминальный отказ операции use-case с её кодом.
type errOpRefused struct {
	code codes.Code
	msg  string
}

func (e errOpRefused) Error() string {
	return fmt.Sprintf("операция отказала: %s: %s", e.code, e.msg)
}

// awaitOpDone — терминальный исход операции use-case.
func awaitOpDone(ctx context.Context, ops operations.Repo, op *operations.Operation, err error) error {
	if err != nil {
		return err
	}
	deadline := time.Now().Add(2 * grantCensusBudget)
	for time.Now().Before(deadline) {
		got, gerr := ops.Get(ctx, op.ID)
		if gerr != nil {
			return fmt.Errorf("чтение операции %s: %w", op.ID, gerr)
		}
		if got.Done {
			if got.Error != nil {
				return errOpRefused{code: codes.Code(got.Error.GetCode()), msg: got.Error.GetMessage()}
			}
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("операция %s не завершилась за %s", op.ID, 2*grantCensusBudget)
}

// codeOf — код исхода стороны: сентинел репозитория, статус либо отказ операции.
func codeOf(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	var op errOpRefused
	if errors.As(err, &op) {
		return op.code
	}
	if isDeadlock(err) {
		return codes.Aborted
	}
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Unknown
}

// lawfulLoss — исход стороны, законный для проигравшего гонку: выдачи уже нет либо
// она снята (NOT_FOUND, FAILED_PRECONDITION; правка снятой выдачи отвечает
// PERMISSION_DENIED — сокрытие существования, update.go).
func lawfulLoss(c codes.Code) bool {
	return c == codes.OK || c == codes.NotFound || c == codes.FailedPrecondition || c == codes.PermissionDenied
}

// deadlocksOf — счётчик взаимных блокировок базы пары.
func deadlocksOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	_, err := pool.Exec(ctx, `SELECT pg_stat_clear_snapshot()`)
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT deadlocks FROM pg_stat_database WHERE datname = current_database()`).Scan(&n))
	return n
}

// raceGrantPair — двадцать ходов пары (a, b) на свежей выдаче каждый.
func raceGrantPair(t *testing.T, a, b grantWriter) {
	ctx := context.Background()
	env := newGrantEnv(t, "g922")
	expired := a == gwExpiry || b == gwExpiry
	before := deadlocksOf(t, ctx, env.pool)
	refused := 0
	for i := 0; i < grantCensusRepeats; i++ {
		g := env.target(t, i, expired)
		holder, err := env.pool.Begin(ctx)
		require.NoError(t, err)
		_, err = holder.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, string(g.bid))
		require.NoError(t, err)
		_, err = holder.Exec(ctx, `SELECT 1 FROM kaname.access_bindings WHERE id = $1 FOR UPDATE`, string(g.bid))
		require.NoError(t, err)

		ra := env.run(ctx, a, g)
		rb := env.run(ctx, b, g)
		met := lockWaiters(ctx, env.pool, 2, grantCensusBudget)
		require.NoError(t, holder.Rollback(ctx))
		aerr, berr := awaitBoth(t, ra, rb, i)
		require.Truef(t, met, "ход %d: стороны %s и %s не встали обе за держателем — не встретились (исходы %v · %v)",
			i, a, b, aerr, berr)
		ca, cb := codeOf(aerr), codeOf(berr)
		require.Falsef(t, ca == codes.Aborted || cb == codes.Aborted,
			"ход %d: взаимная блокировка: %s=%v · %s=%v", i, a, aerr, b, berr)
		require.Truef(t, lawfulLoss(ca), "ход %d: %s завершился %s (%v)", i, a, ca, aerr)
		require.Truef(t, lawfulLoss(cb), "ход %d: %s завершился %s (%v)", i, b, cb, berr)
		if ca != codes.OK || cb != codes.OK {
			refused++
		}
	}
	flushStats(env.pool)
	delta := deadlocksOf(t, ctx, env.pool) - before
	t.Logf("%s×%s: ходов %d · взаимных блокировок по счётчику базы %d · законных проигрышей %d",
		a, b, grantCensusRepeats, delta, refused)
	require.Zerof(t, delta, "%s×%s: база отметила взаимных блокировок %d за %d ходов", a, b, delta, grantCensusRepeats)
}

// flushStats — сброс статистики соединений пула. Счётчик взаимных блокировок база
// пополняет из статистики стороны-жертвы, а соединение в простое сбрасывает её с
// задержкой до десяти секунд; закрытое соединение сбрасывает её при выходе.
func flushStats(pool *pgxpool.Pool) {
	pool.Reset()
	time.Sleep(500 * time.Millisecond)
}

// TestDeadlockCounterSeesADeadlock — положительный контроль ПРИБОРА: счётчик базы,
// по которому судятся пары, видит взаимную блокировку. Две транзакции берут две
// строки каталога в обратном порядке (ABBA); без этого контроля «ноль по
// счётчику» был бы неотличим от счётчика, который не пополняется.
func TestDeadlockCounterSeesADeadlock(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	before := deadlocksOf(t, ctx, pool)

	lock := `SELECT 1 FROM kaname.catalog_module WHERE module = $1 FOR UPDATE`
	a, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = a.Rollback(ctx) }()
	b, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = b.Rollback(ctx) }()
	_, err = a.Exec(ctx, lock, "compute")
	require.NoError(t, err)
	_, err = b.Exec(ctx, lock, "vpc")
	require.NoError(t, err)
	ares := make(chan error, 1)
	go func() { _, e := a.Exec(ctx, lock, "vpc"); ares <- e }()
	require.True(t, lockWaiters(ctx, pool, 1, grantCensusBudget), "ПРЕДПОСЫЛКА: первая сторона встала")
	_, berr := b.Exec(ctx, lock, "compute")
	aerr := <-ares
	require.True(t, isDeadlock(aerr) || isDeadlock(berr), "ПРЕДПОСЫЛКА: одна сторона снята взаимной блокировкой (%v · %v)", aerr, berr)
	_ = a.Rollback(ctx)
	_ = b.Rollback(ctx)

	flushStats(pool)
	delta := deadlocksOf(t, ctx, pool) - before
	t.Logf("контроль счётчика: взаимных блокировок по счётчику базы %d", delta)
	require.Equal(t, int64(1), delta, "счётчик базы не увидел взаимной блокировки — судить пары по нему нельзя")
}

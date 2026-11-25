// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding_test

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Барьер существующего ClaimForExecution: Operation уже записана и вернулась
// вызывающему, исполнитель ещё не вошёл в Writer. Каждая операция имеет свою
// задвижку; существующие Create/Revoke и фоновые операции не задерживаются.
type gduClaimGate struct {
	operations.Repo
	mu       sync.Mutex
	gates    map[string]chan struct{}
	entered  chan string
	armed    bool
	recorded []string
}

func (g *gduClaimGate) Create(ctx context.Context, op operations.Operation) error {
	if err := g.Repo.Create(ctx, op); err != nil {
		return err
	}
	g.record(op.ID)
	return nil
}
func (g *gduClaimGate) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	if err := g.Repo.CreateWithPrincipal(ctx, op, p); err != nil {
		return err
	}
	g.record(op.ID)
	return nil
}
func (g *gduClaimGate) record(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.armed {
		g.recorded = append(g.recorded, id)
		g.gates[id] = make(chan struct{})
	}
}
func (g *gduClaimGate) ClaimForExecution(ctx context.Context, id string) (bool, error) {
	g.mu.Lock()
	ch := g.gates[id]
	g.mu.Unlock()
	if ch != nil {
		select {
		case g.entered <- id:
		case <-ctx.Done():
			return false, ctx.Err()
		}
		select {
		case <-ch:
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return g.Repo.(interface {
		ClaimForExecution(context.Context, string) (bool, error)
	}).ClaimForExecution(ctx, id)
}
func (u *gduWorld) claimGate() *gduClaimGate {
	g := &gduClaimGate{Repo: u.ops, gates: map[string]chan struct{}{}, entered: make(chan string, 8), armed: true}
	u.ops = g
	u.buildHandlers()
	u.t.Cleanup(func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		for id, ch := range g.gates {
			select {
			case <-ch:
			default:
				close(ch)
			}
			delete(g.gates, id)
		}
	})
	return g
}
func (u *gduWorld) accepted(g *gduClaimGate, body string) *operationpb.Operation {
	return u.acceptedAs(g, asUser(u.ctx, u.usrA), body)
}
func (u *gduWorld) acceptedAs(g *gduClaimGate, ctx context.Context, body string) *operationpb.Operation {
	u.t.Helper()
	_, msg, err := u.gdCall(ctx, "Update", body)
	require.NoError(u.t, err, "preflight принят до барьера")
	op, ok := msg.(*operationpb.Operation)
	require.True(u.t, ok)
	require.NotEmpty(u.t, op.GetId())
	select {
	case id := <-g.entered:
		require.Equal(u.t, op.GetId(), id)
	case <-time.After(gduBarrierDeadline):
		u.t.Fatal("исполнитель не дошёл до существующего ClaimForExecution")
	}
	return op
}
func (g *gduClaimGate) release(id string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	ch := g.gates[id]
	if ch != nil {
		close(ch)
		delete(g.gates, id)
	}
}
func (g *gduClaimGate) disarm() { g.mu.Lock(); g.armed = false; g.mu.Unlock() }
func (u *gduWorld) acceptHeld(body string) (*operationpb.Operation, func()) {
	g := u.claimGate()
	op := u.accepted(g, body)
	g.disarm()
	return op, func() { g.release(op.GetId()) }
}

func TestGrantDelegation_GDU13_ConcurrentSameAxis(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		t.Run(fmt.Sprintf("first_admin_%t", reverse), func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			first, second := u.rolPusher, u.rolRegAdmin
			if reverse {
				first, second = second, first
			}
			a := map[string]any{"roleIds": []string{string(u.rolPuller), string(first)}}
			b := map[string]any{"roleIds": []string{string(u.rolPuller), string(second)}}
			g := u.claimGate()
			opA := u.accepted(g, u.body(gduMask("roleIds"), a))
			opB := u.accepted(g, u.body(gduMask("roleIds"), b))
			g.disarm()
			g.release(opA.GetId())
			u.finish(opA)
			g.release(opB.GetId())
			gduOpError(t, u, opB, codes.FailedPrecondition, gduNarrow(u.d, "role_ids"))
			u.axes(a)
			u.invariant(false)
			require.Len(t, u.audit(), 1)
			u.refuse(asUser(u.ctx, u.usrA), gduMask("roleIds"), b, codes.FailedPrecondition, gduNarrow(u.d, "role_ids"), "")
			b["roleIds"] = []string{string(u.rolPuller), string(first), string(second)}
			u.patch("roleIds", b)
			u.axes(b)
			require.Len(t, u.audit(), 2)
		})
	}
}
func TestGrantDelegation_GDU14_ConcurrentDisjointAndIdentical(t *testing.T) {
	for _, mode := range []string{"disjoint", "identical", "disjoint_small_pool"} {
		t.Run(mode, func(t *testing.T) {
			u := newGDUWorld(t, false)
			u.subject()
			var rendezvous *gduWriterRendezvous
			var g *gduClaimGate
			if mode == "disjoint_small_pool" {
				lifetime, cancelWorkers := context.WithCancel(u.ctx)
				t.Cleanup(cancelWorkers)
				cfg := u.pool.Config()
				cfg.ConnConfig.Tracer = &gduWorkerCancelTrace{lifetime: lifetime}
				cfg.MaxConns = 2
				cfg.MinConns = 0
				cfg.ConnConfig.RuntimeParams["application_name"] = "gdu14-small-pool"
				p, err := pgxpool.NewWithConfig(u.ctx, cfg)
				require.NoError(t, err)
				rendezvous = &gduWriterRendezvous{lifetime: lifetime, pool: p, Repository: kanamepg.New(p, nil), entered: make(chan struct{}, 2), release: make(chan struct{}), firstReady: make(chan struct{}), continueFirst: make(chan struct{})}
				u.updateRepo = rendezvous
				t.Cleanup(func() {
					// Caller cancel отрезан corelib worker. Отменяем реальные SQL
					// и Acquire только этого пула, затем дренируем лишь его две LRO.
					cancelWorkers()
					select {
					case <-rendezvous.release:
					default:
						close(rendezvous.release)
					}
					select {
					case <-rendezvous.continueFirst:
					default:
						close(rendezvous.continueFirst)
					}
					if gdDrainOwnedUpdates(u.gdWorld, g, p) {
						p.Close()
					}
				})
			}
			g = u.claimGate()
			a := u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]})
			b := u.body(gduMask("targetTypes"), map[string]any{"targetTypes": u.all()["targetTypes"]})
			if mode == "identical" {
				a = u.body(gduMask(""), u.all())
				b = a
			}
			opA := u.accepted(g, a)
			opB := u.accepted(g, b)
			g.disarm()
			// Два уже принятых запроса основаны на одном снимке; выпускаем обе
			// горутины. Rendezvous до Writer допускает настоящий legacy compat
			// порядок; затем exact queue доказывает занятость обоих соединений.
			// Authority recheck первого Writer не должен просить третье.
			g.release(opA.GetId())
			g.release(opB.GetId())
			if rendezvous != nil {
				setupCtx, cancel := context.WithTimeout(u.ctx, gduBarrierDeadline)
				defer cancel()
				for i := 0; i < 2; i++ {
					select {
					case <-rendezvous.entered:
					case <-setupCtx.Done():
						t.Fatal("две горутины не дошли до барьера перед Writer")
					}
				}
				close(rendezvous.release)
				select {
				case <-rendezvous.firstReady:
				case <-setupCtx.Done():
					t.Fatal("первый Writer не получил compat fence")
				}
				holder := gdCompatOwner(u.gdWorld)
				waiter := gdAwaitCompatWaiterUntil(setupCtx, u.gdWorld, holder, "gdu14-small-pool")
				require.NotEqual(t, holder, waiter)
				require.EqualValues(t, 2, rendezvous.pool.Stat().AcquiredConns(), "оба соединения малого пула реально заняты")
				close(rendezvous.continueFirst)
			}
			u.awaitSuccess(opA)
			u.awaitSuccess(opB)
			if mode == "identical" {
				u.axes(u.all())
				require.Len(t, u.audit(), 1)
			} else {
				u.axes(map[string]any{"roleIds": u.all()["roleIds"], "targetTypes": u.all()["targetTypes"]})
				u.patch("subjectTypes", map[string]any{"subjectTypes": u.all()["subjectTypes"]})
				u.axes(u.all())
				require.Len(t, u.audit(), 3)
			}
			require.Equal(t, 1, u.countDelegated(u.d))
			u.invariant(false)
		})
	}
}

type gduWriterRendezvous struct {
	kanamerepo.Repository
	pool          *pgxpool.Pool
	lifetime      context.Context
	entered       chan struct{}
	release       chan struct{}
	firstReady    chan struct{}
	continueFirst chan struct{}
	once          sync.Once
}

func (r *gduWriterRendezvous) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.lifetime, cancel)
	defer stop()
	defer cancel()
	if r.lifetime.Err() != nil {
		cancel()
	}
	select {
	case <-r.release:
		return r.Repository.Writer(ctx)
	default:
	}
	// Обе настоящие горутины встречаются до сериализующего Writer.
	select {
	case r.entered <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case <-r.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	first := false
	r.once.Do(func() { first = true; close(r.firstReady) })
	if first {
		// Первое соединение удерживается до доказанного ожидания второго
		// на его точном compat key. Оба заняты во время первого recheck.
		select {
		case <-r.continueFirst:
		case <-ctx.Done():
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			_ = w.Rollback(cleanup)
			return nil, ctx.Err()
		}
	}
	return w, nil
}

type gduCommitGateRepo struct {
	kanamerepo.Repository
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}
type gduCommitGateWriter struct {
	kanamerepo.Writer
	gate *gduCommitGateRepo
}

func (r *gduCommitGateRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, e := r.Repository.Writer(ctx)
	if e != nil {
		return nil, e
	}
	return &gduCommitGateWriter{Writer: w, gate: r}, nil
}
func (w *gduCommitGateWriter) Commit(ctx context.Context) error {
	held := false
	w.gate.once.Do(func() { held = true; close(w.gate.entered) })
	if held {
		select {
		case <-w.gate.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return w.Writer.Commit(ctx)
}

func TestGrantDelegation_GDU15_GrantAndRevokeOrdering(t *testing.T) {
	t.Run("old_and_new_grants_commit_boundary", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		old := u.grant("role", false)
		old.Subjects = []*iamv1.Subject{svaSubject(u.svaA2)}
		id := requireGranted(t, u.tryGrant(asSA(u.ctx, u.svaIss), old), "старая комбинация до PATCH")
		u.requireDelegatedBinding(id, u.d, "старое разрешено")
		requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), u.grant("role", true)), "новая роль до фиксации")
		// У старой выдачи материализация продолжает работать после Operation.done.
		// Только проверяемый Create входит в Writer через этот именованный пул.
		const grantApp = "gdu15-old-grant"
		cfg := u.pool.Config()
		cfg.ConnConfig.RuntimeParams["application_name"] = grantApp
		grantPool, err := pgxpool.NewWithConfig(u.ctx, cfg)
		require.NoError(t, err)
		t.Cleanup(grantPool.Close)
		create, _, _ := u.newGrantVerbsOn(kanamepg.New(grantPool, nil), u.ops)
		grant := accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
		gate := &gduCommitGateRepo{Repository: u.repo, entered: make(chan struct{}), release: make(chan struct{})}
		u.updateRepo = gate
		u.buildHandlers()
		t.Cleanup(func() {
			select {
			case <-gate.release:
			default:
				close(gate.release)
			}
		})
		_, msg, err := u.gdCall(asUser(u.ctx, u.usrA), "Update", u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		require.NoError(t, err)
		op := msg.(*operationpb.Operation)
		select {
		case <-gate.entered:
		case <-time.After(gduBarrierDeadline):
			t.Fatal("Update не дошёл до Commit")
		}
		requireDenied(t, u.tryGrant(asSA(u.ctx, u.svaIss), u.grant("role", true)), "до реального Commit новая роль ещё запрещена")
		old.Subjects = []*iamv1.Subject{svaSubject(u.svaA3)}
		holderPID := gdCompatOwner(u.gdWorld)
		grantOp, err := grant.Create(asSA(u.ctx, u.svaIss), old)
		require.NoError(t, err)
		gdAwaitCompatWaiter(u.gdWorld, holderPID, grantApp)
		close(gate.release)
		u.finish(op)
		done := awaitOp(t, u.ctx, u.ops, grantOp.GetId())
		require.Nil(t, done.Error)
		u.expandedGrant("role")
		u.invariant(false)
	})
	t.Run("revoke_first_after_acceptance", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		op, release := u.acceptHeld(u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		u.revokeDelegation(asUser(u.ctx, u.usrA), u.d, "Revoke между acceptance и Writer")
		release()
		gduOpError(t, u, op, codes.FailedPrecondition, fmt.Sprintf("grant delegation %s is already revoked", u.d))
		require.Equal(t, "REVOKED", u.get()["status"])
		require.Zero(t, u.countActiveDelegated(u.d))
		u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, false)
		out := u.call(asUser(u.ctx, u.usrA), gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]})
		requireSyncRefusal(t, out.syncErr, codes.FailedPrecondition, fmt.Sprintf("grant delegation %s is already revoked", u.d), "retry revoked")
	})
	t.Run("update_first_then_revoke", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		u.patch("roleIds", map[string]any{"roleIds": u.all()["roleIds"]})
		u.expandedGrant("role")
		u.revokeDelegation(asUser(u.ctx, u.usrA), u.d, "Revoke после Update")
		require.Zero(t, u.countActiveDelegated(u.d))
		u.effect("role", false)
		u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, false)
	})
	t.Run("share_lock_and_pair_before_row", func(t *testing.T) {
		u := newGDUWorld(t, false)
		u.subject()
		gdRequirePairBeforeRow(u)
		// Read-only держатель оставляет compat fence доступным настоящему
		// Update: эта стадия проверяет его реальное FOR UPDATE ожидание.
		holder, holderPID := gdRowHolder(u.gdWorld, `SELECT id FROM kaname.grant_delegations WHERE id=$1 AND status='ACTIVE' FOR SHARE`, u.d)
		_, msg, err := u.gdCall(asUser(u.ctx, u.usrA), "Update", u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		require.NoError(t, err)
		op := msg.(*operationpb.Operation)
		updatePID := gdAwaitRowWaiter(u.gdWorld, 0, holderPID, "grant_delegations")
		require.Equal(t, updatePID, gdCompatOwner(u.gdWorld))
		// Настоящий Revoke встаёт за этим конкретным Update; pair→row oracle
		// выше отдельно отвергает обратный порядок production замков.
		_, rmsg, err := u.gdCall(asUser(u.ctx, u.usrA), "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, u.d))
		require.NoError(t, err)
		rop := rmsg.(*operationpb.Operation)
		revokePID := gdAwaitCompatWaiter(u.gdWorld, updatePID, "")
		require.NotEqual(t, updatePID, revokePID)
		require.NoError(t, holder.Rollback(u.ctx))
		u.awaitSuccess(op)
		done := awaitOp(t, u.ctx, u.ops, rop.GetId())
		require.Nil(t, done.Error)
		require.Equal(t, "REVOKED", u.get()["status"])
		require.Zero(t, u.countActiveDelegated(u.d))
	})
}

func (u *gduWorld) awaitSuccess(op *operationpb.Operation) {
	u.t.Helper()
	require.NotEmpty(u.t, op.GetId())
	require.Equal(u.t, u.d, anyField(u.t, op.GetMetadata(), "grantDelegationId"))
	require.Equal(u.t, string(u.accA), anyField(u.t, op.GetMetadata(), "accountId"))
	done := awaitOp(u.t, u.ctx, u.ops, op.GetId())
	require.Nil(u.t, done.Error)
	require.NotNil(u.t, done.Response)
	require.Equal(u.t, u.d, anyField(u.t, done.Response, "id"))
}

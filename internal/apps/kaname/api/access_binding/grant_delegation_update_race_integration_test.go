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
	"github.com/PRO-Robotech/kaname/internal/domain"
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
	mu      sync.Mutex
	gates   map[string]chan struct{}
	entered chan string
	armed   bool
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
			if mode == "disjoint_small_pool" {
				cfg := u.pool.Config()
				cfg.MaxConns = 2
				cfg.MinConns = 0
				p, err := pgxpool.NewWithConfig(u.ctx, cfg)
				require.NoError(t, err)
				t.Cleanup(p.Close)
				rendezvous = &gduWriterRendezvous{Repository: kanamepg.New(p, nil), entered: make(chan struct{}, 2), release: make(chan struct{})}
				u.updateRepo = rendezvous
				t.Cleanup(func() {
					select {
					case <-rendezvous.release:
					default:
						close(rendezvous.release)
					}
				})
			}
			g := u.claimGate()
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
			// горутины. При малом пуле два Writer захватывают оба соединения прежде
			// продолжения; authority recheck не должен просить третье соединение.
			g.release(opA.GetId())
			g.release(opB.GetId())
			if rendezvous != nil {
				for i := 0; i < 2; i++ {
					select {
					case <-rendezvous.entered:
					case <-time.After(gduBarrierDeadline):
						t.Fatal("два Writer не дошли до барьера")
					}
				}
				close(rendezvous.release)
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
	entered chan struct{}
	release chan struct{}
}

func (r *gduWriterRendezvous) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case <-r.release:
		return w, nil
	default:
	}
	select {
	case r.entered <- struct{}{}:
	case <-ctx.Done():
		_ = w.Rollback(ctx)
		return nil, ctx.Err()
	}
	select {
	case <-r.release:
		return w, nil
	case <-ctx.Done():
		_ = w.Rollback(ctx)
		return nil, ctx.Err()
	}
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
		grantOp, err := u.abx.Create(asSA(u.ctx, u.svaIss), old)
		require.NoError(t, err)
		u.awaitLockWaiter("grant_delegations", gduBarrierDeadline, "HoldActive старой выдачи ждёт Update row lock")
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
		writer, err := u.repo.Writer(u.ctx)
		require.NoError(t, err)
		defer func() { _ = writer.Rollback(u.ctx) }()
		_, active, err := writer.AccessBindingsW().GrantDelegationsW().HoldActive(u.ctx, domain.GrantDelegationID(u.d))
		require.NoError(t, err)
		require.True(t, active)
		_, msg, err := u.gdCall(asUser(u.ctx, u.usrA), "Update", u.body(gduMask("roleIds"), map[string]any{"roleIds": u.all()["roleIds"]}))
		require.NoError(t, err)
		op := msg.(*operationpb.Operation)
		u.awaitLockWaiter("grant_delegations", gduBarrierDeadline, "Update обязан конфликтовать с HoldActive FOR SHARE")
		// Настоящий Revoke вступает в тот же порядок блокировок. При row→pair
		// вместо pair→row сочетание должно проявить deadlock/неуспех, не тишину.
		_, rmsg, err := u.gdCall(asUser(u.ctx, u.usrA), "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, u.d))
		require.NoError(t, err)
		rop := rmsg.(*operationpb.Operation)
		u.waitLockCount(2)
		require.NoError(t, writer.Commit(u.ctx))
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

func (u *gduWorld) waitLockCount(want int) {
	u.t.Helper()
	ctx, cancel := context.WithTimeout(u.ctx, gduBarrierDeadline)
	defer cancel()
	for {
		var n int
		err := u.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND (query ILIKE '%grant_delegations%' OR query ILIKE '%pg_advisory_xact_lock%')`).Scan(&n)
		require.NoError(u.t, err)
		if n >= want {
			return
		}
		select {
		case <-ctx.Done():
			u.t.Fatalf("порядок не создан: ожидающих %d, нужно %d", n, want)
		case <-time.After(20 * time.Millisecond):
		}
	}
}

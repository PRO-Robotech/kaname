// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_g_race_integration_test.go — группа G приёмки делегированных
// выдач (PRO-Robotech/kaname#986): конкуренция, GD-50 и GD-51, и
// детерминированная гонка CE-09 разбора классов.
//
// Горутины проб не зовут `require`: отказ из горутины не останавливает пробу.
// Исходы собираются и судятся в горутине пробы.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/operations"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// gdInvokeRaw — вызов испытуемого без `require`: годится для горутин.
func (w *gdWorld) gdInvokeRaw(ctx context.Context, method, body string) (proto.Message, error) {
	reg, ok := w.subject.svcs[gdServiceName]
	if !ok {
		return nil, errors.New("служба не провязана")
	}
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	if err != nil {
		return nil, err
	}
	md := d.(protoreflect.ServiceDescriptor).Methods().ByName(protoreflect.Name(method))
	if md == nil {
		return nil, fmt.Errorf("метода %s нет", method)
	}
	in := dynamicpb.NewMessage(md.Input())
	if err := protojson.Unmarshal([]byte(body), in); err != nil {
		return nil, fmt.Errorf("тело не разбирается: %w", err)
	}
	var handler grpc.MethodHandler
	for _, m := range reg.desc.Methods {
		if m.MethodName == method {
			handler = m.Handler
		}
	}
	if handler == nil {
		return nil, fmt.Errorf("обработчика %s нет", method)
	}
	out, err := handler(reg.impl, ctx, func(v any) error {
		raw, err := proto.Marshal(in)
		if err != nil {
			return err
		}
		return proto.Unmarshal(raw, v.(proto.Message))
	}, nil)
	if err != nil {
		return nil, err
	}
	msg, _ := out.(proto.Message)
	return msg, nil
}

// GD-50 — два (восемь) одновременных заведения одной пары; близнец — GD-01.
func TestGrantDelegation_GD50_ConcurrentCreatesOfOnePair(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-50")
	const n = 8
	type result struct {
		opID string
		err  error
	}
	results := make([]result, n)
	body := w.d1Body(w.svaIss)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			msg, err := w.gdInvokeRaw(asUser(w.ctx, w.usrA), "Create", body)
			if op, ok := msg.(*operationpb.Operation); ok {
				results[i].opID = op.GetId()
			}
			results[i].err = err
		}(i)
	}
	close(start)
	wg.Wait()

	ok, dup := 0, 0
	want := fmt.Sprintf("an active grant delegation to service account %s in account %s already exists", w.svaIss, w.accA)
	for i, r := range results {
		require.NoErrorf(t, r.err, "GD-50: вызов %d — синхронный отказ", i)
		require.NotEmptyf(t, r.opID, "GD-50: вызов %d — нет операции", i)
		done := awaitOp(t, w.ctx, w.ops, r.opID)
		if done.Error == nil {
			ok++
			continue
		}
		assert.Equalf(t, codes.AlreadyExists, codes.Code(done.Error.Code), "GD-50: вызов %d — код (текст %q)", i, done.Error.Message)
		assert.Equalf(t, want, done.Error.Message, "GD-50: вызов %d — текст", i)
		dup++
	}
	t.Logf("GD-50: done без ошибки %d, ALREADY_EXISTS %d из %d", ok, dup, n)
	assert.Equal(t, 1, ok, "GD-50: ровно одна операция без ошибки")
	assert.Equal(t, n-1, dup, "GD-50: остальные — ALREADY_EXISTS")
	assert.Equal(t, 1, w.activeDelegationsOfPair(w.accA, w.svaIss), "GD-50: действующих делегирований пары")
}

// GD-51 — выдача делегатом во время отзыва делегирования, 20 раундов;
// близнец — GD-10 a без отзыва.
func TestGrantDelegation_GD51_GrantDuringDelegationRevoke(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-51")
	// Близнец: без отзыва выдача действует.
	twinD1 := w.d1()
	twin := requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), w.v()), "GD-51 близнец (GD-10 a)")
	w.requireDelegatedBinding(twin, twinD1, "GD-51 близнец")
	w.revokeDelegation(asUser(w.ctx, w.usrA), twinD1, "GD-51: отзыв D1 близнеца")

	const rounds = 20
	var denied, txRefused, revokedAfter int
	for round := 0; round < rounds; round++ {
		d1 := w.d1()
		subject := seedServiceAccount(t, w.ctx, w.pool, w.accA, fmt.Sprintf("sva-gd51-%02d", round))
		req := w.vWith(func(r *iamv1.CreateAccessBindingRequest) { r.Subjects = []*iamv1.Subject{svaSubject(subject)} })

		var grantOp *operationpb.Operation
		var grantErr, revokeErr error
		var revokeMsg proto.Message
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			grantOp, grantErr = w.abx.Create(asSA(w.ctx, w.svaIss), req)
		}()
		go func() {
			defer wg.Done()
			<-start
			revokeMsg, revokeErr = w.gdInvokeRaw(asUser(w.ctx, w.usrA), "Revoke", fmt.Sprintf(`{"grantDelegationId":%q}`, d1))
		}()
		close(start)
		wg.Wait()

		require.NoErrorf(t, revokeErr, "GD-51 раунд %d: отзыв D1 — синхронный отказ", round)
		rop, ok := revokeMsg.(*operationpb.Operation)
		require.Truef(t, ok, "GD-51 раунд %d: отзыв — не Operation", round)
		rdone := awaitOp(t, w.ctx, w.ops, rop.GetId())
		require.Nilf(t, rdone.Error, "GD-51 раунд %d: отзыв D1 завершился ошибкой %+v", round, rdone.Error)

		switch {
		case grantErr != nil:
			requireSyncRefusal(t, grantErr, codes.PermissionDenied, "permission denied", fmt.Sprintf("GD-51 раунд %d", round))
			denied++
		default:
			done := awaitOp(t, w.ctx, w.ops, grantOp.GetId())
			if done.Error != nil {
				assert.Equalf(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "GD-51 раунд %d: код Т-D1 (текст %q)", round, done.Error.Message)
				assert.Equalf(t, fmt.Sprintf("grant delegation %s was revoked before the access binding was written", d1),
					done.Error.Message, "GD-51 раунд %d: текст Т-D1", round)
				txRefused++
				break
			}
			var md iamv1.CreateAccessBindingMetadata
			require.NoError(t, grantOp.GetMetadata().UnmarshalTo(&md))
			pb := w.getBinding(md.GetAccessBindingId())
			assert.Equalf(t, iamv1.AccessBinding_REVOKED, pb.GetStatus(), "GD-51 раунд %d: выдача пережила отзыв делегирования ACTIVE", round)
			assert.Equalf(t, reasonDelegationRevoked, pb.GetRevocationReason(), "GD-51 раунд %d: причина", round)
			revokedAfter++
		}
		assert.Zerof(t, w.countActiveDelegated(d1), "GD-51 раунд %d: выдач ACTIVE с delegationId отозванного D1", round)
	}
	t.Logf("GD-51: распределение исходов за %d раундов — синхронный PERMISSION_DENIED %d · Operation.error Т-D1 %d · REVOKED с DELEGATION_REVOKED %d · ACTIVE 0",
		rounds, denied, txRefused, revokedAfter)
	assert.Equal(t, rounds, denied+txRefused+revokedAfter, "GD-51: каждый раунд кончился одним из трёх исходов")
}

// countActiveDelegated — выдач ACTIVE с данным `delegationId`.
func (w *gdWorld) countActiveDelegated(gdl string) int {
	w.t.Helper()
	return w.delegatedBindings(gdl, true)
}

// gdGatedOps — хранилище операций с задвижкой на заведении операции. Выдача
// заводит операцию ПОСЛЕ синхронных проверок права и ДО асинхронной записи
// (`create.go`: `opsRepo.Create` → `operations.Run`), поэтому задвижка
// останавливает выдачу ровно между решением делегированного пути и записью.
type gdGatedOps struct {
	operations.Repo
	armed   atomic.Bool
	entered chan struct{}
	release chan struct{}
}

func newGDGatedOps(inner operations.Repo) *gdGatedOps {
	return &gdGatedOps{Repo: inner, entered: make(chan struct{}), release: make(chan struct{})}
}

func (g *gdGatedOps) hold() {
	if g.armed.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
}

func (g *gdGatedOps) Create(ctx context.Context, op operations.Operation) error {
	g.hold()
	return g.Repo.Create(ctx, op)
}

func (g *gdGatedOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	g.hold()
	return g.Repo.CreateWithPrincipal(ctx, op, p)
}

// ClaimForExecution — подтверждение исполнения проходит к хранилищу, как без задвижки.
func (g *gdGatedOps) ClaimForExecution(ctx context.Context, id string) (bool, error) {
	c, ok := g.Repo.(interface {
		ClaimForExecution(context.Context, string) (bool, error)
	})
	if !ok {
		return true, nil
	}
	return c.ClaimForExecution(ctx, id)
}

// CE-09 — детерминированная гонка выдачи с отзывом делегирования (разбор
// классов, «нужен детерминированный» держатель к GD-51): синхронная проверка
// делегированного пути прошла на действующем D1; затем D1 отозвано и у пары
// заведено новое делегирование D1′ с другими осями; запись выдачи обязана
// перепроверить делегирование ПО ЗАХВАЧЕННОМУ id и отказать Т-D1 — ни
// прицепиться к D1′, ни записаться действующей.
func TestGrantDelegation_CE09_GrantWriteRechecksTheCapturedDelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("CE-09")
	d1 := w.d1()

	gated := newGDGatedOps(w.ops)
	create, _, _ := w.newGrantVerbs(gated)
	h := accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	gated.armed.Store(true)

	type res struct {
		op  *operationpb.Operation
		err error
	}
	got := make(chan res, 1)
	go func() {
		op, err := h.Create(asSA(w.ctx, w.svaIss), w.v())
		got <- res{op, err}
	}()
	select {
	case <-gated.entered:
	case r := <-got:
		t.Fatalf("CE-09: выдача не дошла до заведения операции — синхронный исход %v: делегированный путь отказал на действующем D1", r.err)
	case <-time.After(30 * time.Second):
		t.Fatalf("CE-09: выдача за 30 с не дошла до заведения операции")
	}

	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "CE-09: отзыв D1 между решением и записью")
	d1b := w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss, "registry.registries"),
		"CE-09: новое делегирование пары D1′")
	close(gated.release)

	r := <-got
	require.NoError(t, r.err, "CE-09: синхронный отказ после задвижки")
	done := awaitOp(t, w.ctx, w.ops, r.op.GetId())
	require.NotNil(t, done.Error, "CE-09: запись выдачи по отозванному D1 прошла")
	assert.Equal(t, codes.FailedPrecondition, codes.Code(done.Error.Code), "CE-09: код (текст %q)", done.Error.Message)
	assert.Equal(t, fmt.Sprintf("grant delegation %s was revoked before the access binding was written", d1),
		done.Error.Message, "CE-09: текст Т-D1")
	assert.Zero(t, w.countActiveDelegated(d1), "CE-09: действующих выдач по D1")
	assert.Zero(t, w.countActiveDelegated(d1b), "CE-09: запись прицепилась к D1′ (перевыбор по паре)")
}

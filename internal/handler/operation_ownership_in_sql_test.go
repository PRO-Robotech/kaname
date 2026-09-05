// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operation_ownership_in_sql_test.go — предмет: гейт владения операцией не
// вправе зависеть от УСПЕХА отдельного чтения.
//
// Проверка вида «прочитал строку → сравнил владельца → выполнил мутацию»
// открыта при отказе чтения: неудачное чтение — это не «владелец совпал» и не
// «строки нет», а «не знаю», и продолжать по «не знаю» на мутирующем пути
// нельзя. Правильная форма — предикат владения ВНУТРИ того же оператора, что
// выполняет мутацию (ownership-scoped порт CancelOwned/GetOwned): тогда «не
// удалось» не может превратиться в «разрешено».
package handler

import (
	"context"
	"errors"
	"testing"

	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/operations/operationspb"
)

// ownedOpsRepo — фейк, реализующий И общий operations.Repo, И ownership-scoped
// порт. Несуженные Get/Cancel умеют отвечать транзиентной ошибкой (обрыв
// соединения, рестарт БД), суженные GetOwned/CancelOwned применяют предикат
// владения в том же шаге, что и действие, — как это делает SQL.
type ownedOpsRepo struct {
	store map[string]*operations.Operation
	// unscopedGetErr — ошибка, которой отвечает НЕСУЖЕННОЕ чтение (не
	// ErrNotFound: именно «не удалось прочитать»). Модель подтверждённого
	// триггера: соединение, по которому шло чтение, оборвано (рестарт/failover
	// БД, терминация backend'а, ресет через прокси), а следующий оператор
	// уходит по свежему соединению и ПРОХОДИТ. Именно в этой асимметрии живёт
	// дефект: «не удалось спросить» не мешает «сделать».
	unscopedGetErr error
	// cancelled фиксирует, что мутация реально применилась.
	cancelled map[string]bool
}

func newOwnedOpsRepo(op *operations.Operation) *ownedOpsRepo {
	return &ownedOpsRepo{
		store:     map[string]*operations.Operation{op.ID: op},
		cancelled: map[string]bool{},
	}
}

func (r *ownedOpsRepo) Create(_ context.Context, op operations.Operation) error {
	r.store[op.ID] = &op
	return nil
}

func (r *ownedOpsRepo) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	r.store[op.ID] = &op
	return nil
}

func (r *ownedOpsRepo) Get(_ context.Context, id string) (*operations.Operation, error) {
	if r.unscopedGetErr != nil {
		return nil, r.unscopedGetErr
	}
	o, ok := r.store[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	return o, nil
}

func (r *ownedOpsRepo) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (r *ownedOpsRepo) MarkDone(_ context.Context, _ string, _ *anypb.Any) error { return nil }

func (r *ownedOpsRepo) MarkError(_ context.Context, _ string, _ *gstatus.Status) error { return nil }

// Cancel — несуженная мутация. Она НЕ наследует отказ чтения: оператор уходит
// по свежему соединению, поэтому «чтение сорвалось» и «мутация не применилась»
// — независимые события.
func (r *ownedOpsRepo) Cancel(_ context.Context, id string) error {
	if _, ok := r.store[id]; !ok {
		return operations.ErrNotFound
	}
	r.cancelled[id] = true
	return nil
}

// GetOwned — предикат владения в том же шаге, что и чтение.
func (r *ownedOpsRepo) GetOwned(_ context.Context, id string, owner operations.Owner) (*operations.Operation, error) {
	if owner.IsAnonymous() {
		return nil, operations.ErrNotFound
	}
	o, ok := r.store[id]
	if !ok || o.Principal.Type != owner.PrincipalType || o.Principal.ID != owner.PrincipalID {
		return nil, operations.ErrNotFound
	}
	return o, nil
}

// CancelOwned — предикат владения в том же шаге, что и мутация.
func (r *ownedOpsRepo) CancelOwned(_ context.Context, id string, owner operations.Owner) (*operations.Operation, error) {
	if owner.IsAnonymous() {
		return nil, operations.ErrNotFound
	}
	o, ok := r.store[id]
	if !ok || o.Principal.Type != owner.PrincipalType || o.Principal.ID != owner.PrincipalID {
		return nil, operations.ErrNotFound
	}
	if o.Done {
		return nil, operations.ErrAlreadyDone
	}
	r.cancelled[id] = true
	return o, nil
}

func (r *ownedOpsRepo) ListOwned(_ context.Context, _ operations.ListFilter, _ operations.Owner) ([]operations.Operation, string, error) {
	return nil, "", nil
}

// TestOperationCancel_ReadFailureDoesNotWaiveOwnership — несущая проба класса:
// при отказе несуженного чтения чужая операция НЕ должна отменяться.
//
// Наблюдаемое утверждение — не код ответа, а факт мутации: отказ, выданный уже
// после применения отмены, для клиента выглядит так же, как отказ до неё.
func TestOperationCancel_ReadFailureDoesNotWaiveOwnership(t *testing.T) {
	repo := newOwnedOpsRepo(sampleOp())
	repo.unscopedGetErr = errors.New("read failed: connection reset by peer")
	h := operationspb.NewHandler(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_bob"})

	_, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if err == nil {
		t.Fatalf("cross-principal Cancel must not succeed")
	}
	if repo.cancelled["iop_alice_op_1234567890ab"] {
		t.Fatalf("чужая операция ОТМЕНЕНА: гейт владения снялся вместе с отказом чтения — "+
			"предикат обязан жить в том же шаге, что и мутация (got err=%v)", err)
	}
}

// TestOperationCancel_OwnerStillCancels — законная половина той же формы:
// владелец по-прежнему отменяет свою операцию.
func TestOperationCancel_OwnerStillCancels(t *testing.T) {
	repo := newOwnedOpsRepo(sampleOp())
	h := operationspb.NewHandler(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})

	op, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if err != nil {
		t.Fatalf("owner Cancel must succeed, got %v", err)
	}
	if op.GetId() != "iop_alice_op_1234567890ab" {
		t.Fatalf("wrong op returned: %q", op.GetId())
	}
	if !repo.cancelled["iop_alice_op_1234567890ab"] {
		t.Fatalf("owner Cancel must actually cancel the row")
	}
}

// TestOperationCancel_AnonymousDoesNotCancel — безымянный вызывающий не владеет
// ничем; проба снова смотрит на факт мутации, а не на код.
func TestOperationCancel_AnonymousDoesNotCancel(t *testing.T) {
	repo := newOwnedOpsRepo(sampleOp())
	h := operationspb.NewHandler(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "system", ID: "anonymous"})

	_, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("anonymous Cancel must return NotFound (no-leak), got %v", err)
	}
	if repo.cancelled["iop_alice_op_1234567890ab"] {
		t.Fatalf("anonymous caller cancelled someone else's operation")
	}
}

// TestOperationGet_ResolvedThroughOwnershipScopedPort — чтение идёт суженным
// портом: несуженное чтение в этом фейке отказывает, и владелец всё равно
// получает свою операцию. Тем самым проба фиксирует ПУТЬ, а не только исход.
func TestOperationGet_ResolvedThroughOwnershipScopedPort(t *testing.T) {
	repo := newOwnedOpsRepo(sampleOp())
	repo.unscopedGetErr = errors.New("read failed: connection reset by peer")
	h := operationspb.NewHandler(repo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})

	op, err := h.Get(ctx, &operationpb.GetOperationRequest{OperationId: "iop_alice_op_1234567890ab"})
	if err != nil {
		t.Fatalf("owner Get must be served by the ownership-scoped port, got %v", err)
	}
	if op.GetId() != "iop_alice_op_1234567890ab" {
		t.Fatalf("wrong op returned: %q", op.GetId())
	}
}

// TestOperationHandler_FailsClosedWithoutOwnershipScopedRepo — repo без
// ownership-scoped порта (ошибка провязки) не должен превращаться в
// несуженный доступ: оба метода отказывают.
func TestOperationHandler_FailsClosedWithoutOwnershipScopedRepo(t *testing.T) {
	h := operationspb.NewHandler(&fakeOpsRepoW16{store: map[string]*operations.Operation{
		"iop_alice_op_1234567890ab": sampleOp(),
	}})
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr_alice"})

	if _, err := h.Get(ctx, &operationpb.GetOperationRequest{OperationId: "iop_alice_op_1234567890ab"}); status.Code(err) != codes.Internal {
		t.Fatalf("Get without ownership-scoped repo must fail closed with Internal, got %v", err)
	}
	if _, err := h.Cancel(ctx, &operationpb.CancelOperationRequest{OperationId: "iop_alice_op_1234567890ab"}); status.Code(err) != codes.Internal {
		t.Fatalf("Cancel without ownership-scoped repo must fail closed with Internal, got %v", err)
	}
}

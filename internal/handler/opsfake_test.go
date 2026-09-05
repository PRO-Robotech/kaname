// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Дублёры репозитория операций для проб ЭТОГО сервиса.
//
// Переехали сюда из снятой пробы обработчика (#1369): сам обработчик сведён в
// `pkg/operations/operationspb` и проверяется там одной суитой, а здешние пробы
// утверждают СВОЙ предмет — что репозиторий этого сервиса несёт предикат
// владения и что подделанный заголовок его не снимает.

package handler

import (
	"context"
	"time"

	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// fakeOpsRepoW16 — minimal operations.Repo WITHOUT the ownership-scoped port.
// Он намеренно не реализует operations.OwnedOperationRepo: на нём проверяется,
// что хендлер при такой провязке отказывает (fail-closed), а не сваливается на
// несуженный доступ. Полнофункциональный фейк с предикатом владения —
// ownedOpsRepo в operation_ownership_in_sql_test.go.

type fakeOpsRepoW16 struct {
	store map[string]*operations.Operation
}

func (r *fakeOpsRepoW16) Create(_ context.Context, op operations.Operation) error {
	r.store[op.ID] = &op
	return nil
}

func (r *fakeOpsRepoW16) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	r.store[op.ID] = &op
	return nil
}

func (r *fakeOpsRepoW16) Get(_ context.Context, id string) (*operations.Operation, error) {
	o, ok := r.store[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	return o, nil
}

func (r *fakeOpsRepoW16) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (r *fakeOpsRepoW16) MarkDone(_ context.Context, _ string, _ *anypb.Any) error { return nil }

func (r *fakeOpsRepoW16) MarkError(_ context.Context, _ string, _ *gstatus.Status) error {
	return nil
}

func (r *fakeOpsRepoW16) Cancel(_ context.Context, id string) error {
	if _, ok := r.store[id]; !ok {
		return operations.ErrNotFound
	}
	return nil
}

func sampleOp() *operations.Operation {
	return &operations.Operation{
		ID:        "iop_alice_op_1234567890ab",
		CreatedAt: time.Now(),
		Principal: operations.Principal{Type: "user", ID: "usr_alice"},
	}
}

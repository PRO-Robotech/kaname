// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Дублёры репозитория операций для проб ЭТОГО сервиса.
//
// # Почему дом здесь, а не в `internal/handler` (#2640)
//
// Прежде эти дублёры и их пробы лежали в пакете `internal/handler`, у которого
// после сведения обработчика в фундамент (#1369) не осталось НИ ОДНОГО
// прод-объявления: каталог держал пакет из одних проб, и предмет, о котором они
// говорят, жил в другом месте.
//
// Место это — здесь: репозиторий операций, который композиционный корень отдаёт
// обработчику, собирается `NewTerminalRefusalRepo` в этом самом пакете
// (`terminal_refusal_repo.go`), и пробы рядом с ним судят ту пару, которую
// корень и провязывает.
//
// # Что эти пробы утверждают, а что НЕТ
//
// Утверждают: обработчик операций разрешает чтение и отмену ЧЕРЕЗ суженный
// владением порт, и отказ несуженного чтения не превращается в разрешение.
// Дублёры здесь — не украшение: настоящий предикат владения живёт в SQL, а
// воспроизвести «чтение оборвалось, а следующий оператор прошёл» на живой базе
// нечем.
//
// НЕ утверждают: что репозиторий ЭТОГО сервиса несёт суженный порт. Это держит
// компилятор, а не проба: `NewTerminalRefusalRepo` принимает и отдаёт
// `operations.FullRepo`, а тот включает `OwnedOperationRepo` — провязка без
// суженного порта невыразима by construction. Прежняя редакция шапки утверждала
// обратное, и утверждение было шире сделанного.

package shared

import (
	"context"
	"time"

	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"
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

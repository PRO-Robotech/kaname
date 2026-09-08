// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// name_canon_test.go — канон имени на пути создания ServiceAccount (#1279,
// канон #715).

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// nameCanonOps — записывающий дублёр реестра операций: нужен ИМЕННО
// записывающий, потому что утверждение здесь про то, ЧТО увидит арендатор в
// ответе операции. Дублёр-пустышка оставил бы пробу зелёной при любом имени.
type nameCanonOps struct {
	mu  sync.Mutex
	ops map[string]*operations.Operation
}

func newNameCanonOps() *nameCanonOps {
	return &nameCanonOps{ops: map[string]*operations.Operation{}}
}

func (r *nameCanonOps) Create(_ context.Context, op operations.Operation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cp := op
	r.ops[op.ID] = &cp
	return nil
}

func (r *nameCanonOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, _ operations.Principal) error {
	return r.Create(ctx, op)
}

func (r *nameCanonOps) Get(_ context.Context, id string) (*operations.Operation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	op, ok := r.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	cp := *op
	return &cp, nil
}

func (r *nameCanonOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (r *nameCanonOps) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done, op.Response = true, resp
	}
	return nil
}

func (r *nameCanonOps) MarkError(_ context.Context, id string, st *gstatus.Status) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done, op.Error = true, st
	}
	return nil
}

func (r *nameCanonOps) Cancel(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if op, ok := r.ops[id]; ok {
		op.Done = true
	}
	return nil
}

func createServiceAccountNamed(t *testing.T, name string) *iamv1.ServiceAccount {
	t.Helper()
	opsRepo := newNameCanonOps()
	uc := NewCreateServiceAccountUseCase(newLcsRepo(nil), opsRepo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000abcd"})
	op, err := uc.Execute(ctx, domain.ServiceAccount{
		AccountID: domain.AccountID(lcsAcctID),
		Name:      domain.SvcAccountName(name),
	})
	require.NoError(t, err, "создание с именем %q обязано пройти синхронную проверку", name)
	require.NotNil(t, op)

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	done, err := opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, done.Done, "операция обязана завершиться")
	require.Nil(t, done.Error, "создание обязано пройти, отказ: %v", done.Error)
	require.NotNil(t, done.Response, "ответ операции обязан нести созданный ресурс")

	var got iamv1.ServiceAccount
	require.NoError(t, done.Response.UnmarshalTo(&got))
	return &got
}

// TestCreateServiceAccount_EmptyName_WritesIdDerivedDefault — пустое имя до
// записи не доживает.
func TestCreateServiceAccount_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := createServiceAccountNamed(t, "")
	assert.NotEmpty(t, got.Name, "строка ресурса не может нести пустое имя")
	assert.Equal(t, got.Id, got.Name, "умолчание — сам идентификатор (pkg/validate.NameOrDefault)")
}

// TestCreateServiceAccount_TwoEmptyNames_DistinctNames — оба безымянных создания
// проходят и получают разные имена (`service_accounts_account_name_unique`).
func TestCreateServiceAccount_TwoEmptyNames_DistinctNames(t *testing.T) {
	first := createServiceAccountNamed(t, "")
	second := createServiceAccountNamed(t, "")
	assert.NotEqual(t, first.Name, second.Name,
		"два безымянных создания обязаны получить разные имена")
}

// TestCreateServiceAccount_CanonNames_Accepted — положительный контроль.
func TestCreateServiceAccount_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "sa-ok"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := createServiceAccountNamed(t, tc.value)
			assert.Equal(t, tc.value, got.Name, "присланное имя обязано сохраниться как есть")
		})
	}
}

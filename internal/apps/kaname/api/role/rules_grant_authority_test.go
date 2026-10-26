// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// rules_grant_authority_test.go — порядок и исходы проверки Р2 в правке роли
// (приёмка role-rights-stay-within-what-is-named.md, Р2, Д-4, Д-5; задача
// PRO-Robotech/kaname#1036). Поведение на настоящем хранилище и двери решения
// держат интеграционные ESC-10…14 мира Э; здесь — то, что видно на одном
// use-case: кого и когда спрашивают и что отвечает непровязанный порт.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// grantAuthorityAnswer — дублёр порта Р2 с заданным ответом и перечнем
// спрошенных ролей. Пробы, чей предмет — не право выдавать, провязывают его с
// ответом «разрешено» явно: непровязанный порт правку правил отвергает.
type grantAuthorityAnswer struct {
	mu    sync.Mutex
	err   error
	asked []domain.RoleID
}

func (a *grantAuthorityAnswer) RequireForRole(_ context.Context, id domain.RoleID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, id)
	return a.err
}

// countingOps — хранилище операций, считающее заведённые операции.
type countingOps struct {
	*rlFakeOps
	mu      sync.Mutex
	created int
}

func (o *countingOps) Create(ctx context.Context, op operations.Operation) error {
	o.mu.Lock()
	o.created++
	o.mu.Unlock()
	return o.rlFakeOps.Create(ctx, op)
}

func (o *countingOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	o.mu.Lock()
	o.created++
	o.mu.Unlock()
	return o.rlFakeOps.CreateWithPrincipal(ctx, op, p)
}

func r2RulesInput() UpdateRoleInput {
	return UpdateRoleInput{
		ID:         rlUpdRoleID,
		Rules:      domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}},
		UpdateMask: []string{"rules"},
	}
}

// TestUpdateRole_R2_RefusalIsSyncAndCreatesNoOperation — отказ порта доходит до
// вызывающего синхронно и дословно, операции нет. Близнец — ответ «разрешено»:
// операция заведена, роль спрошена ровно одна.
func TestUpdateRole_R2_RefusalIsSyncAndCreatesNoOperation(t *testing.T) {
	allow := &grantAuthorityAnswer{}
	okOps := &countingOps{rlFakeOps: newRlFakeOps()}
	op, err := NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{}), okOps, catalogfixture.Source()).
		WithGrantAuthority(allow).Execute(ownerCtx(), r2RulesInput())
	require.NoError(t, err, "близнец: право выдавать подтверждено")
	require.NotNil(t, op)
	waitOps(t)
	assert.Equal(t, []domain.RoleID{rlUpdRoleID}, allow.asked, "близнец: спрошена правимая роль")
	assert.Equal(t, 1, okOps.created, "близнец: операция заведена")

	deny := &grantAuthorityAnswer{err: authzguard.PermissionDenied()}
	ops := &countingOps{rlFakeOps: newRlFakeOps()}
	op, err = NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{}), ops, catalogfixture.Source()).
		WithGrantAuthority(deny).Execute(ownerCtx(), r2RulesInput())
	require.Nil(t, op, "отказ Р2: операция не возвращена")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(), "отказ Р2: код")
	assert.Equal(t, "permission denied", st.Message(), "отказ Р2: текст")
	assert.Zero(t, ops.created, "отказ Р2: операция не заведена")
}

// TestUpdateRole_R2_NonRulesEditDoesNotAsk — правка, не называющая правил,
// порта не спрашивает (Д-5) и проходит даже при отказывающем порте.
func TestUpdateRole_R2_NonRulesEditDoesNotAsk(t *testing.T) {
	deny := &grantAuthorityAnswer{err: authzguard.PermissionDenied()}
	desc := domain.Description("esc-12")
	op, err := NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(), catalogfixture.Source()).
		WithGrantAuthority(deny).Execute(ownerCtx(), UpdateRoleInput{
		ID: rlUpdRoleID, Description: &desc, UpdateMask: []string{"description"},
	})
	require.NoError(t, err, "правка описания права выдавать не требует")
	require.NotNil(t, op)
	waitOps(t)
	assert.Empty(t, deny.asked, "правка описания спросила порт Р2")
}

// TestUpdateRole_R2_InvalidRulesRefusedBeforeTheQuestion — порядок Д-4: правила,
// которых каталог не знает, отвергаются ДО вопроса о праве — отказ в праве не
// говорит о правилах, а отказ в правилах не стоит вопроса к хранилищу.
func TestUpdateRole_R2_InvalidRulesRefusedBeforeTheQuestion(t *testing.T) {
	a := &grantAuthorityAnswer{err: authzguard.PermissionDenied()}
	_, err := NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{}), newRlFakeOps(), catalogfixture.Source()).
		WithGrantAuthority(a).Execute(ownerCtx(), UpdateRoleInput{
		ID:         rlUpdRoleID,
		Rules:      domain.Rules{{Module: "vpc", Resources: []string{"security_group"}, Verbs: []string{"get"}}},
		UpdateMask: []string{"rules"},
	})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "неизвестный каталогу ресурс — отказ формы (%v)", err)
	assert.Empty(t, a.asked, "порт Р2 спрошен раньше проверки правил")
}

// TestUpdateRole_R2_UnwiredPortRefusesTheRulesChange — непровязанный порт
// отвергает правку правил (fail-closed) фиксированным текстом; операции нет.
func TestUpdateRole_R2_UnwiredPortRefusesTheRulesChange(t *testing.T) {
	ops := &countingOps{rlFakeOps: newRlFakeOps()}
	op, err := NewUpdateRoleUseCase(newRlUpdRepo(domain.Labels{}), ops, catalogfixture.Source()).
		Execute(ownerCtx(), r2RulesInput())
	require.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code(), "непровязанный порт: код")
	assert.Equal(t, "internal error", st.Message(), "непровязанный порт: текст наружу фиксирован")
	assert.Zero(t, ops.created, "непровязанный порт: операция не заведена")
}

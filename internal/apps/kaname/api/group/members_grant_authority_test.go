// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// members_grant_authority_test.go — порядок и исходы проверки Р3 в добавлении
// участника (приёмка role-rights-stay-within-what-is-named.md, Р3, Д-4; задача
// PRO-Robotech/kaname#1037). Поведение на настоящем хранилище и двери решения
// держат интеграционные ESC-20…25 мира Э; здесь — что видно на одном use-case.

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// groupGrantAuthorityAnswer — дублёр порта Р3 с заданным ответом и перечнем
// спрошенных групп. Пробы, чей предмет — не право выдавать, провязывают его с
// ответом «разрешено» явно: непровязанный порт добавление отвергает.
type groupGrantAuthorityAnswer struct {
	mu    sync.Mutex
	err   error
	asked []domain.GroupID
}

func (a *groupGrantAuthorityAnswer) RequireForGroup(_ context.Context, id domain.GroupID) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, id)
	return a.err
}

func r3Input() AddMemberInput {
	return AddMemberInput{GroupID: metaGrp, MemberType: domain.SubjectTypeUser, MemberID: "usr0000000000000mmmm"}
}

// TestAddMember_R3_RefusalIsSyncAndCreatesNoOperation — отказ порта доходит до
// вызывающего синхронно и дословно, операции нет; близнец — «разрешено».
func TestAddMember_R3_RefusalIsSyncAndCreatesNoOperation(t *testing.T) {
	allow := &groupGrantAuthorityAnswer{}
	okOps := newFakeGrpOps()
	op, err := NewAddMemberUseCase(newFakeGrpRepo(), okOps).WithGrantAuthority(allow).Execute(ownerCtx(), r3Input())
	require.NoError(t, err, "близнец: право выдавать подтверждено")
	require.NotNil(t, op)
	assert.Equal(t, []domain.GroupID{metaGrp}, allow.asked, "близнец: спрошена группа добавления")

	deny := &groupGrantAuthorityAnswer{err: authzguard.PermissionDenied()}
	ops := newFakeGrpOps()
	op, err = NewAddMemberUseCase(newFakeGrpRepo(), ops).WithGrantAuthority(deny).Execute(ownerCtx(), r3Input())
	require.Nil(t, op, "отказ Р3: операция не возвращена")
	st, _ := status.FromError(err)
	assert.Equal(t, codes.PermissionDenied, st.Code(), "отказ Р3: код")
	assert.Equal(t, "permission denied", st.Message(), "отказ Р3: текст")
	assert.Empty(t, ops.ops, "отказ Р3: операция не заведена")
}

// TestAddMember_R3_BadMemberTypeRefusedBeforeTheQuestion — порядок Д-4: вид
// участника проверяется ДО вопроса о праве.
func TestAddMember_R3_BadMemberTypeRefusedBeforeTheQuestion(t *testing.T) {
	a := &groupGrantAuthorityAnswer{err: authzguard.PermissionDenied()}
	in := r3Input()
	in.MemberType = domain.SubjectTypeGroup
	_, err := NewAddMemberUseCase(newFakeGrpRepo(), newFakeGrpOps()).WithGrantAuthority(a).Execute(ownerCtx(), in)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "группа участником — отказ формы (%v)", err)
	assert.Empty(t, a.asked, "порт Р3 спрошен раньше проверки вида участника")
}

// TestAddMember_R3_UnwiredPortRefusesTheAdd — непровязанный порт отвергает
// добавление (fail-closed) фиксированным текстом; операции нет.
func TestAddMember_R3_UnwiredPortRefusesTheAdd(t *testing.T) {
	ops := newFakeGrpOps()
	op, err := NewAddMemberUseCase(newFakeGrpRepo(), ops).Execute(ownerCtx(), r3Input())
	require.Nil(t, op)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code(), "непровязанный порт: код")
	assert.Equal(t, "internal error", st.Message(), "непровязанный порт: текст наружу фиксирован")
	assert.Empty(t, ops.ops, "непровязанный порт: операция не заведена")
}

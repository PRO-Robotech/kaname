// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_role_test.go — модульные пробы читающего RPC аудита ListByRole
// для модели правил RBAC 2026. Чтение списка из репозитория проверяет
// интеграционная проба pg; здесь проверяются минимум прав сценария
// и поток чтения через поддельный репозиторий.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

func TestListByRole_E33_AnonymousRejected(t *testing.T) {
	repo := newABFakeRepo("usr_owner-----------", "acc_a", "acc_a", "rol_r", "viewer", domain.Permissions{"iam.access_bindings.get"})
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	_, _, err := uc.Execute(context.Background(), "rol_r", repoab.ListByRoleFilter{})
	require.Error(t, err, "anonymous caller must be rejected")
}

func TestListByRole_E33_MalformedRoleID(t *testing.T) {
	repo := newABFakeRepo("usr_owner-----------", "acc_a", "acc_a", "rol_r", "viewer", domain.Permissions{"iam.access_bindings.get"})
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := newOwnerContext("usr_owner-----------")
	_, _, err := uc.Execute(ctx, "not-a-role-id!!", repoab.ListByRoleFilter{})
	require.Error(t, err, "malformed role id → INVALID_ARGUMENT")
}

func TestListByRole_E33_OwnerSeesBinding(t *testing.T) {
	const (
		roleID    = domain.SystemAdminRoleID
		ownerID   = "usr_owner-----------"
		accountID = "acc_lbr_account-----"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer", domain.Permissions{"iam.access_bindings.get"})
	// Сеем выдачу с этой ролью (хранилище подделки вмещает одну выдачу).
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1-----------",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_member----------",
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	uc := NewListByRoleUseCase(repo).WithRelationStore(newRecordingFGA(), nil)
	ctx := newOwnerContext(ownerID) // владелец аккаунта → право выдачи

	got, _, err := uc.Execute(ctx, roleID, repoab.ListByRoleFilter{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, got, 1, "account owner sees the binding carrying the role")
	require.Equal(t, domain.RoleID(roleID), got[0].RoleID)
}

var _ = authzguard.PermissionDenied // сохраняем ссылку на импорт

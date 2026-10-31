// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// list_by_role_visibility_test.go — что ПОСТОРОННИЙ получает при чтении
// аудита «кто держит роль R».
//
// Запись каталога для этого RPC требует `viewer` на единственном кластере,
// а начальный посев кластера даёт это отношение системному классу `authenticated`,
// чтобы глобальный справочник оставался читаемым. Любой аутентифицированный субъект
// проходит входную проверку; построчный фильтр области в сценарии — единственное сужение.
// Набор закреплял положительную ветвь (владелец аккаунта видит выдачу), но не
// отрицательную. Фильтр без красной пробы на случай, который он должен
// предотвращать, можно снять незаметно.
//
// Проверяется наблюдаемый результат — возвращённые строки, а не код
// статуса: посторонний не должен узнать ни о существовании выдачи, ни о её
// субъекте, ни об области, к которой она относится.

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// TestListByRole_StrangerSeesNothing — аутентифицированный вызывающий, который
// не владеет областью выдачи, не администрирует её и не является её субъектом, получает пустую страницу.
func TestListByRole_StrangerSeesNothing(t *testing.T) {
	const (
		roleID    = domain.SystemAdminRoleID
		ownerID   = "usr_owner-----------"
		accountID = "acc_lbr_account-----"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1-----------",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    "usr_member----------",
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	// denyingFGA: делегированного администратора нигде нет, вызывающий — не владелец.
	uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	got, _, err := uc.Execute(foreignCtx(), roleID, repoab.ListByRoleFilter{PageSize: 50})

	require.NoError(t, err, "a stranger gets an empty page, not an error")
	require.Empty(t, got,
		"a stranger must learn neither that the binding exists nor who holds the role")
}

// TestListByRole_SubjectOfBindingSeesOwnRow — намеренное исключение: получатель
// выдачи видит свою строку даже без полномочий на область. Это закрепляет,
// что сужение выше фильтрует область, а не запрещает чтение всем.
func TestListByRole_SubjectOfBindingSeesOwnRow(t *testing.T) {
	const (
		roleID    = domain.SystemAdminRoleID
		ownerID   = "usr_owner-----------"
		accountID = "acc_lbr_account-----"
		memberID  = "usr_member----------"
	)
	repo := newABFakeRepo(ownerID, accountID, accountID, roleID, "viewer",
		domain.Permissions{"iam.access_bindings.get"})
	repo.ab = &domain.AccessBinding{
		ID:           "acb_lbr_1-----------",
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    memberID,
		RoleID:       domain.RoleID(roleID),
		ResourceType: "account",
		ResourceID:   accountID,
		Status:       domain.AccessBindingStatusActive,
	}
	uc := NewListByRoleUseCase(repo).WithRelationStore(&denyingFGA{}, nil)

	got, _, err := uc.Execute(newOwnerContext(memberID), roleID, repoab.ListByRoleFilter{PageSize: 50})

	require.NoError(t, err)
	require.Len(t, got, 1, "the subject of the grant sees the grant that names them")
	require.Equal(t, domain.SubjectID(memberID), got[0].SubjectID)
}

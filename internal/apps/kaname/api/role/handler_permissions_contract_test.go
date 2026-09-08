// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

// handler_permissions_contract_test.go — ТРИ исхода входного `permissions`,
// закреплённые поведением, потому что комментарий контракта называл ОДИН
// («на входе Create/Update игнорируется», `#1949`). Исход зависит от ПУТИ и от
// МАСКИ, а не от самого поля:
//
//	Create, поле непусто               → INVALID_ARGUMENT «Illegal argument
//	                                     permissions (compiled/output-only)»
//	                                     (A-02, handler.go — handler_rules_test.go)
//	Update, поле названо в update_mask → INVALID_ARGUMENT «permissions is
//	                                     immutable after Role.Create»
//	                                     (A-08, update.go — handler_rules_test.go)
//	Update, поле в теле, маска молчит  → значение НЕ ЧИТАЕТСЯ (этот файл)
//
// Первые два уже пинил `handler_rules_test.go`; третий не пинил никто — и ровно
// он единственный, для которого слово «игнорируется» было верным. Пока он не
// закреплён, комментарий контракта нечем удержать: его правку не роняет ничто.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// Update, чья маска НЕ называет permissions, доезжает до записи: значение из
// тела не читается ни одной веткой прод-кода, и мутация мимо него проходит
// целиком. Это и есть единственный путь, на котором вход «игнорируется».
func TestRoleHandler_UpdatePermissionsInBodyWithoutMask_IsNotRead(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "payments"})
	h := &Handler{update: NewUpdateRoleUseCase(repo, newRlFakeOps(), catalogfixture.Source())}

	_, err := h.Update(ownerCtx(), &iamv1.UpdateRoleRequest{
		RoleId:      rlUpdRoleID,
		Labels:      map[string]string{"team": "sre"},
		Permissions: []string{"vpc.subnet.*.get"}, //nolint:staticcheck // предмет пробы: значение обязано остаться непрочитанным
		UpdateMask:  &fieldmaskpb.FieldMask{Paths: []string{"labels"}},
	})

	require.NoError(t, err, "permissions в теле без маски не отвергается")
	waitOps(t)
	assert.Equal(t, domain.Labels{"team": "sre"}, repo.labelsSnapshot(),
		"мутация мимо permissions прошла целиком — поле не помешало")
}

// Парный отрицательный контроль на ТОТ ЖЕ вход: различает исходы МАСКА, а не
// тело. Без него положительный выше остался бы зелёным и на сервере, который
// permissions не отвергает нигде, — то есть не утверждал бы ничего.
func TestRoleHandler_UpdatePermissionsDiscriminatorIsTheMask(t *testing.T) {
	repo := newRlUpdRepo(domain.Labels{"team": "payments"})
	h := &Handler{update: NewUpdateRoleUseCase(repo, newRlFakeOps(), catalogfixture.Source())}

	_, err := h.Update(ownerCtx(), &iamv1.UpdateRoleRequest{
		RoleId:      rlUpdRoleID,
		Labels:      map[string]string{"team": "sre"},
		Permissions: []string{"vpc.subnet.*.get"}, //nolint:staticcheck // тот же вход, что в положительной пробе
		UpdateMask:  &fieldmaskpb.FieldMask{Paths: []string{"labels", "permissions"}},
	})

	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code(), "маска, назвавшая permissions, отвергается")
	assert.Equal(t, "permissions is immutable after Role.Create", st.Message(),
		"текст отказа — часть контракта")
	assert.Empty(t, repo.labelsSnapshot(),
		"отказ по маске наступает ДО записи — метки не применены")
}

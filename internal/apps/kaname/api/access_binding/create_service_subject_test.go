// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_service_subject_test.go — тенантская поверхность выдачи служебного
// субъекта не производит (приёмка NTF-1, NTF1-M10 (а); замысел З17).
//
// Субъект `service:<имя>` производит только фундамент из проверенного
// сертификата и применитель манифеста. Привязка доступа с субъектом типа
// `service` — `INVALID_ARGUMENT` с полем `subjects[i].type` и текстом приёмки,
// `Operation` не создаётся, кортежей не прибавляется. Близнец — тот же запрос с
// субъектом `user`: принят. Без близнеца проба зеленела бы на использовании,
// отвергающем всякую выдачу.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestNTF1M10a_ServiceSubjectIsNotGrantable(t *testing.T) {
	const (
		roleID     = "rol_m10_test--------"
		roleName   = "viewer"
		userID     = "usr_m10_user--------"
		resourceID = "acc_m10_account-----"
		ownerID    = "usr_m10_owner-------"
		accountID  = "acc_m10_account-----"
	)
	perms := domain.Permissions{"iam.access_bindings.get", "iam.access_bindings.list"}

	cases := []struct {
		name      string
		binding   domain.AccessBinding
		wantField string
	}{
		{
			name: "единственная форма subject_type",
			binding: domain.AccessBinding{
				SubjectType: "service", SubjectID: "notify",
			},
			wantField: "subjects[0].type",
		},
		{
			name: "subjects[0]",
			binding: domain.AccessBinding{
				Subjects: []domain.Subject{{Type: "service", ID: "notify"}},
			},
			wantField: "subjects[0].type",
		},
		{
			name: "subjects[1] рядом с законным",
			binding: domain.AccessBinding{
				Subjects: []domain.Subject{
					{Type: domain.SubjectTypeUser, ID: userID},
					{Type: "service", ID: "notify"},
				},
			},
			wantField: "subjects[1].type",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
			opsRepo := newFakeOpsRepo()
			uc := NewCreateAccessBindingUseCase(repo, opsRepo).WithRelationStore(newRecordingFGA(), nil)

			b := tc.binding
			b.RoleID = domain.RoleID(roleID)
			b.ResourceType = "account"
			b.ResourceID = resourceID
			op, err := uc.Execute(newOwnerContext(ownerID), b)

			require.Nil(t, op, "Operation создана на служебном субъекте")
			st := status.Convert(err)
			require.Equal(t, codes.InvalidArgument, st.Code(), "код: %v", err)
			want := tc.wantField + ": 'service' is not a grantable subject type"
			require.Equal(t, want, st.Message())
			var field string
			for _, d := range st.Details() {
				if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) == 1 {
					field = br.GetFieldViolations()[0].GetField()
				}
			}
			require.Equal(t, tc.wantField, field, "поле нарушения не названо")
			require.Empty(t, opsRepo.ops, "в хранилище операций появилась запись")
			require.Empty(t, repo.drainFGAWritten(), "кортежи прибавились при отказе")
		})
	}

	t.Run("близнец: субъект user принят", func(t *testing.T) {
		repo := newABFakeRepo(ownerID, accountID, resourceID, roleID, roleName, perms)
		uc := NewCreateAccessBindingUseCase(repo, newFakeOpsRepo()).WithRelationStore(newRecordingFGA(), nil)
		op, err := uc.Execute(newOwnerContext(ownerID), domain.AccessBinding{
			RoleID: domain.RoleID(roleID), ResourceType: "account", ResourceID: resourceID,
			Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: userID}},
		})
		require.NoError(t, err)
		require.NotNil(t, op)
		waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		require.NoError(t, operations.Wait(waitCtx))
	})
}

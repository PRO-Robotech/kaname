// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// TestCreate_WildcardSubjectIsRejectedInAnyPosition — подстановочный субъект
// в любом месте набора несистемной выдачи — синхронный отказ без операции
// (kaname#917); близнец без подстановочного — операция заводится.
func TestCreate_WildcardSubjectIsRejectedInAnyPosition(t *testing.T) {
	const roleID = "rol_wild_position---"
	newUC := func() (*CreateAccessBindingUseCase, *fakeOpsRepo) {
		repo := newABFakeRepo("usr_owner-----------", "acc_x", "", roleID, "vpc_reader", nil)
		repo.setRoleRules(domain.Rules{
			{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"net1"}},
		})
		ops := newFakeOpsRepo()
		return NewCreateAccessBindingUseCase(repo, ops, catalogfixture.Source()).WithRelationStore(newRecordingFGA(), nil), ops
	}
	second := func(id domain.SubjectID) domain.AccessBinding {
		b := clusterScopeBinding(roleID, "usr_wildposition0001")
		b.Subjects = append(b.Subjects, domain.Subject{Type: domain.SubjectTypeUser, ID: id})
		return b
	}

	t.Run("подстановочный вторым — отказ", func(t *testing.T) {
		uc, ops := newUC()
		_, err := uc.Execute(clusterAdminCtx("usr_root------------"), second("*"))
		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, status.Code(err))
		require.Equal(t, `Illegal argument subject_id "*" on a non-system access binding`, status.Convert(err).Message())
		require.Empty(t, ops.ops, "отказ синхронный: операции нет")
	})
	t.Run("без подстановочного — операция", func(t *testing.T) {
		uc, _ := newUC()
		op, err := uc.Execute(clusterAdminCtx("usr_root------------"), second("usr_wildposition0002"))
		require.NoError(t, err)
		require.NotNil(t, op)
	})
}

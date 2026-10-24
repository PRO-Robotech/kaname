// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// TestCreate_DescriptionNamesEverySubject — описание операции создания
// называет КАЖДОГО субъекта выдачи, а не проекцию первого (kaname#917): у
// выдачи двум субъектам второй в описании есть; у выдачи одному описание то же,
// что давала пара.
func TestCreate_DescriptionNamesEverySubject(t *testing.T) {
	const roleID = "rol_desc_names------"
	newUC := func() (*CreateAccessBindingUseCase, *fakeOpsRepo) {
		repo := newABFakeRepo("usr_owner-----------", "acc_x", "", roleID, "vpc_reader", nil)
		repo.setRoleRules(domain.Rules{
			{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get"}, ResourceNames: []string{"net1"}},
		})
		ops := newFakeOpsRepo()
		return NewCreateAccessBindingUseCase(repo, ops, catalogfixture.Source()).WithRelationStore(newRecordingFGA(), nil), ops
	}

	t.Run("двум субъектам", func(t *testing.T) {
		uc, _ := newUC()
		b := clusterScopeBinding(roleID, "usr_desctarget000001")
		b.Subjects = append(b.Subjects, domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_descsecond000001"})
		op, err := uc.Execute(clusterAdminCtx("usr_root------------"), b)
		require.NoError(t, err)
		require.NotNil(t, op)
		require.True(t, strings.Contains(op.Description, "user/usr_desctarget000001") && strings.Contains(op.Description, "user/usr_descsecond000001"),
			"описание обязано называть обоих субъектов, получено %q", op.Description)
	})
	t.Run("одному субъекту — прежний текст", func(t *testing.T) {
		uc, _ := newUC()
		op, err := uc.Execute(clusterAdminCtx("usr_root------------"), clusterScopeBinding(roleID, "usr_desctarget000001"))
		require.NoError(t, err)
		require.Equal(t, "Create access binding (user/usr_desctarget000001 → "+roleID+" on cluster/"+domain.ClusterSingletonID+")",
			op.Description)
	})
}

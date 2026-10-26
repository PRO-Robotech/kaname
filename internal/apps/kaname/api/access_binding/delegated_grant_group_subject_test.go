// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// delegated_grant_group_subject_test.go — субъект-группа выдачи делегатом судится
// и по СОСТАВУ (задача PRO-Robotech/kaname#986, §1 приёмки: делегирование не
// даёт делегату доступа к данным; находка ревью SEC-986-1).
//
// Право роли, выданное группе, достаётся каждому её члену. Группа, в составе
// которой делегат, для Д4 — тот же делегат. Вложенных групп модель не знает:
// член группы — только человек или учётка (`group_members_type_check`), поэтому
// состав читается одним уровнем.
//
// Пара близнецов отличается ровно составом группы. Мир и пул — общие с пробой
// SD-986-C1 (`delegated_grant_one_connection_test.go`).

import (
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestDelegatedGrant_D4_GroupHoldingTheDelegateIsTheDelegate(t *testing.T) {
	for _, tc := range []struct {
		name           string
		delegateMember bool
	}{
		{name: "делегат в составе группы — отказ", delegateMember: true},
		{name: "близнец: группа без делегата — принято", delegateMember: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newConnWorld()
			w.members[domain.SubjectID(w.subjectSA)] = true
			if tc.delegateMember {
				w.members[domain.SubjectID(w.delegate)] = true
			}
			pool := &connPool{}
			p := NewDelegatedGrantPath(&connRepo{pool: pool, w: w}, connRelations{pool: pool})

			gdl, err := delegatedGrantAuthority(asDelegate(w), p, w.binding(domain.Subject{
				Type: domain.SubjectTypeGroup, ID: domain.SubjectID(w.group)}), false)

			require.Zero(t, pool.held, "соединения пути возвращены в пул")
			if !tc.delegateMember {
				require.NoError(t, err, "группа без делегата")
				require.Equal(t, w.d.ID, gdl)
				return
			}
			require.Error(t, err, "выдача группе, в которой состоит делегат, принята")
			st, _ := status.FromError(err)
			require.Equal(t, codes.PermissionDenied, st.Code(), "код (текст %q)", st.Message())
			require.Equal(t, "permission denied", st.Message(), "текст — побайтово тот же отказ, что у вызывающего без права")
			require.Empty(t, gdl)
		})
	}
}

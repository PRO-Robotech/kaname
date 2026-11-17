// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

// Отсутствие получателя не должно прерывать подготовку полномочий ошибкой
// owner lookup. После настоящего D3 прежняя проверка ссылки одинаково
// отвергает отсутствующую и чужую учётку; своя учётка служит законным близнецом.
func TestGroupAdditionOptionalReferenceMissingMatchesForeignAfterAuthority(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, local := membershipFixture(t, r)
	foreign := seedSAID(t, r.ctx, r.admin, r.b, "optional-reference-foreign")
	missing := ids.NewID(domain.PrefixServiceAccount)
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	var refusal string
	for _, tc := range []struct {
		name, id string
		allowed  bool
	}{{"foreign", foreign, false}, {"missing", missing, false}, {"local", local, true}} {
		t.Run(tc.name, func(t *testing.T) {
			member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(tc.id)}
			w, err := writers.GroupAdditionAuthorityWriter(r.ctx, member, actor)
			require.NoError(t, err, "подготовка не подменяет позднюю проверку ссылки")
			roleFinalCleanup(t, w)
			if tc.name == "missing" {
				require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode())
			}
			require.NoError(t, grantpolicy.RequireGroupAddition(r.ctx, w, actor, member))
			err = w.GroupsW().RequireMemberOfGroupAccount(r.ctx, member)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, iamerr.ErrReferenceMissing)
				if refusal == "" {
					refusal = err.Error()
				} else {
					require.Equal(t, refusal, err.Error())
				}
			}
			require.NoError(t, w.Rollback(r.ctx))
			membershipCounts(t, r, string(g.ID), "service_account:"+tc.id, 0)
		})
	}
	canceled, cancel := context.WithCancel(r.ctx)
	cancel()
	w, err := writers.GroupAdditionAuthorityWriter(canceled, domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(missing)}, actor)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, w)
}

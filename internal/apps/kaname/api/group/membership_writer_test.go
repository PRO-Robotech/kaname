// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type membershipFactoryProbe struct {
	w       Writer
	err     error
	members []domain.GroupMember
}

func (p *membershipFactoryProbe) GroupMembershipWriter(_ context.Context, m domain.GroupMember) (kaname.Writer, error) {
	p.members = append(p.members, m)
	return p.w, p.err
}
func TestMembershipParticipantWorkersUseSelectedTransaction(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(map[bool]string{false: "add", true: "remove"}[remove], func(t *testing.T) {
			legacy, old := newFakeMemberRepo()
			_, selected := newFakeMemberRepo()
			f := &membershipFactoryProbe{w: selected}
			var err error
			if remove {
				_, err = NewRemoveMemberUseCase(legacy, nil).WithMembershipWriter(f).doRemove(context.Background(), RemoveMemberInput{GroupID: testGroupID, MemberType: domain.SubjectTypeUser, MemberID: testMemberID})
			} else {
				_, err = NewAddMemberUseCase(legacy, nil).WithMembershipWriter(f).doAdd(context.Background(), AddMemberInput{GroupID: testGroupID, MemberType: domain.SubjectTypeUser, MemberID: testMemberID})
			}
			require.NoError(t, err)
			require.False(t, old.committed)
			require.Empty(t, old.seq)
			require.True(t, selected.committed)
			require.Len(t, f.members, 1)
			require.Equal(t, testGroupID, f.members[0].GroupID)
			require.Equal(t, testMemberID, f.members[0].MemberID)
			require.Len(t, selected.abw.events, 1)
			if remove {
				require.Len(t, selected.delEmitted, 1)
				require.Len(t, selected.gw.removed, 1)
			} else {
				require.Len(t, selected.writeEmitted, 1)
				require.Len(t, selected.gw.added, 1)
				require.Len(t, selected.gw.belongAsked, 1)
			}
		})
	}
}
func TestMembershipParticipantFailureNeverFallsBack(t *testing.T) {
	var typedNil *membershipFactoryProbe
	for name, f := range map[string]kaname.GroupMembershipWriterFactory{"nil": nil, "typed_nil": typedNil, "entry_error": &membershipFactoryProbe{err: errors.New("closed")}, "changed": &membershipFactoryProbe{err: kaname.ErrAuthorityClassificationChanged}, "absent_writer": &membershipFactoryProbe{}} {
		t.Run(name, func(t *testing.T) {
			repo, w := newFakeMemberRepo()
			_, err := NewAddMemberUseCase(repo, nil).WithMembershipWriter(f).doAdd(context.Background(), AddMemberInput{GroupID: testGroupID, MemberType: domain.SubjectTypeUser, MemberID: testMemberID})
			require.Error(t, err)
			if name == "changed" {
				require.Equal(t, codes.Aborted, status.Code(err))
			}
			require.False(t, w.committed)
			require.Empty(t, w.seq)
			_, err = NewRemoveMemberUseCase(repo, nil).WithMembershipWriter(f).doRemove(context.Background(), RemoveMemberInput{GroupID: testGroupID, MemberType: domain.SubjectTypeUser, MemberID: testMemberID})
			require.Error(t, err)
			if name == "changed" {
				require.Equal(t, codes.Aborted, status.Code(err))
			}
			require.False(t, w.committed)
		})
	}
	repo, w := newFakeMemberRepo()
	f := &membershipFactoryProbe{w: w}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewAddMemberUseCase(repo, nil).WithMembershipWriter(f).doAdd(ctx, AddMemberInput{GroupID: testGroupID, MemberType: domain.SubjectTypeUser, MemberID: testMemberID})
	require.Error(t, err)
	require.Empty(t, f.members)
	require.False(t, w.committed)
}

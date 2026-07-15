// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package group

// member_fga_emit_test.go — RED→GREEN unit proof for the group-membership FGA
// mirror bug (E-31 ExpandAccess, broader group-based authz):
//
//   AddMember writes ONLY the group_members row (iam DB) and never emitted the
//   FGA `group:<gid>#member` userset tuple, so a binding on a GROUP subject
//   (`<obj>#<rel>@group:<gid>#member`) resolved its userset to EMPTY in OpenFGA —
//   members got no real access and ExpandAccess found no concrete members.
//
// These white-box tests pin the co-commit contract: doAdd MUST co-commit
// EmitFGARelationWrite({user|service_account:<member>, "member", group:<gid>})
// in the SAME writer-tx, and doRemove MUST co-commit the symmetric
// EmitFGARelationDelete. The tuple's OBJECT type is `group` (the userset type
// the binding's subjectRef points at — group_model.fga `type group`), NOT
// `iam_group` (the object-scope hierarchy type used by group Create).
//
// The FGA outbox row is exercised end-to-end (real Postgres tx + real OpenFGA
// Check/ExpandAccess) by member_fga_outbox_integration_test.go; this unit test
// proves the use-case emits the RIGHT tuple shape without a DB.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ─── fakes ───────────────────────────────────────────────────────────────────

// fakeMemberRepo is a kachorepo.Repository whose Writer() records the group
// member-mutation + FGA tuple emits. Reader() is unused by doAdd/doRemove.
type fakeMemberRepo struct{ w *fakeMemberWriter }

func (r *fakeMemberRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return nil, assertNotCalled("Reader")
}
func (r *fakeMemberRepo) Writer(context.Context) (kachorepo.Writer, error) { return r.w, nil }
func (r *fakeMemberRepo) Close()                                           {}

// fakeMemberWriter embeds kachorepo.Writer (nil) so it satisfies the wide
// interface; only the methods doAdd/doRemove touch are overridden. Any other
// method call panics (nil deref) — a guard that the use-case path stays narrow.
type fakeMemberWriter struct {
	kachorepo.Writer
	gw *fakeGroupWriter

	committed    bool
	writeEmitted [][]service.RelationTuple
	delEmitted   [][]service.RelationTuple
}

func (w *fakeMemberWriter) GroupsW() group.WriterIface { return w.gw }
func (w *fakeMemberWriter) EmitFGARelationWrite(_ context.Context, tuples []service.RelationTuple) error {
	w.writeEmitted = append(w.writeEmitted, tuples)
	return nil
}
func (w *fakeMemberWriter) EmitFGARelationDelete(_ context.Context, tuples []service.RelationTuple) error {
	w.delEmitted = append(w.delEmitted, tuples)
	return nil
}
func (w *fakeMemberWriter) Commit(context.Context) error   { w.committed = true; return nil }
func (w *fakeMemberWriter) Rollback(context.Context) error { return nil }

// fakeGroupWriter records the group_members DML; satisfies group.WriterIface.
type fakeGroupWriter struct {
	added   []domain.GroupMember
	removed []struct {
		gid domain.GroupID
		mt  domain.SubjectType
		mid domain.SubjectID
	}
}

func (g *fakeGroupWriter) Insert(context.Context, domain.Group) (domain.Group, error) {
	return domain.Group{}, assertNotCalled("Insert")
}
func (g *fakeGroupWriter) Update(context.Context, domain.Group, []string) (domain.Group, error) {
	return domain.Group{}, assertNotCalled("Update")
}
func (g *fakeGroupWriter) Delete(context.Context, domain.GroupID) error {
	return assertNotCalled("Delete")
}
func (g *fakeGroupWriter) AddMember(_ context.Context, m domain.GroupMember) error {
	g.added = append(g.added, m)
	return nil
}
func (g *fakeGroupWriter) RemoveMember(_ context.Context, gid domain.GroupID, mt domain.SubjectType, mid domain.SubjectID) error {
	g.removed = append(g.removed, struct {
		gid domain.GroupID
		mt  domain.SubjectType
		mid domain.SubjectID
	}{gid, mt, mid})
	return nil
}

func assertNotCalled(name string) error { panic("unexpected call to " + name) }

func newFakeMemberRepo() (*fakeMemberRepo, *fakeMemberWriter) {
	w := &fakeMemberWriter{gw: &fakeGroupWriter{}}
	return &fakeMemberRepo{w: w}, w
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestAddMember_CoCommitsFGAMemberTuple_User(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewAddMemberUseCase(repo, nil)

	gid := domain.GroupID("grp00000000000000abcd")
	in := AddMemberInput{
		GroupID:    gid,
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID("usr00000000000000aaaa"),
	}
	_, err := uc.doAdd(context.Background(), in)
	require.NoError(t, err)

	// group_members DML happened.
	require.Len(t, w.gw.added, 1)
	// FGA member-tuple co-committed in the SAME writer-tx (committed=true).
	assert.True(t, w.committed, "writer-tx must commit (DML + emit atomic)")
	require.Len(t, w.writeEmitted, 1, "AddMember must co-commit exactly one EmitFGARelationWrite batch")
	require.Len(t, w.writeEmitted[0], 1)
	got := w.writeEmitted[0][0]
	assert.Equal(t, service.RelationTuple{
		User:     "user:usr00000000000000aaaa",
		Relation: "member",
		Object:   "group:grp00000000000000abcd",
	}, got, "member-tuple must target FGA type `group` (binding userset), NOT iam_group")
}

func TestAddMember_CoCommitsFGAMemberTuple_ServiceAccount(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewAddMemberUseCase(repo, nil)

	in := AddMemberInput{
		GroupID:    domain.GroupID("grp00000000000000abcd"),
		MemberType: domain.SubjectTypeServiceAccount,
		MemberID:   domain.SubjectID("sva00000000000000bbbb"),
	}
	_, err := uc.doAdd(context.Background(), in)
	require.NoError(t, err)

	require.Len(t, w.writeEmitted, 1)
	require.Len(t, w.writeEmitted[0], 1)
	assert.Equal(t, service.RelationTuple{
		User:     "service_account:sva00000000000000bbbb",
		Relation: "member",
		Object:   "group:grp00000000000000abcd",
	}, w.writeEmitted[0][0], "service_account member uses the service_account FGA prefix")
	assert.Empty(t, w.delEmitted, "AddMember must not emit a delete")
}

func TestRemoveMember_CoCommitsFGAMemberTupleDelete(t *testing.T) {
	repo, w := newFakeMemberRepo()
	uc := NewRemoveMemberUseCase(repo, nil)

	in := RemoveMemberInput{
		GroupID:    domain.GroupID("grp00000000000000abcd"),
		MemberType: domain.SubjectTypeUser,
		MemberID:   domain.SubjectID("usr00000000000000aaaa"),
	}
	_, err := uc.doRemove(context.Background(), in)
	require.NoError(t, err)

	require.Len(t, w.gw.removed, 1)
	assert.True(t, w.committed, "writer-tx must commit (DELETE + emit-delete atomic)")
	require.Len(t, w.delEmitted, 1, "RemoveMember must co-commit exactly one EmitFGARelationDelete batch")
	require.Len(t, w.delEmitted[0], 1)
	assert.Equal(t, service.RelationTuple{
		User:     "user:usr00000000000000aaaa",
		Relation: "member",
		Object:   "group:grp00000000000000abcd",
	}, w.delEmitted[0][0], "symmetric revoke of the exact member-tuple AddMember wrote")
	assert.Empty(t, w.writeEmitted, "RemoveMember must not emit a write")
}

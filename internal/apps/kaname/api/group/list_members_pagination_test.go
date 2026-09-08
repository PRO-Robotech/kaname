// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package group

// list_members_pagination_test.go — the membership listing honours the three
// pagination fields it publishes.
//
// The request message declares page_size (documented "<=1000") and page_token, the
// response declares next_page_token, and the service's own documentation lists the
// method as paged. None of the three had a reader in production code: the whole
// membership came back in one message, the continuation token was never emitted, so
// the published page_token could not have worked even if a caller sent one, and an
// out-of-range page_size was neither rejected nor clamped — it was not read.
//
// A field accepted and ignored is worse than one refused: the caller is told the
// call succeeded and believes the parameter applied. Sixty-nine of the seventy
// request types carrying page_size read it; this was the one that did not.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	repogroup "github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

const pageGroupID = "grp0000000000000page"

// memberPageRepo — records the page the use-case asked for and answers with a
// fixed page plus a continuation token.
type memberPageRepo struct {
	seen    repogroup.MemberPage
	members []domain.GroupMember
	next    string
}

func (f *memberPageRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &memberPageReader{parent: f}, nil
}
func (f *memberPageRepo) Writer(context.Context) (kanamerepo.Writer, error) { return nil, nil }
func (f *memberPageRepo) Close()                                            {}

type memberPageReader struct{ parent *memberPageRepo }

func (r *memberPageReader) Accounts() account.ReaderIface                { return nil }
func (r *memberPageReader) Projects() project.ReaderIface                { return nil }
func (r *memberPageReader) Users() user.ReaderIface                      { return nil }
func (r *memberPageReader) ServiceAccounts() service_account.ReaderIface { return nil }
func (r *memberPageReader) Groups() repogroup.ReaderIface                { return &memberPageRdr{parent: r.parent} }
func (r *memberPageReader) Roles() role.ReaderIface                      { return nil }
func (r *memberPageReader) AccessBindings() access_binding.ReaderIface   { return nil }
func (r *memberPageReader) Commit(context.Context) error                 { return nil }
func (r *memberPageReader) Rollback(context.Context) error               { return nil }

type memberPageRdr struct{ parent *memberPageRepo }

func (r *memberPageRdr) Get(context.Context, domain.GroupID) (domain.Group, error) {
	return domain.Group{}, nil
}
func (r *memberPageRdr) List(context.Context, repogroup.ListFilter) ([]domain.Group, string, error) {
	return nil, "", nil
}
func (r *memberPageRdr) ListMembers(_ context.Context, _ domain.GroupID, page repogroup.MemberPage) ([]domain.GroupMember, string, error) {
	r.parent.seen = page
	return r.parent.members, r.parent.next, nil
}
func (r *memberPageRdr) IsMember(context.Context, domain.GroupID, domain.SubjectType, domain.SubjectID) (bool, error) {
	return false, nil
}

// membersHandler builds the handler for the PAGING cases, so it wires a caller
// who is allowed to read this group. Who may read WHOSE roster is settled in
// list_members_authz_test.go; here the subject is the cursor.
func membersHandler(repo *memberPageRepo) *Handler {
	uc := NewListMembersUseCase(repo).WithRelationStore(
		rosterGrants("user:" + pagingCaller + "|v_list|iam_group:" + pageGroupID))
	return NewHandler(nil, nil, nil, nil, nil, nil, nil, uc)
}

// pagingCaller — the granted identity every paging case runs under.
const pagingCaller = "usr0000000000000pagr"

// asPagingCaller is the context those cases use.
func asPagingCaller() context.Context { return asRosterUser(pagingCaller) }

// The continuation token the storage produced must reach the caller. Without it the
// published page_token is unusable: a client cannot ask for the next page of a
// listing that never says there is one.
func TestListMembers_EmitsTheContinuationToken(t *testing.T) {
	repo := &memberPageRepo{
		members: []domain.GroupMember{{
			GroupID: pageGroupID, MemberType: "user",
			MemberID: "usr0000000000000one1", AddedAt: time.Now().UTC(),
		}},
		next: "opaque-continuation",
	}
	resp, err := membersHandler(repo).ListMembers(asPagingCaller(),
		&iamv1.ListGroupMembersRequest{GroupId: pageGroupID, PageSize: 25})
	require.NoError(t, err)
	assert.Equal(t, "opaque-continuation", resp.GetNextPageToken(),
		"the response must carry the continuation token it declares")
	assert.Len(t, resp.GetMembers(), 1)
	assert.EqualValues(t, 25, repo.seen.PageSize, "the requested page size must reach the storage")
}

// The token the caller sends must reach the storage. Accepting it and starting from
// the beginning would repeat the first page for ever.
func TestListMembers_PassesTheCallersTokenThrough(t *testing.T) {
	repo := &memberPageRepo{}
	_, err := membersHandler(repo).ListMembers(asPagingCaller(),
		&iamv1.ListGroupMembersRequest{GroupId: pageGroupID, PageToken: "caller-cursor"})
	require.NoError(t, err)
	assert.Equal(t, "caller-cursor", repo.seen.PageToken, "the caller's cursor must reach the storage")
}

// Out of range is REFUSED, not clamped — the platform convention for page_size, and
// the reason it is a convention: a silently clamped page size makes a caller
// believe it received everything it asked for.
func TestListMembers_RejectsOutOfRangePageSize(t *testing.T) {
	for _, size := range []int64{1001, -1} {
		repo := &memberPageRepo{}
		_, err := membersHandler(repo).ListMembers(asPagingCaller(),
			&iamv1.ListGroupMembersRequest{GroupId: pageGroupID, PageSize: size})
		require.Error(t, err, "page_size=%d must be refused", size)
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "page_size=%d", size)
		assert.Zero(t, repo.seen.PageSize, "a refused page size must never reach the storage")
	}
}

// Zero means "use the default", the same default every other listing applies.
func TestListMembers_UnsetPageSizeBecomesTheDefault(t *testing.T) {
	repo := &memberPageRepo{}
	_, err := membersHandler(repo).ListMembers(asPagingCaller(),
		&iamv1.ListGroupMembersRequest{GroupId: pageGroupID})
	require.NoError(t, err)
	assert.EqualValues(t, 50, repo.seen.PageSize, "an unset page size must become the platform default")
}

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *memberPageReader) Visibility() visibility.ReaderIface { return nil }

// MembersOfGroups — предмет этой пробы не касается состава нескольких групп;
// дублёр отвечает пусто и говорит об этом, а не притворяется источником.
func (r *memberPageRdr) MembersOfGroups(context.Context, []domain.GroupID) ([]domain.GroupMember, []domain.GroupID, error) {
	return nil, nil, nil
}

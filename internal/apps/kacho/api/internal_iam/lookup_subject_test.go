// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// lookup_subject_test.go — unit-тесты LookupSubjectUseCase.
//
// Покрытие:
//   - byExternalID: happy + NotFound + empty.
//   - byID: happy (usr-prefix) + unknown prefix + NotFound.
//   - byEmail: happy + NotFound.

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/access_binding"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/group"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/project"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/role"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/service_account"
	repouser "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/user"
)

// ── fake reader (без writer — LookupSubject use-case read-only) ──

type fakeRepo struct {
	user        *domain.User
	sa          *domain.ServiceAccount
	getByExtErr error
}

func (f *fakeRepo) Reader(context.Context) (kachorepo.Reader, error) {
	return &fakeReader{parent: f}, nil
}
func (f *fakeRepo) Writer(context.Context) (kachorepo.Writer, error) { return nil, nil }
func (f *fakeRepo) Close()                                           {}

type fakeReader struct{ parent *fakeRepo }

func (r *fakeReader) Accounts() account.ReaderIface { return nil }
func (r *fakeReader) Projects() project.ReaderIface { return nil }
func (r *fakeReader) Users() repouser.ReaderIface   { return &fakeUserRdr{parent: r.parent} }
func (r *fakeReader) ServiceAccounts() service_account.ReaderIface {
	return &fakeSARdr{parent: r.parent}
}
func (r *fakeReader) Groups() group.ReaderIface                  { return nil }
func (r *fakeReader) Roles() role.ReaderIface                    { return nil }
func (r *fakeReader) AccessBindings() access_binding.ReaderIface { return nil }
func (r *fakeReader) Commit(context.Context) error               { return nil }
func (r *fakeReader) Rollback(context.Context) error             { return nil }

type fakeUserRdr struct{ parent *fakeRepo }

func (r *fakeUserRdr) Get(_ context.Context, id domain.UserID) (domain.User, error) {
	if r.parent.user != nil && r.parent.user.ID == id {
		return *r.parent.user, nil
	}
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUserRdr) GetByExternalID(_ context.Context, ext domain.ExternalSubject) (domain.User, error) {
	if r.parent.getByExtErr != nil {
		return domain.User{}, r.parent.getByExtErr
	}
	if r.parent.user != nil && r.parent.user.ExternalID == ext {
		return *r.parent.user, nil
	}
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUserRdr) GetByEmail(_ context.Context, email domain.Email) (domain.User, error) {
	if r.parent.user != nil && r.parent.user.Email == email {
		return *r.parent.user, nil
	}
	return domain.User{}, iamerr.ErrNotFound
}
func (r *fakeUserRdr) GetByAccountEmail(_ context.Context, _ domain.AccountID, email domain.Email) (domain.User, error) {
	return r.GetByEmail(context.Background(), email)
}
func (r *fakeUserRdr) FindPendingByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindActiveByExternalID(context.Context, domain.ExternalSubject) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindByExternalIDInStatuses(context.Context, domain.ExternalSubject, []domain.InviteStatus) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) FindActiveByEmail(context.Context, domain.Email) ([]domain.User, error) {
	return nil, nil
}
func (r *fakeUserRdr) ListAccountsForUser(context.Context, domain.UserID) ([]domain.AccountID, error) {
	return nil, nil
}
func (r *fakeUserRdr) List(context.Context, repouser.ListFilter) ([]domain.User, string, error) {
	return nil, "", nil
}

type fakeSARdr struct{ parent *fakeRepo }

func (r *fakeSARdr) Get(_ context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	if r.parent.sa != nil && r.parent.sa.ID == id {
		return *r.parent.sa, nil
	}
	return domain.ServiceAccount{}, iamerr.ErrNotFound
}
func (r *fakeSARdr) List(context.Context, service_account.ListFilter) ([]domain.ServiceAccount, string, error) {
	return nil, "", nil
}

// ── tests ──

func TestLookupSubject_ByExternalID_Happy(t *testing.T) {
	repo := &fakeRepo{user: &domain.User{
		ID:          "usr-test-1",
		ExternalID:  "zit-12345",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	}}
	uc := NewLookupSubjectUseCase(repo)
	resp, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: "zit-12345"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetUser())
	assert.Equal(t, "usr-test-1", resp.GetUser().GetId())
	assert.Equal(t, "alice@example.com", resp.GetUser().GetEmail())
}

func TestLookupSubject_ByExternalID_NotFound(t *testing.T) {
	repo := &fakeRepo{user: nil}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: "zit-nonexistent"},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestLookupSubject_ByExternalID_Empty(t *testing.T) {
	repo := &fakeRepo{}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: ""},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestLookupSubject_ByID_UserHappy(t *testing.T) {
	repo := &fakeRepo{user: &domain.User{
		ID:         "usr-001",
		ExternalID: "ext-1",
		Email:      "u@example.com",
	}}
	uc := NewLookupSubjectUseCase(repo)
	resp, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "usr-001"},
	})
	require.NoError(t, err)
	assert.Equal(t, "usr-001", resp.GetUser().GetId())
}

func TestLookupSubject_ByID_ServiceAccountHappy(t *testing.T) {
	repo := &fakeRepo{sa: &domain.ServiceAccount{
		ID:        "sva-001",
		AccountID: "acc-001",
		Name:      "ci-runner",
	}}
	uc := NewLookupSubjectUseCase(repo)
	resp, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "sva-001"},
	})
	require.NoError(t, err)
	require.NotNil(t, resp.GetServiceAccount())
	assert.Equal(t, "sva-001", resp.GetServiceAccount().GetId())
	assert.Equal(t, "ci-runner", resp.GetServiceAccount().GetName())
}

func TestLookupSubject_ByID_UnknownPrefix(t *testing.T) {
	repo := &fakeRepo{}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "xyz-1234"},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestLookupSubject_ByID_NotFound(t *testing.T) {
	repo := &fakeRepo{}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "usr-doesnotexist"},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestLookupSubject_ByEmail_Happy(t *testing.T) {
	repo := &fakeRepo{user: &domain.User{
		ID:    "usr-bob",
		Email: "bob@example.com",
	}}
	uc := NewLookupSubjectUseCase(repo)
	resp, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Email{Email: "bob@example.com"},
	})
	require.NoError(t, err)
	assert.Equal(t, "usr-bob", resp.GetUser().GetId())
}

func TestLookupSubject_ByEmail_NotFound(t *testing.T) {
	repo := &fakeRepo{}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Email{Email: "x@nowhere.com"},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestLookupSubject_KeyOneofMissing(t *testing.T) {
	repo := &fakeRepo{}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestLookupSubject_RepoError_Wrapped(t *testing.T) {
	repo := &fakeRepo{getByExtErr: stderrors.New("db connection broken")}
	uc := NewLookupSubjectUseCase(repo)
	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: "zit-x"},
	})
	require.Error(t, err)
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Internal, st.Code())
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/project"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/service_account"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/visibility"
)

// ── fake reader (без writer — LookupSubject use-case read-only) ──

type fakeRepo struct {
	user        *domain.User
	sa          *domain.ServiceAccount
	getByExtErr error
}

func (f *fakeRepo) Reader(context.Context) (kanamerepo.Reader, error) {
	return &fakeReader{parent: f}, nil
}
func (f *fakeRepo) Writer(context.Context) (kanamerepo.Writer, error) { return nil, nil }
func (f *fakeRepo) Close()                                            {}

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

// FindByExternalIDInStatuses отдаёт строку личности КАК ЕСТЬ, если её состояние
// входит в запрошенный набор: use-case судит состояние сам, поэтому фейк не
// вправе решать за него, отфильтровывая недействующие строки.
func (r *fakeUserRdr) FindByExternalIDInStatuses(
	_ context.Context, ext domain.ExternalSubject, statuses []domain.InviteStatus,
) ([]domain.User, error) {
	if r.parent.getByExtErr != nil {
		return nil, r.parent.getByExtErr
	}
	if r.parent.user == nil || r.parent.user.ExternalID != ext {
		return nil, nil
	}
	for _, s := range statuses {
		if s == r.parent.user.InviteStatus {
			return []domain.User{*r.parent.user}, nil
		}
	}
	return nil, nil
}

// FindActiveByEmail — только действующие строки с этим адресом.
func (r *fakeUserRdr) FindActiveByEmail(_ context.Context, email domain.Email) ([]domain.User, error) {
	if r.parent.user == nil || r.parent.user.Email != email {
		return nil, nil
	}
	if !r.parent.user.InviteStatus.MayAuthenticate() {
		return nil, nil
	}
	return []domain.User{*r.parent.user}, nil
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
		// Состояние названо явно: резолв судит по нему, поэтому фикстура,
		// которая его умалчивает, описывает не действующую личность, а строку
		// с пустым состоянием — и проверяла бы не то, о чём заявлена.
		InviteStatus: domain.InviteStatusActive,
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
		ID:           "usr-001",
		ExternalID:   "ext-1",
		Email:        "u@example.com",
		InviteStatus: domain.InviteStatusActive,
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
		Enabled:   true,
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
		ID:           "usr-bob",
		Email:        "bob@example.com",
		InviteStatus: domain.InviteStatusActive,
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

// Visibility — дублёр структурных фактов о вызывающем не несёт: они читаются
// живой БД, и пробы, которые их проверяют, гоняют настоящий Postgres
// (services/iam/internal/apps/kaname/api/listvisibility). nil здесь означает
// «сузить нечем», и списочный use-case обязан на нём ОТКАЗАТЬ, а не листать
// ненаречённое.
func (r *fakeReader) Visibility() visibility.ReaderIface { return nil }

// MembershipExists — дублёр не отвечает на вопрос о членстве: предмет этой
// пробы другой, и подставной ответ был бы утверждением, которого никто не
// делал. Единственный прод-вызывающий — разрешение осиротевшей операции
// исключения из аккаунта (#1127).
func (*fakeUserRdr) MembershipExists(context.Context, domain.UserID, domain.AccountID) (bool, error) {
	return false, nil
}

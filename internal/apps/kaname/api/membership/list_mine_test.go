// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// list_mine_test.go — что решает СВОЙ СПИСОК членств до того, как коснётся
// хранилища (IAM-ID-2, стадия S2; сценарии IAM-ID-2-07, -09, -10, -11).
//
// Единственный вход чтения — личность вызывающего из контекста. Поэтому
// утверждения здесь двух родов: (а) страница спрашивается у хранилища РОВНО
// про принципала, и никакой другой идентификатор до запроса не доходит;
// (б) отказы без принципала, с машинной личностью и на негодной форме —
// СИНХРОННЫЕ, до любого обращения к хранилищу. Наблюдаемым второе делает
// счётчик дублёра, а не код ответа.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repomembership "github.com/PRO-Robotech/kaname/internal/repo/kaname/membership"
)

// mineReader — дублёр СВОЕГО списка: считает обращения и запоминает, ПРО КОГО
// спросили.
type mineReader struct {
	countingReader
	mine     int
	askedFor domain.UserID
	page     repomembership.MinePage
}

func (m *mineReader) ListMine(_ context.Context, userID domain.UserID, page repomembership.MinePage) ([]domain.Membership, string, error) {
	m.mine++
	m.askedFor = userID
	m.page = page
	if m.err != nil {
		return nil, "", m.err
	}
	return m.rows, m.next, nil
}

type mineSession struct{ rd *mineReader }

func (s mineSession) Memberships() repomembership.ReaderIface { return s.rd }
func (s mineSession) Close(context.Context)                   {}

type mineRepo struct {
	rd    *mineReader
	opens int
}

func (r *mineRepo) MembershipReader(context.Context) (repomembership.Session, error) {
	r.opens++
	return mineSession{rd: r.rd}, nil
}

func newMineRepo(rows ...domain.Membership) (*mineRepo, *mineReader) {
	rd := &mineReader{countingReader: countingReader{rows: rows}}
	return &mineRepo{rd: rd}, rd
}

const (
	callerUser = "usr00000000000000001"
	otherUser  = "usr00000000000000002"
)

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
}

func machineCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "sva00000000000000001"})
}

// TestListMine_IAMID2_07_PageIsAskedForTheCallerAndNobodyElse — хранилище
// спрашивается РОВНО про принципала: другого входа у чтения нет.
func TestListMine_IAMID2_07_PageIsAskedForTheCallerAndNobodyElse(t *testing.T) {
	row := sampleMembership()
	row.UserID = callerUser
	row.InvitedBy = otherUser
	repo, rd := newMineRepo(row)
	uc := NewListMyMembershipsUseCase(repo)

	rows, next, err := uc.Execute(userCtx(callerUser), repomembership.MinePage{PageSize: 50})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, domain.UserID(otherUser), rows[0].InvitedBy, "след приглашения доезжает как есть")
	require.Empty(t, next)
	require.Equal(t, 1, rd.mine, "страница читается одним обращением")
	require.Equal(t, domain.UserID(callerUser), rd.askedFor,
		"спросили ПРО ВЫЗЫВАЮЩЕГО: сужение — личность из контекста, а не поле запроса")
	require.Zero(t, rd.lists, "аккаунт-скоупное чтение не задействуется")
}

// TestListMine_IAMID2_10_NoPrincipalIsRefusedBeforeTheStore — без личности
// отказ, а не пустая страница; и отказ наступает ДО открытия чтения.
func TestListMine_IAMID2_10_NoPrincipalIsRefusedBeforeTheStore(t *testing.T) {
	repo, rd := newMineRepo(sampleMembership())
	uc := NewListMyMembershipsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), repomembership.MinePage{})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.Unauthenticated, st.Code(),
		"пустая страница читалась бы как «членств нет» и скрыла бы отказ аутентификации")
	require.Zero(t, rd.mine)
	require.Zero(t, repo.opens, "чтение даже не открывалось")

	// ПОЛОЖИТЕЛЬНЫЙ контроль: с принципалом та же страница отдаётся.
	rows, _, err := uc.Execute(userCtx(callerUser), repomembership.MinePage{})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, 1, rd.mine)
}

// TestListMine_MachinePrincipalIsRefusedNotAnsweredEmpty — членство есть
// принадлежность ЧЕЛОВЕКА; машинная учётка личностью не является, и отказ
// называет предмет, а не отдаёт пустой набор (та же полоса, что у чтения
// пределов личности — соседние чтения «про себя» сверены между собой).
func TestListMine_MachinePrincipalIsRefusedNotAnsweredEmpty(t *testing.T) {
	repo, rd := newMineRepo()
	uc := NewListMyMembershipsUseCase(repo)

	_, _, err := uc.Execute(machineCtx(), repomembership.MinePage{})
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.FailedPrecondition, st.Code())
	require.Equal(t, "memberships are readable by a user principal only", st.Message())
	require.Zero(t, rd.mine)
	require.Zero(t, repo.opens)
}

// TestListMine_IAMID2_11_PaginationIsJudgedBeforeTheStore — негодная форма
// страницы отвергается синхронно, тем же разбором, что и на пути чтения.
func TestListMine_IAMID2_11_PaginationIsJudgedBeforeTheStore(t *testing.T) {
	repo, rd := newMineRepo(sampleMembership())
	uc := NewListMyMembershipsUseCase(repo)

	for name, page := range map[string]repomembership.MinePage{
		"размер_страницы_вне_предела": {PageSize: 5000},
		"негодный_токен":              {PageToken: "не-курсор"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := uc.Execute(userCtx(callerUser), page)
			require.Error(t, err)
			st, _ := status.FromError(err)
			require.Equal(t, codes.InvalidArgument, st.Code())
			require.Zero(t, rd.mine, "формат судится ДО чтения")
		})
	}

	// ПОЛОЖИТЕЛЬНЫЙ контроль: законная страница доходит до хранилища с теми же
	// величинами.
	_, _, err := uc.Execute(userCtx(callerUser), repomembership.MinePage{PageSize: 1})
	require.NoError(t, err)
	require.Equal(t, 1, rd.mine)
	require.Equal(t, int32(1), rd.page.PageSize)
}

// TestListMine_IAMID2_09_RequestNamesNoSubject — у сообщения запроса своего
// списка НОЛЬ полей, называющих субъекта: сужение по принципалу — единственное,
// и расширить его, не тронув контракт, нельзя.
//
// Законный близнец — аккаунт-скоупный список: терм `userId` в его фильтре
// законен, потому что действует ВНУТРИ обязательного аккаунта. Здесь он
// проверяется тем, что у того сообщения поле `filter` ЕСТЬ, — иначе отрицание
// зеленело бы на распознавателе, который не видит полей вовсе.
func TestListMine_IAMID2_09_RequestNamesNoSubject(t *testing.T) {
	forbidden := map[string]bool{"user_id": true, "subject": true, "filter": true, "account_id": true}

	mine := (&iamv1.ListMyMembershipsRequest{}).ProtoReflect().Descriptor().Fields()
	require.Positive(t, mine.Len(), "у запроса есть поля пагинации — иначе перепись пуста")
	for i := 0; i < mine.Len(); i++ {
		name := string(mine.Get(i).Name())
		require.Falsef(t, forbidden[name], "запрос своего списка несёт поле %q, называющее субъекта либо область", name)
	}

	scoped := (&iamv1.ListMembershipsRequest{}).ProtoReflect().Descriptor().Fields()
	require.NotNil(t, scoped.ByName(protoreflect.Name("filter")),
		"положительный контроль: у аккаунт-скоупного списка терм фильтра есть, и он законен")
	require.NotNil(t, scoped.ByName(protoreflect.Name("account_id")))
	_ = proto.Message(nil)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// usecase_test.go — что решают ЧТЕНИЯ членства до того, как коснутся хранилища.
//
// Дублёр хранилища здесь СЧИТАЕТ обращения. Это не украшение: утверждения
// «отказ синхронный, первым стейтментом, до любого обращения к хранилищу»
// (IAM-ID-2-04) и «формат проверяется до чтения» (IAM-ID-2-05) НЕ выражаются
// через код ответа — отказ с тем же кодом мог бы прийти и после запроса.
// Наблюдаемым их делает счётчик.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	repomembership "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/membership"
)

type countingReader struct {
	gets  int
	lists int
	rows  []domain.Membership
	next  string
	err   error
}

func (c *countingReader) Get(context.Context, domain.AccountID, domain.MembershipID) (domain.Membership, error) {
	c.gets++
	if c.err != nil {
		return domain.Membership{}, c.err
	}
	if len(c.rows) == 0 {
		return domain.Membership{}, iamerr.Wrapf(iamerr.ErrNotFound, "Membership %s not found", "mbr-x")
	}
	return c.rows[0], nil
}

func (c *countingReader) List(context.Context, repomembership.ListFilter) ([]domain.Membership, string, error) {
	c.lists++
	if c.err != nil {
		return nil, "", c.err
	}
	return c.rows, c.next, nil
}

type fakeSession struct{ rd *countingReader }

func (s fakeSession) Memberships() repomembership.ReaderIface { return s.rd }
func (s fakeSession) Close(context.Context)                   {}

type fakeRepo struct {
	rd    *countingReader
	opens int
}

func (r *fakeRepo) MembershipReader(context.Context) (repomembership.Session, error) {
	r.opens++
	return fakeSession{rd: r.rd}, nil
}

func newFakeRepo(rows ...domain.Membership) (*fakeRepo, *countingReader) {
	rd := &countingReader{rows: rows}
	return &fakeRepo{rd: rd}, rd
}

// Законные значения формы. Идентификатор членства — то, что производит
// неизменяемая функция схемы: `mbr-` плюс 17 шестнадцатеричных цифр.
const (
	goodAccount    = "acc00000000000000000"
	goodMembership = "mbr-0123456789abcdef0"
)

func sampleMembership() domain.Membership {
	return domain.Membership{
		ID:        goodMembership,
		AccountID: goodAccount,
		UserID:    "usr00000000000000000",
		State:     domain.MembershipStateActive,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}
}

// TestGet_MalformedIDIsRejectedBeforeTheStore — IAM-ID-2-04, первая половина.
func TestGet_MalformedIDIsRejectedBeforeTheStore(t *testing.T) {
	repo, rd := newFakeRepo(sampleMembership())
	uc := NewGetMembershipUseCase(repo)

	_, err := uc.Execute(context.Background(), goodAccount, "не-идентификатор")
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid membership id 'не-идентификатор'", st.Message(),
		"текст — контракт-тон владельца, он часть контракта")
	require.Zero(t, rd.gets, "отказ обязан быть ПЕРВЫМ стейтментом: хранилища он не касается")
	require.Zero(t, repo.opens, "чтение даже не открывалось")

	// ПОЛОЖИТЕЛЬНЫЙ контроль: законный идентификатор доходит до хранилища.
	// Без него «негодное отвергнуто» истинно и у пути, который отвергает всё.
	got, err := uc.Execute(context.Background(), goodAccount, goodMembership)
	require.NoError(t, err)
	require.Equal(t, domain.MembershipID(goodMembership), got.ID)
	require.Equal(t, 1, rd.gets)
}

// TestGet_ForeignKnownPrefixPassesFormatAndAnswersAbsence — проверка формата
// FAMILY-AGNOSTIC по контракту: чужой ОБЪЯВЛЕННЫЙ префикс форму проходит и
// обязан отвечать полосой ОТСУТСТВИЯ, а не «негодный аргумент».
//
// Различие не педантское: терминальный отказ формы на входе, который в этом
// дереве является законным идентификатором, солгал бы вызывающему о его же
// строке.
func TestGet_ForeignKnownPrefixPassesFormatAndAnswersAbsence(t *testing.T) {
	repo := &fakeRepo{rd: &countingReader{}} // строк нет — хранилище ответит отсутствием
	uc := NewGetMembershipUseCase(repo)

	_, err := uc.Execute(context.Background(), goodAccount, "usr-0123456789abcdef0")
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.NotFound, st.Code(),
		"чужой ОБЪЯВЛЕННЫЙ префикс проходит форму: валидатор family-agnostic по контракту")
	require.Equal(t, 1, repo.rd.gets, "вход дошёл до хранилища — значит формой он не отвергнут")
}

// TestGet_MalformedAccountIDIsRejectedBeforeTheStore — тот же порядок для
// аккаунта. На пути через край сюда такой вход не доходит (край отвечает
// раньше), поэтому проверка здесь — заслон прямого вызова, и она названа им.
func TestGet_MalformedAccountIDIsRejectedBeforeTheStore(t *testing.T) {
	repo, rd := newFakeRepo(sampleMembership())
	uc := NewGetMembershipUseCase(repo)

	_, err := uc.Execute(context.Background(), "не-аккаунт", goodMembership)
	require.Error(t, err)
	st, _ := status.FromError(err)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Equal(t, "invalid account id 'не-аккаунт'", st.Message())
	require.Zero(t, rd.gets)
}

// TestList_PaginationFormatIsCheckedBeforeTheStore — IAM-ID-2-05.
func TestList_PaginationFormatIsCheckedBeforeTheStore(t *testing.T) {
	repo, rd := newFakeRepo(sampleMembership())
	uc := NewListMembershipsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, PageSize: 5000,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err), "page_size вне [0..1000] ОТВЕРГАЕТСЯ, а не подрезается")
	require.Zero(t, rd.lists, "формат проверяется ДО чтения страницы")

	_, _, err = uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, PageToken: "не-курсор",
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Zero(t, rd.lists)

	// ПОЛОЖИТЕЛЬНЫЙ контроль: законная пагинация проходит ПО ТОМУ ЖЕ ПУТИ.
	rows, _, err := uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, PageSize: 10,
	})
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, 1, rd.lists)
}

// TestList_UnsupportedFilterOperatorIsRefusedByName — оператор вне объявленного
// отвергается ЯВНО и называет предмет, а не сводится молча к равенству.
func TestList_UnsupportedFilterOperatorIsRefusedByName(t *testing.T) {
	repo, rd := newFakeRepo(sampleMembership())
	uc := NewListMembershipsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, Filter: `userId CONTAINS "usr"`,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "userId",
		"отказ обязан называть поле, к которому относится")
	require.Zero(t, rd.lists, "до хранилища негодный оператор не доходит")

	// ПОЛОЖИТЕЛЬНЫЙ контроль: объявленный оператор проходит.
	_, _, err = uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, Filter: `userId="usr00000000000000000"`,
	})
	require.NoError(t, err)
	require.Equal(t, 1, rd.lists)
}

// TestList_MalformedAccountIDIsRejectedBeforeTheStore — заслон прямого вызова.
func TestList_MalformedAccountIDIsRejectedBeforeTheStore(t *testing.T) {
	repo, rd := newFakeRepo(sampleMembership())
	uc := NewListMembershipsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), repomembership.ListFilter{AccountID: "не-аккаунт"})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Zero(t, rd.lists)
}

// TestList_StoreErrorIsMappedNotLeaked — сентинел хранилища превращается в код,
// а сырой текст наружу не течёт.
func TestList_StoreErrorIsMappedNotLeaked(t *testing.T) {
	repo, rd := newFakeRepo()
	rd.err = iamerr.Wrapf(iamerr.ErrInvalidArg, "Bad expression at column 1. Unknown field: \"email\"")
	uc := NewListMembershipsUseCase(repo)

	_, _, err := uc.Execute(context.Background(), repomembership.ListFilter{
		AccountID: goodAccount, Filter: `email="p@example.test"`,
	})
	require.Error(t, err)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Contains(t, status.Convert(err).Message(), "email")
}

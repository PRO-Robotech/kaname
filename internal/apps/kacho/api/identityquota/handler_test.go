// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package identityquota

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	quotav1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/pkg/quota/quotaread"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// Чтение квот, носителем которых является ЛИЧНОСТЬ.
//
// Утверждается НАБЛЮДАЕМОЕ: что вызывающий видит про себя, чего он не может
// спросить в принципе и что получает, когда личности у него нет.

// readerStub — подставное чтение ДВУХ личностей.
//
// Двух намеренно: дублёр, знающий одну, отвечал бы верно на любой вопрос и сделал
// бы невидимым дефект, ради которого стоит отрицание, — ответ про чужого.
type readerStub struct {
	identityOfUser map[string]string
	statesOf       map[string][]quotaread.State

	askedUser     string
	askedIdentity string
	identityErr   error
	statesErr     error
}

func (s *readerStub) IdentityOfUser(_ context.Context, userID domain.UserID) (string, error) {
	s.askedUser = string(userID)
	if s.identityErr != nil {
		return "", s.identityErr
	}
	return s.identityOfUser[string(userID)], nil
}

func (s *readerStub) States(_ context.Context, identity string) ([]quotaread.State, error) {
	s.askedIdentity = identity
	if s.statesErr != nil {
		return nil, s.statesErr
	}
	return s.statesOf[identity], nil
}

func newFixture() (*Handler, *readerStub) {
	r := &readerStub{
		identityOfUser: map[string]string{
			"usr-mine":   "ext-mine",
			"usr-theirs": "ext-theirs",
		},
		statesOf: map[string][]quotaread.State{
			"ext-mine": {{
				Kind: "iam.account", Limit: 5, Used: 3,
				SourceScope: "DEFAULT",
				CarrierType: "identity", CarrierID: "ext-mine",
			}},
			"ext-theirs": {{
				Kind: "iam.account", Limit: 999, Used: 900,
				SourceScope: "DEFAULT",
				CarrierType: "identity", CarrierID: "ext-theirs",
			}},
		},
	}
	return NewHandler(r), r
}

// callerCtx — контекст с проверенным принципалом-человеком.
func callerCtx(userID string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: userID})
}

// Свой предел и своё потребление видны.
func TestList_ShowsTheCallersOwnCeilingAndUsage(t *testing.T) {
	h, r := newFixture()

	resp, err := h.List(callerCtx("usr-mine"), &quotav1.ListIdentityQuotasRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetQuotas(), 1,
		"личность читает ПОЛНЫЙ набор своих видов: пустой ответ был бы прочитан как «предела нет»")

	got := resp.GetQuotas()[0]
	require.Equal(t, "iam.account", got.GetKind())
	require.EqualValues(t, 5, got.GetLimit())
	require.EqualValues(t, 3, got.GetUsed(),
		"потребление — половина ответа: без него предел не говорит человеку, сколько у него осталось")
	require.Equal(t, iamv1.Limit_DEFAULT, got.GetSourceScope())
	require.Equal(t, "identity", got.GetCarrierType())
	require.Equal(t, "ext-mine", got.GetCarrierId())

	require.Equal(t, "usr-mine", r.askedUser)
	require.Equal(t, "ext-mine", r.askedIdentity,
		"спрошена не та личность: счёт ведётся по внешнему идентификатору входа, "+
			"а не по строке пользователя")
}

// Чужие числа спросить НЕЛЬЗЯ — и это свойство контракта, а не проверки.
//
// Отрицание к пробе выше: дублёр держит обе личности, поэтому «вернулось чужое»
// здесь было бы наблюдаемо. Утверждается, что личность берётся из принципала и
// только из него.
func TestList_AnswersAboutTheCallerAndNobodyElse(t *testing.T) {
	h, r := newFixture()

	resp, err := h.List(callerCtx("usr-mine"), &quotav1.ListIdentityQuotasRequest{})
	require.NoError(t, err)

	for _, q := range resp.GetQuotas() {
		require.Equal(t, "ext-mine", q.GetCarrierId(),
			"в ответе оказалась строка чужой личности")
		require.NotEqualValues(t, 900, q.GetUsed(), "видно потребление чужого человека")
	}
	require.Equal(t, "ext-theirs", r.statesOf["ext-theirs"][0].CarrierID,
		"положительный контроль дублёра: чужая личность у него ЕСТЬ, "+
			"поэтому «не видно чужого» означает работу отбора, а не пустоту фикстуры")
}

// Анонимный вызывающий личности не имеет — отказ, а не пустой набор.
func TestList_RefusesAnAnonymousCaller(t *testing.T) {
	h, r := newFixture()

	_, err := h.List(context.Background(), &quotav1.ListIdentityQuotasRequest{})
	require.Error(t, err)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Empty(t, r.askedUser, "анонимный запрос не должен доходить до чтения")
}

// Машинная учётка — отказ ПО СУЩЕСТВУ, а не пустой набор.
//
// Аккаунтом владеет человек, и счёт ведётся по тому, кто способен войти. Пустой
// ответ здесь читался бы служебной учёткой как «пределов нет».
func TestList_RefusesAMachinePrincipalByName(t *testing.T) {
	h, r := newFixture()
	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva-1"})

	_, err := h.List(ctx, &quotav1.ListIdentityQuotasRequest{})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Empty(t, r.askedIdentity)
}

// Отказ хранилища не переодевается в пустой ответ.
func TestList_PropagatesAStorageRefusal(t *testing.T) {
	h, r := newFixture()
	r.identityErr = iamerr.Wrapf(iamerr.ErrNotFound, "User usr-mine not found")

	_, err := h.List(callerCtx("usr-mine"), &quotav1.ListIdentityQuotasRequest{})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}

// Непровязанное чтение отвечает НАЗВАННЫМ отказом, а не пустым набором.
func TestList_WithNoReaderRefusesInsteadOfClaimingNoQuotas(t *testing.T) {
	h := NewHandler(nil)

	_, err := h.List(callerCtx("usr-mine"), &quotav1.ListIdentityQuotasRequest{})
	require.Error(t, err)
	require.Equal(t, codes.Internal, status.Code(err))
}

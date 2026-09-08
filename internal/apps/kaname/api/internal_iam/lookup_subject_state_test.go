// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// lookup_subject_state_test.go — резолв принципала отвечает ВЕРДИКТОМ о
// состоянии, а не молчанием о нём.
//
// Прежде запрос по внешнему идентификатору отфильтровывал недействующие строки,
// и заблокированная личность приходила к краю как «такой нет». Ответ «нет» на
// этом пути означает «заводи заново»: край идёт в провизионирование, то есть
// именно туда, куда заблокированному нельзя. Соседние ветки того же RPC при
// этом состояние вовсе не смотрели и возвращали недействующую строку как
// полноценного принципала.
//
// Здесь фиксируется: «строки нет» и «строка есть, но аутентификация ей
// запрещена» — разные ответы, одинаково устроенные во всех трёх ветках.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func blockedUser() *domain.User {
	return &domain.User{
		ID:           "usr-blocked-1",
		ExternalID:   "zit-blocked",
		Email:        "blocked@example.com",
		DisplayName:  "Blocked",
		InviteStatus: domain.InviteStatusBlocked,
	}
}

// TestLookupSubject_ByExternalID_BlockedIsAVerdictNotAbsence — «заблокирован»
// не может приходить как «не найден»: край читает отсутствие как разрешение
// завести личность заново.
func TestLookupSubject_ByExternalID_BlockedIsAVerdictNotAbsence(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{user: blockedUser()})

	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: "zit-blocked"},
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err),
		"состояние личности не позволяет резолвить её как принципала — это не отсутствие")
	require.Equal(t, "identity zit-blocked is blocked", status.Convert(err).Message())
}

// TestLookupSubject_ByExternalID_AbsentStaysNotFound — контрольный случай:
// настоящее отсутствие обязано остаться отсутствием, иначе край перестанет
// заводить новые личности вовсе.
func TestLookupSubject_ByExternalID_AbsentStaysNotFound(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{})

	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: "zit-nobody"},
	})
	require.Error(t, err)
	require.Equal(t, codes.NotFound, status.Code(err))
}

// TestLookupSubject_ByID_BlockedUser — ветка по идентификатору состояние не
// смотрела вовсе и возвращала заблокированную строку как принципала.
func TestLookupSubject_ByID_BlockedUser(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{user: blockedUser()})

	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "usr-blocked-1"},
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "User usr-blocked-1 is blocked", status.Convert(err).Message())
}

// TestLookupSubject_ByID_DisabledServiceAccount — машинная половина того же.
func TestLookupSubject_ByID_DisabledServiceAccount(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{sa: &domain.ServiceAccount{
		ID:        "sva-off-1",
		AccountID: "acc-1",
		Name:      "off",
		Enabled:   false,
	}})

	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "sva-off-1"},
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "ServiceAccount sva-off-1 is disabled", status.Convert(err).Message())
}

// TestLookupSubject_ByID_EnabledServiceAccount — контрольный случай той же
// формы: действующая машинная учётка резолвится.
func TestLookupSubject_ByID_EnabledServiceAccount(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{sa: &domain.ServiceAccount{
		ID:        "sva-on-1",
		AccountID: "acc-1",
		Name:      "on",
		Enabled:   true,
	}})

	resp, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Id{Id: "sva-on-1"},
	})
	require.NoError(t, err)
	require.Equal(t, "sva-on-1", resp.GetServiceAccount().GetId())
}

// TestLookupSubject_ByEmail_BlockedUser — третья ветка того же RPC; она тоже
// отдавала недействующую строку как принципала.
func TestLookupSubject_ByEmail_BlockedUser(t *testing.T) {
	uc := NewLookupSubjectUseCase(&fakeRepo{user: blockedUser()})

	_, err := uc.Execute(context.Background(), &iamv1.LookupSubjectRequest{
		Key: &iamv1.LookupSubjectRequest_Email{Email: "blocked@example.com"},
	})
	require.Error(t, err)
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "identity blocked@example.com is blocked", status.Convert(err).Message())
}

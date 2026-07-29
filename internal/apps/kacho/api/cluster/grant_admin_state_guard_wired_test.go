// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package cluster_test

// grant_admin_state_guard_wired_test.go — проверка состояния субъекта не может
// быть «необязательной».
//
// Соседний гейт того же RPC (ReBAC system_admin) на неподключённом порте
// отказывает: невыданная проверка — это отказ, а не разрешение. Проверка
// состояния была устроена наоборот — «не подключена ⇒ пропускаем», — то есть
// композиция, забывшая её провязать, поднимала сервис, который выдаёт права
// уровня кластера кому угодно, и заметить это было нечем.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/cluster"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// fakeSubjectState — состояние субъекта, каким его вернул бы репозиторий.
type fakeSubjectState struct {
	userStatus domain.InviteStatus
	saEnabled  bool
	userErr    error
	saErr      error
}

func (f *fakeSubjectState) UserInviteStatus(context.Context, string) (domain.InviteStatus, error) {
	return f.userStatus, f.userErr
}

func (f *fakeSubjectState) ServiceAccountEnabled(context.Context, string) (bool, error) {
	return f.saEnabled, f.saErr
}

// TestGrantAdmin_DeniesWhenSubjectStateReaderUnwired — неподключённая проверка
// состояния отказывает, а не пропускает.
func TestGrantAdmin_DeniesWhenSubjectStateReaderUnwired(t *testing.T) {
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).
		WithAdminChecker(&fakeAdminChecker{allow: true})

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Error(t, err, "без проверки состояния право выдавать нельзя")
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "subject state is not verifiable", status.Convert(err).Message(),
		"отказ обязан назвать своё основание оператору, поднимающему стенд")
}

// TestGrantAdmin_DeniesWhenSubjectStateUnreadable — недоступность чтения тоже
// не «да»: отказ хранилища не превращается в разрешение.
func TestGrantAdmin_DeniesWhenSubjectStateUnreadable(t *testing.T) {
	uc := clusterapp.NewGrantAdminUseCase(nil, nil, nil, nil, nil).
		WithAdminChecker(&fakeAdminChecker{allow: true}).
		WithSubjectStateReader(&fakeSubjectState{userErr: context.DeadlineExceeded})

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.Error(t, err)
	require.NotEqual(t, codes.OK, status.Code(err))
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal_user_service_surface_test.go — поверхность InternalUserService на
// внутреннем слушателе (kaname#564, kaname#929).
//
// На этой службе служились два глагола, у которых не осталось вызывающего:
//
//   - приём исхода восстановления от снятого внешнего поставщика (kaname#363,
//     снят kaname#564) — мутация без проверки модели прав;
//   - заведение личности по удостоверению внешнего поставщика (приёмка
//     `active-identity-has-a-way-in.md`, AWI-09, снят kaname#929) — живой
//     производитель личности `ACTIVE` без способа входа; его обратный вызов из
//     края снят платформой, людей заводят регистрация и приглашение.
//
// Проба судит НАБЛЮДАЕМОЕ на регистрации внутреннего слушателя: вызов снятого
// глагола получает Unimplemented, то есть до обработчика не доходит вовсе.
// Законный близнец той же формы — оставшийся глагол той же службы через тот же
// слушатель тем же соединением: он доходит до обработчика и отказывает его
// собственной проверкой входа (InvalidArgument на пустом идентификаторе), а не
// Unimplemented. Различие между кейсами ровно одно — имя метода.
//
// Сообщения — пустые общего вида: проба не может опираться на порождённые типы
// снятого глагола, иначе она перестала бы собираться ровно тогда, когда цель
// достигнута.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"

	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
)

const (
	retiredRecoveryCallback = "/kaname.cloud.iam.v1.InternalUserService/OnRecoveryCompleted"
	retiredIdentityUpsert   = "/kaname.cloud.iam.v1.InternalUserService/UpsertFromIdentity"
	lawfulInternalUserVerb  = "/kaname.cloud.iam.v1.InternalUserService/Get"
)

func internalUserSurface(t *testing.T) *grpc.ClientConn {
	t.Helper()
	// Хранилищ нет: законный вызов отказывает ДО обращения к ним, а проба судит
	// только то, доходит ли вызов до обработчика.
	h := userapp.NewInternalHandler(userapp.NewGetUserUseCase(nil))
	svcs := &services{internalUserHandler: h}
	return serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, config.Config{}, nil)
	})
}

func invokeInternalUser(t *testing.T, conn *grpc.ClientConn, method string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return conn.Invoke(ctx, method, &emptypb.Empty{}, &emptypb.Empty{})
}

func TestRetiredRecoveryCallbackIsNotServedOnTheInternalListener(t *testing.T) {
	err := invokeInternalUser(t, internalUserSurface(t), retiredRecoveryCallback)
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"глагол приёма исхода восстановления от снятого поставщика обязан не служиться: "+
			"у него нет ни вызывающего, ни проверки модели прав; получено %v", err)
}

// TestAWI09_IdentityUpsertIsNotServedOnTheInternalListener — AWI-09: глагол
// заведения личности по внешнему удостоверению службе не объявлен, и близнец тем
// же соединением получает ответ своего глагола — служба на месте, снят ровно один
// метод.
func TestAWI09_IdentityUpsertIsNotServedOnTheInternalListener(t *testing.T) {
	conn := internalUserSurface(t)

	err := invokeInternalUser(t, conn, retiredIdentityUpsert)
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"AWI-09: глагол заведения личности по внешнему удостоверению обязан быть службе "+
			"не объявлен — у него нет вызывающего, а сам он производит личность ACTIVE без "+
			"способа входа; получено %v", err)

	err = invokeInternalUser(t, conn, lawfulInternalUserVerb)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"AWI-09, близнец: оставшийся глагол той же службы тем же соединением обязан "+
			"доходить до обработчика и отказывать его проверкой входа; получено %v", err)
}

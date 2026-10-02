// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// internal_user_service_surface_test.go — поверхность InternalUserService на
// внутреннем слушателе (kaname#564).
//
// Здесь служился глагол приёма исхода восстановления от снятого внешнего
// поставщика (kaname#363). Вызывающего у него не осталось ни в одном дереве, а
// на пути вызова стояли только сертификат и рука вызывающего края: проверки
// модели прав у мутации не было, запись каталога была освобождена, и обоснование
// освобождения ссылалось на проверку общего секрета, которой в коде нет. Такой
// глагол — мутация без AuthZ, поэтому он снят вместе с поставщиком.
//
// Проба судит НАБЛЮДАЕМОЕ на регистрации внутреннего слушателя: вызов снятого
// глагола получает Unimplemented, то есть до обработчика не доходит вовсе.
// Законный близнец той же формы — соседний глагол той же службы через тот же
// слушатель: он доходит до обработчика и отказывает его собственной проверкой
// входа (InvalidArgument на пустом субъекте), а не Unimplemented. Различие между
// кейсами ровно одно — имя метода.
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
	lawfulInternalUserVerb  = "/kaname.cloud.iam.v1.InternalUserService/UpsertFromIdentity"
)

func internalUserSurface(t *testing.T) *grpc.ClientConn {
	t.Helper()
	// Хранилищ нет: оба вызова отказывают ДО обращения к ним, а проба судит
	// только то, доходит ли вызов до обработчика.
	h := userapp.NewInternalHandler(userapp.NewUpsertFromIdentityUseCase(nil, nil), nil)
	svcs := &services{internalUserHandler: h}
	return serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, config.Config{}, nil)
	})
}

func TestRetiredRecoveryCallbackIsNotServedOnTheInternalListener(t *testing.T) {
	conn := internalUserSurface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := conn.Invoke(ctx, retiredRecoveryCallback, &emptypb.Empty{}, &emptypb.Empty{})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"глагол приёма исхода восстановления от снятого поставщика обязан не служиться: "+
			"у него нет ни вызывающего, ни проверки модели прав; получено %v", err)
}

func TestLawfulInternalUserVerbIsStillServedOnTheInternalListener(t *testing.T) {
	conn := internalUserSurface(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err := conn.Invoke(ctx, lawfulInternalUserVerb, &emptypb.Empty{}, &emptypb.Empty{})
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"соседний глагол той же службы обязан доходить до обработчика и отказывать "+
			"его проверкой входа; получено %v", err)
}

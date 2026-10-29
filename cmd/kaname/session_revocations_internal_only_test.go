// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// session_revocations_internal_only_test.go — закрепляет контракт регистрации
// gRPC для InternalSessionRevocationsService (запрет #6: только внутренний).
//
// До этой починки обработчик выхода api-gateway звал Revoke, но kaname службу
// не регистрировал вовсе → codes.Unimplemented во время работы → отзыв токена
// был НЕДЕЙСТВУЮЩИМ (стражу IsRevoked крючка обновления никто ничего не писал).
// Проба держит обе половины:
//
//	на ПУБЛИЧНОМ (внешнем) сервере служба НЕ зарегистрирована → Unimplemented
//	   (на внешней поверхности она не должна появиться никогда, запрет #6);
//	на ВНУТРЕННЕМ (:9091) сервере служба зарегистрирована → маршрут есть
//	   (любой код, кроме Unimplemented, доказывает достижимость).
//
// Чистая проба регистрации и транспорта (bufconn, без базы).
package main

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	sessionrevapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
)

func TestSessionRevocations_InternalOnly_NotOnExternalListener(t *testing.T) {
	// Обработчика без провязанных писателя и читателя достаточно: маршрут либо
	// есть (доходит до обработчика → Unavailable с отказом по умолчанию), либо
	// отвечает Unimplemented (не зарегистрирован). nil вместо use-case и
	// читателя заставляет оба RPC отказать, не трогая базу.
	handler := sessionrevapp.NewHandler(nil, nil)
	svcs := &services{sessionRevocationsHandler: handler}

	// ПУБЛИЧНЫЙ сервер: НЕ зарегистрирована → Unimplemented.
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewInternalSessionRevocationsServiceClient(pubConn)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := pubClient.IsRevoked(ctx, &iamv1.IsRevokedRequest{TokenJti: "jti-1"})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"IsRevoked must NOT exist on the external listener (ban #6)")

	_, err = pubClient.Revoke(ctx, &iamv1.RevokeRequest{UserId: "usr0000000000000000x", TokenJti: "jti-1", Reason: "x"})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"Revoke must NOT exist on the external listener (ban #6)")

	// ВНУТРЕННИЙ сервер: зарегистрирована → достижима (НЕ Unimplemented).
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, config.Config{}, nil)
	})
	intClient := iamv1.NewInternalSessionRevocationsServiceClient(intConn)

	_, err = intClient.IsRevoked(ctx, &iamv1.IsRevokedRequest{TokenJti: "jti-1"})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"IsRevoked must be reachable on the internal listener")

	_, err = intClient.Revoke(ctx, &iamv1.RevokeRequest{UserId: "usr0000000000000000x", TokenJti: "jti-1", Reason: "x"})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"Revoke must be reachable on the internal listener")
}

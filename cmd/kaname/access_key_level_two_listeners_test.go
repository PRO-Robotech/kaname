// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// access_key_level_two_listeners_test.go — пол «2» у трёх глаголов ключа
// доступа на КАЖДОМ слушателе, где служба их обслуживает (задача kaname#747;
// приёмка `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`,
// Р3).
//
// # Что утверждается
//
//  1. Публичный слушатель, вызов краем: настоящий TLS-слушатель, клиентский
//     лист с SAN края, личность и уровень — метаданными доверенного
//     отправителя. Цепочка собрана ТЕМИ ЖЕ конструкторами, что в `serve.go`:
//     звено причины отказа, сборщик личности публичного слушателя
//     (`publicIdentityUnary`, круг отправителей — край), политика вызывающего
//     над встроенным каталогом прав. Уровень «1» — указание повысить уровень
//     до «2» (`UNAUTHENTICATED`, текст и вызов в хвосте ответа), обработчик не
//     достигнут; уровень «2» — обработчик достигнут. Пол здесь держит служба
//     сама: каталог края этой пробе не нужен вовсе.
//  2. Внутренний слушатель глаголов ключа НЕ обслуживает: регистрация служб
//     внутреннего слушателя отвечает `Unimplemented`, публичного — нет. Пути
//     входа, на котором пол не судился бы, не существует.
//
// Против цепочки `serve.go` не собраны четыре звена, и ни одно не решает судьбу
// этого вызова: измеритель задержки (только считает), `UnaryPanicRecovery`
// (действует лишь на панике), рубеж подтверждения адреса (ему нужна база; пол
// стоит раньше него по смыслу, а не по месту) и анти-аноним с дверью (личность
// названа, а дверь спрашивается только о прошедшем политику).
//
// # Способность падать
//
// До правки ветвь края в политике вызывающего пропускала любой глагол: случай
// «уровень «1»» доходил до обработчика по каждому из трёх глаголов.

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

// accessKeyReached — обработчик-дублёр: отмечает, что вызов прошёл цепочку.
type accessKeyReached struct {
	iamv1.UnimplementedAccessKeyServiceServer
	reached atomic.Bool
}

func (s *accessKeyReached) BeginRegistration(context.Context, *iamv1.BeginAccessKeyRegistrationRequest) (*iamv1.AccessKeyRegistrationChallenge, error) {
	s.reached.Store(true)
	return &iamv1.AccessKeyRegistrationChallenge{}, nil
}

func (s *accessKeyReached) FinishRegistration(context.Context, *iamv1.FinishAccessKeyRegistrationRequest) (*operationpb.Operation, error) {
	s.reached.Store(true)
	return &operationpb.Operation{Id: "iop-kn747-probe", Done: true}, nil
}

func (s *accessKeyReached) Revoke(context.Context, *iamv1.RevokeAccessKeyRequest) (*operationpb.Operation, error) {
	s.reached.Store(true)
	return &operationpb.Operation{Id: "iop-kn747-probe", Done: true}, nil
}

// servePublicAccessKeys — публичный слушатель по mTLS с цепочкой боевого
// режима; отдаёт соединение клиента с сертификатом края.
func servePublicAccessKeys(t *testing.T, reg *seed.PermissionRegistry, srv iamv1.AccessKeyServiceServer) *grpc.ClientConn {
	t.Helper()
	serverTLS, clientTLS := secondLockTLS(t, acrTestGatewaySAN)
	chain := append([]grpc.UnaryServerInterceptor{authzguard.DenyDetailUnary(reg)},
		publicIdentityUnary(fwdCfg(acrTestGatewaySAN), nil)...)
	chain = append(chain, authzguard.NewPublicCallerPolicy(
		true, authzguard.PublicPeerCallableRPCs(), reg, presentedcred.Presented).WithModuleRoster(testModuleRoster()).Unary())
	gsrv := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.ChainUnaryInterceptor(chain...))
	iamv1.RegisterAccessKeyServiceServer(gsrv, srv)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestKN747_PublicListenerHoldsLevelTwoOnKeyVerbsCalledByTheEdge(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)
	stub := &accessKeyReached{}
	client := iamv1.NewAccessKeyServiceClient(servePublicAccessKeys(t, reg, stub))

	verbs := []struct {
		fqn  string
		call func(ctx context.Context, opts ...grpc.CallOption) error
	}{
		{"kaname.cloud.iam.v1.AccessKeyService/BeginRegistration", func(ctx context.Context, opts ...grpc.CallOption) error {
			_, err := client.BeginRegistration(ctx, &iamv1.BeginAccessKeyRegistrationRequest{UserId: "usr-kn747"}, opts...)
			return err
		}},
		{"kaname.cloud.iam.v1.AccessKeyService/FinishRegistration", func(ctx context.Context, opts ...grpc.CallOption) error {
			_, err := client.FinishRegistration(ctx, &iamv1.FinishAccessKeyRegistrationRequest{UserId: "usr-kn747"}, opts...)
			return err
		}},
		{"kaname.cloud.iam.v1.AccessKeyService/Revoke", func(ctx context.Context, opts ...grpc.CallOption) error {
			_, err := client.Revoke(ctx, &iamv1.RevokeAccessKeyRequest{UserId: "usr-kn747"}, opts...)
			return err
		}},
	}
	for _, v := range verbs {
		t.Run(v.fqn, func(t *testing.T) {
			// Фикстура раньше предмета: пол каталога службы — «2».
			require.Equal(t, "2", reg.RequiredACRMin(v.fqn), "НЕ ВЫПОЛНИЛОСЬ: пол каталога не «2»")
			call := func(acr string) (error, metadata.MD) {
				md := metadata.Pairs(
					grpcsrv.MDKeyTokenACR, acr,
					grpcsrv.MDKeyPrincipalType, "user",
					grpcsrv.MDKeyPrincipalID, "usr-kn747",
				)
				ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 5*time.Second)
				defer cancel()
				var trailer metadata.MD
				return v.call(ctx, grpc.Trailer(&trailer)), trailer
			}

			stub.reached.Store(false)
			err, trailer := call("1")
			st := status.Convert(err)
			require.Equal(t, codes.Unauthenticated, st.Code(), "служба пропустила уровень «1» на полу «2»: %v", err)
			require.Equal(t, iamerr.TextStepUpRequired, st.Message())
			require.Equal(t, []string{iamerr.StepUpChallenge("2", "1")}, trailer.Get(iamerr.StepUpChallengeTrailer),
				"хвост ответа несёт вызов повышения до «2»")
			require.False(t, stub.reached.Load(), "отказ по уровню — до обработчика, без следствий")

			stub.reached.Store(false)
			err, _ = call("2")
			require.NoError(t, err, "уровень «2» на полу «2» отвергнут")
			require.True(t, stub.reached.Load(), "пол пройден — вызов дошёл до обработчика")
		})
	}
}

func TestKN747_InternalListenerDoesNotServeKeyVerbs(t *testing.T) {
	svcs := &services{accessKeyHandler: &access_keys.Handler{}}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, config.Config{}, nil)
	})
	_, err := iamv1.NewAccessKeyServiceClient(intConn).BeginRegistration(ctx, &iamv1.BeginAccessKeyRegistrationRequest{UserId: "usr-kn747"})
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"внутренний слушатель обслуживает глаголы ключа — путь входа, о котором пол не знает")

	// Близнец: на публичном слушателе служба зарегистрирована (вызов без
	// личности отвергает обработчик, а не регистрация).
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	_, err = iamv1.NewAccessKeyServiceClient(pubConn).BeginRegistration(ctx, &iamv1.BeginAccessKeyRegistrationRequest{UserId: "usr-kn747"})
	require.NotEqual(t, codes.Unimplemented, status.Code(err), "публичный слушатель не обслуживает глаголы ключа: %v", err)
	require.True(t, strings.TrimSpace(status.Convert(err).Message()) != "", "отказ обработчика назван")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_grant_admin_integration_test.go — интеграционная проба.
//
// Прогоняет ЦЕПОЧКУ перехватчиков внутрикластерного слушателя насквозь через
// bufconn для привилегированного RPC за краем InternalClusterService/GrantAdmin
// (в каталоге required_acr_min=2) и доказывает порядок пола acr и политики
// вызывающего на настоящем gRPC-сервере:
//
//   - проверенный SAN api-gateway, передающий acr=2 → проходит ОБА стража →
//     доходит до обработчика;
//   - тот же SAN края, передающий acr=1 → ОТКАЗ от пола acr РАНЬШЕ обработчика
//     (без побочного эффекта);
//   - проверенный SAN НЕ края (kacho-vpc) на этом RPC за краем → ОТКАЗ от
//     политики вызывающего ПЕРВЫМ (пол его не видит вовсе, так что изъятием
//     служебной учётки модуля от acr не злоупотребить).
//
// Цепочка повторяет внутренний слушатель serve.go (боевой режим). Проверенного
// mTLS собеседника и переданный acr изображает крошечный передний перехватчик,
// кладущий в ctx ровно то, что положили бы corelib UnaryCertIdentityExtract +
// UnaryTrustedPrincipalExtract на проверенном ребре край→iam, — так проба
// остаётся о логике цепочки (живого TLS-рукопожатия нет; половину о
// рукопожатии покрывает bufconn-проба corelib).
package main

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

const (
	acrTestGatewaySAN = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"
	acrTestVPCSAN     = "spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc"
	grantAdminFQN     = "/kaname.cloud.iam.v1.InternalClusterService/GrantAdmin"
)

// reachedClusterServer — заглушка InternalClusterServiceServer, записывающая,
// дошёл ли вызов до обработчика GrantAdmin (то есть пропустила ли его цепочка).
type reachedClusterServer struct {
	iamv1.UnimplementedInternalClusterServiceServer
	grantReached bool
}

func (s *reachedClusterServer) GrantAdmin(context.Context, *iamv1.GrantClusterAdminRequest) (*operationpb.Operation, error) {
	s.grantReached = true
	return &operationpb.Operation{Id: "iop0000000000acrtest", Done: true}, nil
}

// seedVerifiedPeer изображает извлечение проверенного mTLS из corelib: кладёт в
// ctx проверенный SAN модуля и доверенный по FD-4 переданный acr ровно так, как
// их оставляют UnaryCertIdentityExtract + UnaryTrustedPrincipalExtract на
// проверенном ребре край→iam.
func seedVerifiedPeer(san, acr string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx = grpcsrv.WithCertIdentityIn(ctx, grpcsrv.NewTrustDomain("kacho.cloud"), san, true)
		ctx = grpcsrv.WithTrustedACR(ctx, acr, true)
		return handler(ctx, req)
	}
}

// serveACRChain поднимает gRPC-сервер на bufconn, чья цепочка — внутренняя
// цепочка боевого режима (политика вызывающего → пол acr) с seedVerifiedPeer
// впереди.
func serveACRChain(t *testing.T, srv iamv1.InternalClusterServiceServer, san, acr string) *grpc.ClientConn {
	t.Helper()
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)

	callerPolicy := authzguard.NewCallerPolicy(true, authzguard.GatewayFrontedInternalRPCs()).WithModuleRoster(testModuleRoster())
	acrFloor := authzguard.NewACRFloor(reg, authzguard.GatewayFrontedInternalRPCs()).WithProductionMode(true)

	lis := bufconn.Listen(1024 * 1024)
	gsrv := grpc.NewServer(grpc.ChainUnaryInterceptor(
		seedVerifiedPeer(san, acr), // замена извлечению личности mTLS-сертификата и доверенного acr
		callerPolicy.Unary(),
		acrFloor.Unary(),
	))
	iamv1.RegisterInternalClusterServiceServer(gsrv, srv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// 5.4-01: SAN края + acr=2 → доходит до обработчика GrantAdmin.
func TestACRFloorIntegration_0401_GatewayAcr2_Reaches(t *testing.T) {
	stub := &reachedClusterServer{}
	conn := serveACRChain(t, stub, acrTestGatewaySAN, "2")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr00000000000target"})
	require.NoError(t, err, "acr=2 ≥ acr_min=2 must pass the floor to the handler")
	require.True(t, stub.grantReached, "handler must be reached on a sufficient acr")
}

// 5.4-02: SAN края + acr=1 → ОТКАЗ от пола acr раньше обработчика.
func TestACRFloorIntegration_0402_GatewayAcr1_DeniedNoSideEffect(t *testing.T) {
	stub := &reachedClusterServer{}
	conn := serveACRChain(t, stub, acrTestGatewaySAN, "1")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr00000000000target"})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"acr=1 < acr_min=2 must be denied by the acr-floor")
	require.False(t, stub.grantReached, "handler must NOT be reached on acr-deny (no side-effect, 5.4-02)")
}

// 5.4-06: проверенный SAN НЕ края (kacho-vpc) на RPC за краем → ОТКАЗ от
// политики вызывающего ПЕРВЫМ (пол acr не исполняется вовсе; изъятием
// служебной учётки модуля от acr на RPC за краем не злоупотребить).
func TestACRFloorIntegration_0406_NonGatewaySAN_CallerPolicyDeniesFirst(t *testing.T) {
	stub := &reachedClusterServer{}
	// Даже подделанный высокий acr=3 от собеседника не края помочь не должен.
	conn := serveACRChain(t, stub, acrTestVPCSAN, "3")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err := iamv1.NewInternalClusterServiceClient(conn).GrantAdmin(ctx,
		&iamv1.GrantClusterAdminRequest{SubjectId: "usr00000000000target"})
	require.Equal(t, codes.PermissionDenied, status.Code(err),
		"a non-gateway module on a gateway-fronted RPC must be denied (caller-policy first)")
	require.False(t, stub.grantReached, "handler must NOT be reached")
}

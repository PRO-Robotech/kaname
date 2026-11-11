// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// GDU09: настоящий TLS gRPC и хвост ответа, не прямой вызов перехватчика.
// Дублёр Update только записывает достижение и отвечает специальным Aborted.
// Здесь нет аккаунта, D0/B0 или выдачи полномочий машине: бизнес-право Update
// и неизменность выдач проверяют отдельные native/REST сценарии kaname#1032.
import (
	"context"
	"net"
	"testing"
	"time"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	gdu09TransportReached = "GDU09 transport sentinel reached"
	gdu09HumanID          = "usr00000000000001032"
	gdu09MachineID        = "sva00000000000001032"
	gdu09Challenge        = "Bearer error=\"insufficient_user_authentication\", error_description=\"Required ACR 2 for this resource; presented ACR 1\", acr_values=\"2\""
	gdu09StepUpText       = "authentication level is insufficient: step up with a second factor, or present a credential of another kind"
)

type gdu09ListenerCall struct {
	principalType string
	principalID   string
	named         bool
	forwarded     bool
	presented     bool
	acr           string
	request       *iamv1.UpdateGrantDelegationRequest
}

type gdu09RecordingService struct {
	iamv1.UnimplementedGrantDelegationServiceServer
	calls chan gdu09ListenerCall
}

func (s *gdu09RecordingService) Update(ctx context.Context, req *iamv1.UpdateGrantDelegationRequest) (*operationpb.Operation, error) {
	p, named := operations.PrincipalFromContextOK(ctx)
	_, forwarded := grpcsrv.TrustedPrincipalFromContext(ctx)
	acr, _ := grpcsrv.TrustedACRFromContext(ctx)
	if callerorigin.IsPresentedCredential(ctx) {
		acr, _ = callerorigin.AssuranceFrom(ctx)
	}
	s.calls <- gdu09ListenerCall{
		principalType: p.Type, principalID: p.ID, named: named,
		forwarded: forwarded, presented: callerorigin.IsPresentedCredential(ctx), acr: acr,
		request: proto.Clone(req).(*iamv1.UpdateGrantDelegationRequest),
	}
	// Не Operation success: прохождение ACR не выдаёт права на обновление.
	return nil, status.Error(codes.Aborted, gdu09TransportReached)
}

func gdu09TLSListener(t *testing.T, reg *seed.PermissionRegistry, clientSAN string, reader *presentedcred.Reader) (iamv1.GrantDelegationServiceClient, *gdu09RecordingService) {
	t.Helper()
	serverTLS, clientTLS := secondLockTLS(t, clientSAN)
	chain := append([]grpc.UnaryServerInterceptor{authzguard.DenyDetailUnary(reg)},
		publicIdentityUnary(fwdCfg(acrTestGatewaySAN), reader)...)
	chain = append(chain,
		authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), reg, presentedcred.Presented).
			WithModuleRoster(testModuleRoster()).Unary(),
		authzguard.AntiAnonymousUnary(nil))
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.ChainUnaryInterceptor(chain...))
	recording := &gdu09RecordingService{calls: make(chan gdu09ListenerCall, 16)}
	iamv1.RegisterGrantDelegationServiceServer(server, recording)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return iamv1.NewGrantDelegationServiceClient(conn), recording
}

func TestGrantDelegation_GDU09_PublicTLSListenerStepUpTrailer(t *testing.T) {
	// Метод и пол берутся из настоящих generated descriptors и встроенного
	// каталога службы. Отсутствующий каталог не заменяется floorCatalog.
	const full = "kaname.cloud.iam.v1.GrantDelegationService/Update"
	require.Equal(t, "/"+full, iamv1.GrantDelegationService_Update_FullMethodName)
	descriptor, err := protoregistry.GlobalFiles.FindDescriptorByName("kaname.cloud.iam.v1.GrantDelegationService")
	require.NoError(t, err)
	method := descriptor.(protoreflect.ServiceDescriptor).Methods().ByName("Update")
	require.NotNil(t, method)
	require.Equal(t, "<exempt>", proto.GetExtension(method.Options(), authzv1.E_Permission))
	require.Equal(t, "HANDLER_DECIDES", proto.GetExtension(method.Options(), authzv1.E_ExemptReason))
	require.Equal(t, "2", proto.GetExtension(method.Options(), authzv1.E_RequiredAcrMin))
	require.Equal(t, "kaname-step-up-challenge", iamerr.StepUpChallengeTrailer)
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	require.NoError(t, err)
	entry, exists := reg.LookupFQN(full)
	require.True(t, exists, "Дано: embedded каталог обязан содержать настоящий Update")
	require.Equal(t, "<exempt>", entry.Permission)
	require.Equal(t, "2", reg.RequiredACRMin(full), "Дано: политика слушателя читает реальный пол 2")

	request := &iamv1.UpdateGrantDelegationRequest{
		GrantDelegationId: "gdl00000000000001032",
		RoleIds:           []string{"rol00000000000001031", "rol00000000000001032"},
		UpdateMask:        &fieldmaskpb.FieldMask{Paths: []string{"role_ids"}},
	}
	call := func(t *testing.T, client iamv1.GrantDelegationServiceClient, md metadata.MD) (error, metadata.MD) {
		t.Helper()
		ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(context.Background(), md), 5*time.Second)
		defer cancel()
		var trailer metadata.MD
		response, err := client.Update(ctx, request, grpc.Trailer(&trailer))
		require.Nil(t, response, "sentinel никогда не объявляет бизнес-успех")
		return err, trailer
	}
	notReached := func(t *testing.T, recording *gdu09RecordingService) {
		t.Helper()
		select {
		case <-recording.calls:
			t.Fatal("отклонённый транспортный вызов дошёл до Update")
		default:
		}
	}
	reached := func(t *testing.T, client iamv1.GrantDelegationServiceClient, recording *gdu09RecordingService, md metadata.MD, kind, id, acr string, presented bool) {
		t.Helper()
		err, trailer := call(t, client, md)
		require.Equal(t, codes.Aborted, status.Code(err), "должен ответить именно sentinel Update")
		require.Equal(t, gdu09TransportReached, status.Convert(err).Message())
		require.Empty(t, trailer.Get(iamerr.StepUpChallengeTrailer))
		select {
		case got := <-recording.calls:
			require.True(t, got.named)
			require.Equal(t, kind, got.principalType)
			require.Equal(t, id, got.principalID)
			require.Equal(t, acr, got.acr)
			require.Equal(t, presented, got.presented)
			if !presented {
				require.True(t, got.forwarded, "личность машины/человека пришла от проверенного TLS forwarder")
			}
			require.True(t, proto.Equal(request, got.request), "тот же запрос дошёл без подмены")
		default:
			t.Fatal("код sentinel без фактического достижения Update")
		}
		notReached(t, recording)
	}
	refusedLevelOne := func(t *testing.T, client iamv1.GrantDelegationServiceClient, recording *gdu09RecordingService, md metadata.MD) {
		t.Helper()
		err, trailer := call(t, client, md)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		require.Equal(t, gdu09StepUpText, status.Convert(err).Message())
		require.Empty(t, status.Convert(err).Details())
		require.Equal(t, []string{gdu09Challenge}, trailer.Get("kaname-step-up-challenge"),
			"точный challenge прочитан клиентом с настоящего gRPC провода")
		notReached(t, recording)
	}
	forwardedMD := func(kind, id, acr string) metadata.MD {
		return metadata.Pairs(grpcsrv.MDKeyPrincipalType, kind,
			grpcsrv.MDKeyPrincipalID, id, grpcsrv.MDKeyTokenACR, acr)
	}

	// Этот TLS peer — существующий допущенный forwarder. Для близнецов
	// меняется только ACR; listener, пользователь и запрос те же.
	forwardedClient, forwarded := gdu09TLSListener(t, reg, acrTestGatewaySAN, nil)
	t.Run("forwarded_human_acr1_with_acr2_twins", func(t *testing.T) {
		levelTwo := forwardedMD("user", gdu09HumanID, "2")
		reached(t, forwardedClient, forwarded, levelTwo, "user", gdu09HumanID, "2", false)
		refusedLevelOne(t, forwardedClient, forwarded, forwardedMD("user", gdu09HumanID, "1"))
		reached(t, forwardedClient, forwarded, levelTwo, "user", gdu09HumanID, "2", false)
	})
	t.Run("forwarded_machine_bypasses_interactive_acr_only", func(t *testing.T) {
		reached(t, forwardedClient, forwarded, forwardedMD("service_account", gdu09MachineID, "1"),
			"service_account", gdu09MachineID, "1", false)
	})

	// Второй TLS peer — безымянный хоп, не модуль и не forwarder. Клиентский
	// лист проверяется той же CA helper; production mTLS не ослаблен. Человека
	// и машину здесь называет настоящий читатель подписанного предъявленного.
	reader, mint := chainMint(t)
	directClient, direct := gdu09TLSListener(t, reg, "", reader)
	presentedMD := func(kind, id, acr string) metadata.MD {
		raw := mint(jwt.MapClaims{"sub": id, "acr": acr,
			domain.ClaimPrincipalType: kind, domain.ClaimPrincipalID: id})
		return metadata.Pairs(presentedcred.MetadataKey, "Bearer "+raw)
	}
	t.Run("anonymous_tls_hop_with_acr2_twin", func(t *testing.T) {
		reached(t, directClient, direct, presentedMD("user", gdu09HumanID, "2"),
			"user", gdu09HumanID, "2", true)
		err, trailer := call(t, directClient, nil)
		require.Equal(t, codes.Unauthenticated, status.Code(err))
		require.Equal(t, "no credential presented; authenticate with authorization: Bearer <token>", status.Convert(err).Message())
		require.Empty(t, trailer.Get(iamerr.StepUpChallengeTrailer), "безымянному нужен вход, не повышение ACR")
		notReached(t, direct)
		reached(t, directClient, direct, presentedMD("user", gdu09HumanID, "2"),
			"user", gdu09HumanID, "2", true)
	})
	t.Run("presented_human_acr1_with_acr2_twins", func(t *testing.T) {
		reached(t, directClient, direct, presentedMD("user", gdu09HumanID, "2"),
			"user", gdu09HumanID, "2", true)
		refusedLevelOne(t, directClient, direct, presentedMD("user", gdu09HumanID, "1"))
		reached(t, directClient, direct, presentedMD("user", gdu09HumanID, "2"),
			"user", gdu09HumanID, "2", true)
	})
	t.Run("presented_machine_bypasses_interactive_acr_only", func(t *testing.T) {
		reached(t, directClient, direct, presentedMD("service_account", gdu09MachineID, "1"),
			"service_account", gdu09MachineID, "1", true)
	})
}

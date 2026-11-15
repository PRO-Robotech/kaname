// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/edgecredential"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const fullBindListenerGateway = "spiffe://kacho.cloud/ns/kacho/sa/kacho-api-gateway"

// Сертификаты повторяют secondLockTLS: взаимная проверка CA и SAN, без
// insecure транспорта. Личность actor приходит только с проверенного forwarder.
func fullBindListenerTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject:   pkix.Name{CommonName: "full-bind-listener-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	leaf := func(serial int64, usage x509.ExtKeyUsage, san string) tls.Certificate {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, e)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(serial),
			Subject:   pkix.Name{CommonName: "full-bind-listener-leaf"},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
			DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
		if san != "" {
			u, e := url.Parse(san)
			require.NoError(t, e)
			tmpl.URIs = []*url.URL{u}
		}
		der, e := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		require.NoError(t, e)
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server := &tls.Config{Certificates: []tls.Certificate{leaf(2, x509.ExtKeyUsageServerAuth, "")},
		ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots, MinVersion: tls.VersionTLS12}
	client := &tls.Config{Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth, fullBindListenerGateway)},
		RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
	return server, client
}

// Регистрируется настоящий handler fullBindWorld, включая active/strict writer
// и обычный LOGIN. Здесь нет sentinel-handler или разрешающего authorizer.
// Порядок policy соответствует publicUnary в cmd/kaname/serve.go.
func fullBindListener(t *testing.T, w *fullBindWorld) iamv1.AccessBindingServiceClient {
	t.Helper()
	registry, err := seed.LoadPermissionRegistry(w.ctx, nil)
	require.NoError(t, err)
	// Create имеет существующую HANDLER_DECIDES строку, а не промах каталога.
	// Exempt RPC не называет action для DenyDetailUnary: handler-отказ остаётся без details.
	const method = "kaname.cloud.iam.v1.AccessBindingService/Create"
	entry, exists := registry.LookupFQN(method)
	require.True(t, exists, "Дано: настоящий каталог содержит AccessBinding.Create")
	require.Equal(t, catalogderive.ExemptPermission, entry.Permission)
	require.Empty(t, registry.ActionForMethod(method), "exempt метод не выдумывает action")
	roster, err := moduleidentity.Parse([]string{"kacho/kacho-api-gateway=edge"})
	require.NoError(t, err)
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: w.door, PositiveTTL: time.Millisecond})
	require.NoError(t, err)
	chain := append([]grpc.UnaryServerInterceptor{authzguard.DenyDetailUnary(registry)},
		grpcsrv.PrincipalExtractUnary(grpcsrv.NewTrustDomain("kacho.cloud"), grpcsrv.NewTrustedForwarders(fullBindListenerGateway))...)
	chain = append(chain, edgecredential.Unary(),
		authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), registry, presentedcred.Presented).
			WithModuleRoster(roster).Unary(),
		authzguard.NewAddressGate(personmarks.New(w.pool)).Unary(),
		authzguard.AntiAnonymousUnary(nil), door.Unary(),
		func(ctx context.Context, req any, info *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
			// Контроль личности — после настоящего admission, до real handler.
			p, ok := operations.PrincipalFromContextOK(ctx)
			if !ok || p.Type != "user" || p.ID != string(w.usrD) {
				return nil, status.Error(codes.Internal, "full-bind listener principal mismatch")
			}
			if _, trusted := grpcsrv.TrustedPrincipalFromContext(ctx); !trusted {
				return nil, status.Error(codes.Internal, "full-bind listener requires trusted forwarding")
			}
			return next(ctx, req)
		})
	serverTLS, clientTLS := fullBindListenerTLS(t)
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(serverTLS)), grpc.ChainUnaryInterceptor(chain...))
	iamv1.RegisterAccessBindingServiceServer(server, w.ab)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(credentials.NewTLS(clientTLS)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return iamv1.NewAccessBindingServiceClient(conn)
}

func fullBindListenerCall(t *testing.T, w *fullBindWorld, client iamv1.AccessBindingServiceClient,
	request *iamv1.CreateAccessBindingRequest, allow bool) *status.Status {
	t.Helper()
	before := w.bindingsOf(w.usrE, w.prjA)
	ctx, cancel := context.WithTimeout(metadata.NewOutgoingContext(w.ctx, metadata.Pairs(
		grpcsrv.MDKeyPrincipalType, "user", grpcsrv.MDKeyPrincipalID, string(w.usrD),
		grpcsrv.MDKeyTokenACR, "2")), 30*time.Second)
	defer cancel()
	op, err := client.Create(ctx, request)
	if !allow {
		require.Nil(t, op, "отказ на проводе предшествует принятию Operation")
		require.Equal(t, codes.PermissionDenied, status.Code(err))
		st := status.Convert(err)
		require.Equal(t, "permission denied", st.Message())
		require.Empty(t, st.Details(), "exempt Create не получает catalog action/details")
		require.True(t, proto.Equal(status.New(codes.PermissionDenied, "permission denied").Proto(), st.Proto()),
			"полный wire status равен объявленному handler-отказу, без добавленных details")
		require.Equal(t, before, w.bindingsOf(w.usrE, w.prjA), "отказ не создал binding")
		require.Empty(t, w.listOf(w.usrE), "положительный actor Given не выдан recipient")
		w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB1, relverdict.Allow)
		w.native("user:"+string(w.usrE), "v_get", atcBoxType, atcB1, relverdict.Deny)
		w.native("user:"+string(w.usrE), "v_list", atcBoxType, atcB2, relverdict.Deny)
		return st
	}
	require.NoError(t, err)
	require.NotNil(t, op)
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.Nil(t, done.Error, "durable успех real handler")
	var meta iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&meta))
	require.NotEmpty(t, meta.GetAccessBindingId())
	require.Equal(t, before+1, w.bindingsOf(w.usrE, w.prjA))
	rows := w.listOf(w.usrE)
	require.Len(t, rows, 1)
	require.Equal(t, meta.GetAccessBindingId(), string(rows[0].ID))
	require.Equal(t, request.GetRoleId(), string(rows[0].RoleID))
	require.Equal(t, string(w.prjA), rows[0].ResourceID)
	require.Equal(t, domain.AccessBindingStatusActive, rows[0].Status)
	require.Equal(t, string(w.usrE), string(rows[0].SubjectID))
	require.True(t, rows[0].Target.AllInScope)
	// Eventual нижний порт проверяется отдельно от принятого durable успеха.
	w.eventuallyNative("user:"+string(w.usrE), "v_get", atcB1, relverdict.Allow)
	w.eventuallyNative("user:"+string(w.usrE), "v_list", atcB2, relverdict.Allow)
	return nil
}

func TestFullBindListener_CoverageRequiresScopedCreate(t *testing.T) {
	var denied *status.Status
	for _, allow := range []bool{true, false} {
		t.Run(map[bool]string{true: "with_scoped_create", false: "without_scoped_create"}[allow], func(t *testing.T) {
			w := newFullBindWorld(t)
			source := w.role("fb_listener_source", fullBindBoxRule("get", "list"))
			proposed := w.role("fb_listener_proposed", fullBindBoxRule("get", "list"))
			require.NotEqual(t, source, proposed)
			w.source(source, allInScopeTarget())
			capability := w.createCapabilityRole()
			if allow {
				w.source(capability, allInScopeTarget())
			}
			w.actorHasNoScopeAdminBypass()
			w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB1, relverdict.Allow)
			w.native("user:"+string(w.usrD), "v_list", atcBoxType, atcB2, relverdict.Allow)
			deniedHere := fullBindListenerCall(t, w, fullBindListener(t, w),
				w.request(w.usrE, proposed, allInScopeTarget()), allow)
			if !allow {
				denied = deniedHere
			}
		})
	}
	require.NotNil(t, denied)
	// Тот же отказ повторяется через тот же genuine listener без маскировки
	// PermissionDenied ошибкой транспорта/мира. Сравнивается полное wire status.
	t.Run("same_method_same_refusal", func(t *testing.T) {
		w := newFullBindWorld(t)
		source := w.role("fb_listener_source", fullBindBoxRule("get", "list"))
		proposed := w.role("fb_listener_proposed", fullBindBoxRule("get", "list"))
		w.source(source, allInScopeTarget())
		client := fullBindListener(t, w)
		req := w.request(w.usrE, proposed, allInScopeTarget())
		first := fullBindListenerCall(t, w, client, req, false)
		second := fullBindListenerCall(t, w, client, req, false)
		require.True(t, proto.Equal(first.Proto(), second.Proto()), "точный отказ повторён на проводе")
		require.True(t, proto.Equal(denied.Proto(), first.Proto()), "отказ не раскрывает Given мира")
	})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package edgecredential_test

// edgecredential_test.go — номер записи сессии и номер выпуска, переданные
// краем, доезжают до обработчика ТОЛЬКО под вердиктом доверенного отправителя
// личности (kaname#677). Цепочка в пробе — та же, что у публичного слушателя:
// общая пара извлечения платформы (`grpcsrv.PrincipalExtractUnary`), за ней —
// читатель этого пакета; обработчик видит то, что видел бы глагол.
//
// Положительный кейс и каждый отрицательный различаются ОДНИМ фактом:
// отправитель не доверен; личность не передана; личность — не человек; номер
// не той формы; номеров два; личность названа предъявленным удостоверением.

import (
	"context"
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/edgecredential"
)

const (
	sessionOfAlice = "hss-0000000000000000a"
	jtiOfAlice     = "jti-of-alice"
)

// seen — что увидел обработчик за цепочкой слушателя.
type seen struct {
	session, credential       string
	hasSession, hasCredential bool
}

// through прогоняет запрос с метаданными md через пару извлечения платформы и
// читатель этого пакета. pre — подготовка контекста ДО цепочки (собеседник,
// пометка предъявленного).
func through(t *testing.T, md metadata.MD, pre func(context.Context) context.Context) seen {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(), md)
	if pre != nil {
		ctx = pre(ctx)
	}
	chain := append(grpcsrv.PrincipalExtractUnary(grpcsrv.NewTrustDomain(""), grpcsrv.NewTrustedForwarders()), edgecredential.Unary())
	var got seen
	handler := func(ctx context.Context, _ any) (any, error) {
		got.session, got.hasSession = callerorigin.SessionIDFrom(ctx)
		got.credential, got.hasCredential = callerorigin.CredentialIDFrom(ctx)
		return nil, nil
	}
	invoke := handler
	for i := len(chain) - 1; i >= 0; i-- {
		ic, next := chain[i], invoke
		invoke = func(ctx context.Context, req any) (any, error) {
			return ic(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AccessKeyService/Revoke"}, next)
		}
	}
	_, err := invoke(ctx, nil)
	require.NoError(t, err)
	return got
}

// edgeForwarded — метаданные, которые ставит край для человека alice.
func edgeForwarded() metadata.MD {
	return metadata.Pairs(
		principalwire.MetaPrincipalType, "user",
		principalwire.MetaPrincipalID, "usr-alice",
		edgecredential.MetaSessionID, sessionOfAlice,
		principalwire.MetaTokenJti, jtiOfAlice,
	)
}

// TestForwardedSessionReachesTheHandlerFromATrustedForwarder — положительный
// кейс: доверенный отправитель передал человека, номер записи и номер выпуска —
// обработчик видит оба.
func TestForwardedSessionReachesTheHandlerFromATrustedForwarder(t *testing.T) {
	got := through(t, edgeForwarded(), nil)
	require.True(t, got.hasSession, "номер записи от доверенного отправителя доезжает")
	require.Equal(t, sessionOfAlice, got.session)
	require.True(t, got.hasCredential, "номер выпуска от доверенного отправителя доезжает")
	require.Equal(t, jtiOfAlice, got.credential)
}

// untrustedPeer — собеседник под TLS без проверенного сертификата: пара
// извлечения отказывает ему в праве говорить за человека.
func untrustedPeer(ctx context.Context) context.Context {
	return peer.NewContext(ctx, &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}})
}

// TestForwardedSessionIsDroppedOffTheTrustedHop — каждый отрицательный кейс
// отличается от положительного ОДНИМ фактом; номер не доезжает ни в одном.
func TestForwardedSessionIsDroppedOffTheTrustedHop(t *testing.T) {
	cases := map[string]struct {
		md  func() metadata.MD
		pre func(context.Context) context.Context
	}{
		"untrusted-peer": {md: edgeForwarded, pre: untrustedPeer},
		"no-principal": {md: func() metadata.MD {
			md := edgeForwarded()
			md.Delete(principalwire.MetaPrincipalType)
			md.Delete(principalwire.MetaPrincipalID)
			return md
		}},
		"service-account": {md: func() metadata.MD {
			md := edgeForwarded()
			md.Set(principalwire.MetaPrincipalType, "service_account")
			md.Set(principalwire.MetaPrincipalID, "sva-0000000000000000a")
			return md
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got := through(t, c.md(), c.pre)
			require.False(t, got.hasSession, "номер записи не доезжает: %+v", got)
			require.False(t, got.hasCredential, "номер выпуска не доезжает: %+v", got)
		})
	}
}

// TestForwardedSessionOfTheWrongFormIsNotAName — номер не той формы и два
// номера разом — не номер: текущая не названа (личность доезжает, предмет
// только номер).
func TestForwardedSessionOfTheWrongFormIsNotAName(t *testing.T) {
	for name, values := range map[string][]string{
		"wrong-form": {"usr-0000000000000000a"},
		"two-values": {sessionOfAlice, "hss-0000000000000000b"},
		"empty":      {""},
	} {
		t.Run(name, func(t *testing.T) {
			md := edgeForwarded()
			md.Set(edgecredential.MetaSessionID, values...)
			got := through(t, md, nil)
			require.False(t, got.hasSession, "номер %q не принят", values)
			require.True(t, got.hasCredential, "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: соседний номер выпуска доезжает")
		})
	}
}

// TestPresentedCredentialIsNotOverriddenByForwardedMetadata — личность названа
// ПРЕДЪЯВЛЕННЫМ удостоверением: метаданные края на этой полосе не читаются, и
// выпуск остаётся тем, который проверил читатель предъявленного.
func TestPresentedCredentialIsNotOverriddenByForwardedMetadata(t *testing.T) {
	got := through(t, edgeForwarded(), func(ctx context.Context) context.Context {
		ctx = callerorigin.WithCredentialID(ctx, "jti-presented")
		return callerorigin.With(ctx, callerorigin.PresentedCredential)
	})
	require.False(t, got.hasSession, "переданный номер записи на полосе предъявленного не читается")
	require.Equal(t, "jti-presented", got.credential, "выпуск предъявленного не подменён переданным")
}

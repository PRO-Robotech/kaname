// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// serve_internal_principal_trust_test.go — страж от подмены для ОБОИХ
// gRPC-слушателей (внутрикластерного :9091 и публичного :9090).
//
// Предмет: ТРАНСПОРТНАЯ половина инварианта доверия — собеседник, не прошедший
// проверки клиентского сертификата, не должен суметь проставить
// x-kacho-principal-*. Провязка слушателя прежним безусловным
// grpcsrv.UnaryPrincipalExtract / StreamPrincipalExtract проставляла бы
// переданный субъект вслепую, и личностью, записанной в
// operations.principal_* / аудит / granted_by, стало бы то, что набрал
// вызывающий.
//
// ДРУГАЯ половина — КАКИМ проверенным собеседникам вообще можно передавать —
// это перечень передающих, и живёт она в trusted_forwarders_test.go (поведение)
// и trusted_forwarders_wiring_test.go (размещение). Половины дополняют друг
// друга: проверка говорит «ты тот, кем называет тебя сертификат», перечень —
// «и ты из отправителей, которым позволено говорить за пользователя». Обе
// цепочки здесь собирает ТОТ ЖЕ боевой сборщик, что у слушателей
// (identityUnary), так что изменение провязки не оставит эти замки зелёными,
// пока боевая сборка расходится.

import (
	"context"
	"crypto/tls"
	"net/url"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
)

// TestPublicChain_DropsForgedPrincipal_HonorsVerified — поведенческий страж над
// той самой цепочкой перехватчиков, которую провязывает публичный слушатель
// (identityUnary): поддельный субъект от непроверенного TLS-собеседника
// отбрасывается (носитель остаётся SystemPrincipal); субъект перечисленного
// проверенного собеседника принимается.
func TestPublicChain_DropsForgedPrincipal_HonorsVerified(t *testing.T) {
	chain := publicUnaryChainUnderTest()

	t.Run("unverified_tls_peer_forged_principal_dropped", func(t *testing.T) {
		tlsPeer := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}}
		ctx := peer.NewContext(context.Background(), tlsPeer)
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, "usr-mallory",
			grpcsrv.MDKeyPrincipalDisplay, "mallory@example.com",
		))

		var carrierID string
		var trusted, present = true, true
		final := func(c context.Context, _ any) (any, error) {
			// present берётся из PrincipalFromContextOK — единственного читателя,
			// который отличает «носитель вычищен» от «носитель держит системную
			// личность». PrincipalFromContext этого не может: по контракту оба
			// состояния читаются как SystemPrincipal, и утверждение о вычистке
			// через него остаётся зелёным, даже когда недоверенному отправителю
			// вручили системную личность — ту самую, по которой предикат владения
			// совпадает с каждой операцией, записанной системой.
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}
		if trusted {
			t.Errorf("principal from unverified TLS peer must NOT be trusted on :9090")
		}
		if present {
			t.Errorf("the identity carrier survived for an untrusted sender: got %q — it must be "+
				"scrubbed, otherwise the ownership predicate treats this request as the owner of "+
				"every system-written operation", carrierID)
		}
		if carrierID == "usr-mallory" {
			t.Errorf("impersonation: forged principal id 'usr-mallory' reached the use-case carrier")
		}
	})

	t.Run("verified_mtls_peer_principal_honored", func(t *testing.T) {
		ctx := forwardedIdentity(verifiedCertPeer(t, fwdGatewaySAN), "usr-alice")

		var carrierID string
		var present bool
		final := func(c context.Context, _ any) (any, error) {
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}
		if !present {
			t.Errorf("the identity carrier must be populated for a listed, verified sender")
		}
		if carrierID != "usr-alice" {
			t.Errorf("verified principal not honored: got %q, want %q", carrierID, "usr-alice")
		}
	})
}

// TestPublicChain_HonorsVerifiedConsumerForwarder — модуль НЕ край (kacho-vpc)
// зовёт :9090 ProjectService.Get на пути своего Create и передаёт субъекта
// КОНЕЧНОГО ПОЛЬЗОВАТЕЛЯ, чтобы iam применил фильтр области этого арендатора.
// Поэтому :9090 по замыслу — слушатель СО МНОГИМИ передающими, и перечень
// называет этих потребителей рядом с краем.
//
// Заметьте, чего это НЕ утверждает: быть дозволенным ОТПРАВИТЕЛЕМ — не значит
// иметь право звать что угодно. Поглагольная политика вызывающего
// (authzguard.PublicCallerPolicy) пускает vpc на ProjectService/Get и больше
// никуда — см. её собственные пробы.
func TestPublicChain_HonorsVerifiedConsumerForwarder(t *testing.T) {
	chain := publicUnaryChainUnderTest()
	ctx := forwardedIdentity(verifiedCertPeer(t, fwdVPCSAN), "usr-alice")

	var carrierID string
	final := func(c context.Context, _ any) (any, error) {
		carrierID = operations.PrincipalFromContext(c).ID
		return nil, nil
	}
	if _, err := chain(ctx, nil, nil, final); err != nil {
		t.Fatalf("chain returned error: %v", err)
	}
	if carrierID != "usr-alice" {
		t.Errorf("a listed consumer forwarder must be honored on :9090 (cross-service project "+
			"validation runs under the end user): got %q, want usr-alice", carrierID)
	}
}

// TestInternalChain_DropsForgedPrincipal_HonorsVerified — поведенческий страж над
// той самой цепочкой перехватчиков, которую провязывает внутренний слушатель
// (identityUnary — ТОТ ЖЕ сборщик, что у публичного).
//
//   - непроверенный TLS-собеседник, предъявивший поддельный x-kacho-principal-*
//     → носитель субъекта, который читают use-case
//     (operations.PrincipalFromContext), ОБЯЗАН остаться на запасном
//     SystemPrincipal (поддельный id отброшен).
//   - перечисленный, проверенный mTLS собеседник с теми же метаданными →
//     субъект ПРИНИМАЕТСЯ (для законных отправителей поведение не меняется).
func TestInternalChain_DropsForgedPrincipal_HonorsVerified(t *testing.T) {
	chain := internalUnaryChainUnderTest()

	t.Run("unverified_tls_peer_forged_principal_dropped", func(t *testing.T) {
		// TLS есть, но проверенного клиентского сертификата НЕТ (пустой
		// VerifiedChains) — ровно так выглядит дошедший до перехватчика
		// непроверенный собеседник или собеседник без сертификата.
		tlsPeer := &peer.Peer{AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{}}}
		ctx := peer.NewContext(context.Background(), tlsPeer)
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(
			grpcsrv.MDKeyPrincipalType, "user",
			grpcsrv.MDKeyPrincipalID, "usr-mallory",
			grpcsrv.MDKeyPrincipalDisplay, "mallory@example.com",
		))

		var carrierID string
		var trusted, present = true, true
		final := func(c context.Context, _ any) (any, error) {
			// present берётся из PrincipalFromContextOK — единственного читателя,
			// который отличает «носитель вычищен» от «носитель держит системную
			// личность». PrincipalFromContext этого не может: по контракту оба
			// состояния читаются как SystemPrincipal, и утверждение о вычистке
			// через него остаётся зелёным, даже когда недоверенному отправителю
			// вручили системную личность — ту самую, по которой предикат владения
			// совпадает с каждой операцией, записанной системой.
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if trusted {
			t.Errorf("principal from unverified TLS peer must NOT be trusted on :9091")
		}
		if present {
			t.Errorf("the identity carrier survived for an untrusted sender: got %q — it must be "+
				"scrubbed, otherwise the ownership predicate treats this request as the owner of "+
				"every system-written operation", carrierID)
		}
		if carrierID == "usr-mallory" {
			t.Errorf("audit-spoof: forged principal id 'usr-mallory' reached the use-case carrier")
		}
	})

	t.Run("verified_mtls_peer_principal_honored", func(t *testing.T) {
		ctx := forwardedIdentity(verifiedCertPeer(t, fwdGatewaySAN), "usr-alice")

		var carrierID string
		var trusted, present bool
		final := func(c context.Context, _ any) (any, error) {
			p, ok := operations.PrincipalFromContextOK(c)
			carrierID, present = p.ID, ok
			_, trusted = grpcsrv.TrustedPrincipalFromContext(c)
			return nil, nil
		}
		if _, err := chain(ctx, nil, nil, final); err != nil {
			t.Fatalf("chain returned error: %v", err)
		}

		if !trusted {
			t.Errorf("principal from a listed, verified mTLS peer must be trusted (no behavior change)")
		}
		if !present {
			t.Errorf("the identity carrier must be populated for a listed, verified sender")
		}
		if carrierID != "usr-alice" {
			t.Errorf("verified principal not honored: got %q, want %q", carrierID, "usr-alice")
		}
	})
}

// internalUnaryChainUnderTest / publicUnaryChainUnderTest собирают перехватчики
// личности, которые два слушателя получают на деле, вызовом БОЕВОГО сборщика, а
// не повторным перечислением здесь. Перечислением эти стражи и работали прежде,
// и именно этот дрейф позволил пустому перечню выглядеть сужением: провязка
// могла измениться, а замки бы этого не заметили.
func internalUnaryChainUnderTest() grpc.UnaryServerInterceptor {
	return chainUnaryServer(identityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN))...)
}

func publicUnaryChainUnderTest() grpc.UnaryServerInterceptor {
	return chainUnaryServer(identityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN))...)
}

// chainUnaryServer складывает однократные серверные перехватчики слева направо
// вокруг конечного обработчика, повторяя смысл grpc.ChainUnaryInterceptor.
func chainUnaryServer(interceptors ...grpc.UnaryServerInterceptor) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		chained := handler
		for i := len(interceptors) - 1; i >= 0; i-- {
			ic := interceptors[i]
			next := chained
			chained = func(c context.Context, r any) (any, error) { return ic(c, r, info, next) }
		}
		return chained(ctx, req)
	}
}

func mustParseURIs(t testing.TB, raw ...string) []*url.URL {
	t.Helper()
	out := make([]*url.URL, 0, len(raw))
	for _, r := range raw {
		u, err := url.Parse(r)
		if err != nil {
			t.Fatalf("parse uri %q: %v", r, err)
		}
		out = append(out, u)
	}
	return out
}

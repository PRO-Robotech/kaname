// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/principalwire"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
)

type chainBasicAuthority struct {
	credential domain.BasicCredential
}

func (a chainBasicAuthority) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	return a.credential, nil
}

// Проба использует боевой publicIdentityUnary, а не свой порядок звеньев.
// Отдельная сборка с настоящими WhoAmI/Check находится у authorize.
func TestDirectOpaqueUsesPublicComposition(t *testing.T) {
	raw, _, err := credsecret.Mint("sak-direct")
	if err != nil {
		t.Fatal(err)
	}
	cfg := presentedcred.Config{
		BasicCredentials: chainBasicAuthority{credential: domain.BasicCredential{
			PrincipalType: "service_account", PrincipalID: "sva00000000000direct", CredentialID: "sak-direct",
			ExpiresAt: time.Now().Add(time.Hour),
		}},
		Issuer: chainIssuer, Audience: chainAudience, AllowedAlgorithms: []string{"ES256"},
		Keys: chainKeys{}, Revocations: chainRevocations{}, RevocationCacheTTL: time.Second,
	}
	r, err := presentedcred.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	p, seen, err := runChain(t, publicChainWithReader(r), presenting(raw))
	if err != nil || !seen || p.Type != "service_account" || p.ID != "sva00000000000direct" {
		t.Fatalf("public composition lost opaque identity: %v %v %v", p, seen, err)
	}
	// Чужие principal/ACR/session/JTI не заменяют результат авторитета.
	md := edgeForwardedMD(principalwire.MetaTokenJti, "forged-jti", principalwire.MetaTokenACR, "3")
	md.Set(presentedcred.MetadataKey, "Bearer "+raw)
	spoofed := metadata.NewIncomingContext(context.Background(), md)
	p, seen, err = runChain(t, publicChainWithReader(r), spoofed)
	if err != nil || !seen || p.Type != "service_account" || p.ID != "sva00000000000direct" {
		t.Fatalf("forwarded metadata replaced opaque principal: %v %v %v", p, seen, err)
	}
	carried := runEdgeChain(t, publicChainWithReader(r), spoofed)
	if carried.hasSession || carried.credential != "sak-direct" {
		t.Fatalf("forwarded metadata replaced credential/session: %+v", carried)
	}
	// Порог человека проверяется отдельным носителем: машина законно
	// освобождена от интерактивного повышения общим правилом платформы.
	cfg.BasicCredentials = chainBasicAuthority{credential: domain.BasicCredential{
		PrincipalType: "user", PrincipalID: "usr00000000000direct", CredentialID: "sak-direct",
		ExpiresAt: time.Now().Add(time.Hour),
	}}
	userReader, err := presentedcred.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	withFloor := func(catalog authzguard.ACRRequirementLookup) grpc.UnaryServerInterceptor {
		policy := authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), catalog, presentedcred.Presented)
		return chainUnaryServer(append(publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), userReader), policy.Unary())...)
	}
	if _, _, err := runChain(t, withFloor(noFloorCatalog{}), spoofed); err != nil {
		t.Fatalf("opaque lawful twin rejected: %v", err)
	}
	if _, _, err := runChain(t, withFloor(floorCatalog{min: "2"}), spoofed); status.Code(err) != codes.Unauthenticated || status.Convert(err).Message() != stepUpText {
		t.Fatalf("forged ACR bypassed public floor: %v", err)
	}
	_, seen, err = runChain(t, internalChainNoReader(), presenting(raw))
	if err != nil || seen {
		t.Fatalf("opaque unexpectedly entered internal listener: %v %v", seen, err)
	}
	ambiguous := metadata.NewIncomingContext(context.Background(), metadata.Pairs(
		"authorization", "Bearer "+raw, "authorization", "Bearer "+raw))
	_, seen, err = runChain(t, publicChainWithReader(r), ambiguous)
	if seen || status.Code(err) != codes.Unauthenticated {
		t.Fatalf("duplicate bearer bypassed public ambiguity guard: %v %v", seen, err)
	}
}

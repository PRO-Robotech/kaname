// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Construct every authorization-bearing public unary layer in production order.
// Only DB-backed marks/relations are substituted; Check's own-door contract is
// derived from the actual descriptors, and the ACR floor from the actual seed.
type anonymousDoor struct{}

func (anonymousDoor) Check(context.Context, string, string, string) (bool, error) {
	return false, fmt.Errorf("unexpected outer relation check")
}
func anonymousPublicChain(t *testing.T, reader *presentedcred.Reader) grpc.UnaryServerInterceptor {
	t.Helper()
	catalog, err := seed.LoadPermissionRegistry(context.Background(), slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	// Цепочку собирает сборщик корня, а не перечисление звеньев здесь: ручная
	// копия молча осталась бы без звена, добавленного в корень.
	return testPublicChain(t, testPublicChainInputs{reader: reader, catalog: catalog, decider: anonymousDoor{}, prodMode: true})
}

// The transport and public identity chain are real. Only the decision port is
// replaced: these tests assert who reaches it, not a second policy evaluator.
type anonymousDecision struct {
	authorize.Authorizer
	allowed bool
	seen    []service.CheckRequest
}

type anonymousRevokedFamily struct {
	chainRevocations
	calls int
}

func (r *anonymousRevokedFamily) FamilyRevoked(context.Context, string) (bool, error) {
	r.calls++
	return true, nil
}

func TestAnonymousSelfCheck_RevokedCredentialDoesNotDowngrade(t *testing.T) {
	revocations := &anonymousRevokedFamily{}
	reader, mint := chainMintWithRevocations(t, revocations)
	d := &anonymousDecision{allowed: true}
	res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), presenting(mint(nil)), anonymousRequest(), d)
	if status.Code(err) != codes.Unauthenticated || revocations.calls != 1 || res != nil || len(d.seen) != 0 {
		t.Fatalf("revoked credential downgraded: response=%v err=%v calls=%d", res, err, len(d.seen))
	}
}

func TestAnonymousSelfCheck_NamedPrincipalAndModuleAreNotAnonymous(t *testing.T) {
	reader, _ := chainReader(t)
	for name, ctx := range map[string]context.Context{
		"module":  verifiedCertPeer(t, fwdVPCSAN),
		"system":  metadata.NewIncomingContext(verifiedCertPeer(t, fwdGatewaySAN), metadata.Pairs(grpcsrv.MDKeyPrincipalType, "system", grpcsrv.MDKeyPrincipalID, "bootstrap")),
		"unknown": metadata.NewIncomingContext(verifiedCertPeer(t, fwdGatewaySAN), metadata.Pairs(grpcsrv.MDKeyPrincipalType, "unknown", grpcsrv.MDKeyPrincipalID, "caller")),
	} {
		t.Run(name, func(t *testing.T) {
			d := &anonymousDecision{allowed: true}
			res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), ctx, anonymousRequest(), d)
			if err == nil || res != nil || len(d.seen) != 0 {
				t.Fatalf("named/module identity became anonymous: response=%v err=%v calls=%d", res, err, len(d.seen))
			}
		})
	}
}

func (d *anonymousDecision) Check(_ context.Context, req service.CheckRequest) (*service.CheckResult, error) {
	d.seen = append(d.seen, req)
	return &service.CheckResult{Allowed: d.allowed, CheckedAt: time.Now()}, nil
}

func anonymousRequest() *iamv1.AuthorizeCheckRequest {
	return &iamv1.AuthorizeCheckRequest{
		Resource: &iamv1.ResourceRef{Type: "service", Id: "123456789/registry"},
		Action:   "registry.repositories.get",
	}
}

func invokeAnonymousCheck(chain grpc.UnaryServerInterceptor, ctx context.Context, req *iamv1.AuthorizeCheckRequest, decision *anonymousDecision) (*iamv1.AuthorizeCheckResponse, error) {
	h := authorize.NewHandler(decision, authorize.NewWhoAmIUseCase(nil, nil))
	value, err := chain(ctx, req, &grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/Check"},
		func(ctx context.Context, _ any) (any, error) { return h.Check(ctx, req) })
	if err != nil {
		return nil, err
	}
	return value.(*iamv1.AuthorizeCheckResponse), nil
}

func TestAnonymousSelfCheck_PublicChainInfersOnlyAnonymous(t *testing.T) {
	reader, _ := chainReader(t)
	for _, allow := range []bool{false, true} {
		for _, ctx := range []context.Context{context.Background(), verifiedCertPeer(t, "spiffe://kacho.cloud/ns/kacho/sa/kaname")} {
			d := &anonymousDecision{allowed: allow}
			req := anonymousRequest()
			res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), ctx, req, d)
			if err != nil {
				t.Fatalf("credential-free self check: %v", err)
			}
			if res.Allowed != allow || len(d.seen) != 1 {
				t.Fatalf("decision was not preserved: response=%v calls=%d", res, len(d.seen))
			}
			got := d.seen[0]
			if got.Subject != "system_class:anonymous" || got.Resource.Type != req.Resource.Type || got.Resource.ID != req.Resource.Id || got.Action != req.Action || len(got.Context) != 0 || got.RequiredRelation != "" {
				t.Fatalf("unexpected decision request: %+v", got)
			}
			if req.Subject != "" {
				t.Fatal("handler mutated the caller's request")
			}
		}
	}
}

func TestAnonymousSelfCheck_PublicChainRefusesOverrides(t *testing.T) {
	reader, _ := chainReader(t)
	contextValue, err := structpb.NewStruct(map[string]any{"authenticated": true})
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*iamv1.AuthorizeCheckRequest){
		"anonymous_subject":       func(r *iamv1.AuthorizeCheckRequest) { r.Subject = "system_class:anonymous" },
		"authenticated_subject":   func(r *iamv1.AuthorizeCheckRequest) { r.Subject = "system_class:authenticated" },
		"user_subject":            func(r *iamv1.AuthorizeCheckRequest) { r.Subject = "user:victim" },
		"service_account_subject": func(r *iamv1.AuthorizeCheckRequest) { r.Subject = "service_account:victim" },
		"context":                 func(r *iamv1.AuthorizeCheckRequest) { r.Context = contextValue },
		"empty_context":           func(r *iamv1.AuthorizeCheckRequest) { r.Context = &structpb.Struct{} },
		"relation":                func(r *iamv1.AuthorizeCheckRequest) { r.RequiredRelation = "owner" },
	} {
		t.Run(name, func(t *testing.T) {
			req := anonymousRequest()
			mutate(req)
			d := &anonymousDecision{allowed: true}
			res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), context.Background(), req, d)
			if err == nil || res != nil || len(d.seen) != 0 {
				t.Fatalf("override reached decision: response=%v err=%v calls=%d", res, err, len(d.seen))
			}
		})
	}
}

func TestAnonymousSelfCheck_PublicChainNeverDowngradesCredentials(t *testing.T) {
	reader, mint := chainMint(t)
	for name, headers := range map[string][]string{
		"empty": {""}, "empty_bearer": {"Bearer "}, "unsupported": {"Other opaque"},
		"malformed": {"Bearer invalid"}, "basic_invalid": {"Basic invalid"},
		"expired":                   {"Bearer " + mint(jwt.MapClaims{"exp": time.Now().Add(-time.Hour).Unix()})},
		"valid_but_subject_omitted": {"Bearer " + mint(nil)},
		"duplicate":                 {"Bearer " + mint(nil), "Bearer " + mint(nil)},
	} {
		t.Run(name, func(t *testing.T) {
			ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": headers})
			d := &anonymousDecision{allowed: true}
			res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), ctx, anonymousRequest(), d)
			if err == nil || res != nil || len(d.seen) != 0 {
				t.Fatalf("credential downgraded: response=%v err=%v calls=%d", res, err, len(d.seen))
			}
		})
	}
	// A lawful authenticated self-query must still reach the same decision port.
	d := &anonymousDecision{allowed: true}
	req := anonymousRequest()
	req.Subject = "user:" + chainSubject
	res, err := invokeAnonymousCheck(anonymousPublicChain(t, reader), presenting(mint(jwt.MapClaims{"acr": "1"})), req, d)
	if err != nil || res == nil || !res.Allowed || len(d.seen) != 1 || d.seen[0].Subject != req.Subject {
		t.Fatalf("authenticated self-query changed: response=%v err=%v calls=%d", res, err, len(d.seen))
	}
}

func TestAnonymousSelfCheck_DoesNotAdmitOtherRPCs(t *testing.T) {
	reader, _ := chainReader(t)
	for _, method := range []string{
		"/kaname.cloud.iam.v1.AuthorizeService/BatchCheck",
		"/kaname.cloud.iam.v1.AuthorizeService/ListSubjects",
		"/kaname.cloud.iam.v1.AuthorizeService/ExpandRelations",
		"/kaname.cloud.iam.v1.AccessBindingService/Create",
	} {
		called := false
		_, err := anonymousPublicChain(t, reader)(context.Background(), anonymousRequest(), &grpc.UnaryServerInfo{FullMethod: method}, func(context.Context, any) (any, error) {
			called = true
			return nil, nil
		})
		if err == nil || called {
			t.Fatalf("anonymous admission leaked to %s", method)
		}
	}
}

type anonymousStream struct{ grpc.ServerStream }

func (anonymousStream) Context() context.Context { return context.Background() }

func TestAnonymousSelfCheck_DoesNotAdmitStream(t *testing.T) {
	policy := authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(), noFloorCatalog{}, presentedcred.Presented)
	called := false
	err := policy.Stream()(nil, anonymousStream{}, &grpc.StreamServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/Check"}, func(any, grpc.ServerStream) error { called = true; return nil })
	if err == nil || called {
		t.Fatal("unary self-check opened anonymous stream admission")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// directAuthority подменяет только хранилище; транспорт, читатель, WhoAmI,
// решатель и запрет чужого субъекта исполняются настоящими обработчиками.
type directAuthority struct {
	mu         sync.Mutex
	err        error
	credential domain.BasicCredential
}

func (a *directAuthority) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.credential, a.err
}

func (a *directAuthority) fail(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.err = err
}

// Эти зависимости нужны конструктору JWT-полосы. Opaque не должен их читать.
type directJWTAuthority struct{}

func (directJWTAuthority) PublishedSet(context.Context) ([]domain.PublishedKey, error) {
	return nil, errors.New("opaque reached JWT key authority")
}

func (directJWTAuthority) RevokedBefore(context.Context, string) (time.Time, bool, error) {
	return time.Time{}, false, errors.New("opaque reached JWT revocation authority")
}

func (directJWTAuthority) FamilyRevoked(context.Context, string) (bool, error) {
	return false, errors.New("opaque reached JWT family authority")
}

func (directJWTAuthority) PersonMarks(context.Context, []string) (map[string]bool, error) {
	return nil, errors.New("opaque reached JWT person authority")
}

func TestDirectOpaqueWhoAmIAndCheck(t *testing.T) {
	const subject = "service_account:sva00000000000000abc"
	raw, _, err := credsecret.Mint("sak-direct")
	if err != nil {
		t.Fatal(err)
	}
	authority := &directAuthority{credential: domain.BasicCredential{
		PrincipalType: "service_account", PrincipalID: "sva00000000000000abc",
		CredentialID: "sak-direct", ExpiresAt: time.Now().Add(time.Hour),
	}}
	reader, err := presentedcred.New(presentedcred.Config{
		BasicCredentials: authority, Issuer: "https://kaname.test", Audience: "kaname-public",
		AllowedAlgorithms: []string{"ES256"}, Keys: directJWTAuthority{},
		Revocations: directJWTAuthority{}, RevocationCacheTTL: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, verdict := newHandlerWithStub(true)
	h.whoAmI = NewWhoAmIUseCase(&fakeWhoAmIRepo{}, nil)
	h.WithCallerAuthority(&authorityStub{allow: map[string]bool{}})
	listener := bufconn.Listen(1 << 20)
	server := grpc.NewServer(grpc.UnaryInterceptor(reader.UnaryOver(nil)))
	iamv1.RegisterAuthorizeServiceServer(server, h)
	t.Cleanup(func() { server.Stop(); _ = listener.Close() })
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///kaname-direct",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := iamv1.NewAuthorizeServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("authorization", "Bearer "+raw))
	me, err := client.WhoAmI(ctx, &iamv1.WhoAmIRequest{})
	if err != nil || me.GetSubject() != subject {
		t.Fatalf("direct identity: %v, %v", me, err)
	}
	req := &iamv1.AuthorizeCheckRequest{Subject: subject,
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"}, Action: "iam.accounts.get", RequiredRelation: "viewer"}
	decision, err := client.Check(ctx, req)
	if err != nil || !decision.GetAllowed() {
		t.Fatalf("self check: %v, %v", decision, err)
	}
	foreign := &iamv1.AuthorizeCheckRequest{Subject: "user:usr_victim", Resource: req.Resource, Action: req.Action}
	if _, err := client.Check(ctx, foreign); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign check: %v", err)
	}
	if _, err := client.BatchCheck(ctx, &iamv1.BatchAuthorizeCheckRequest{Checks: []*iamv1.AuthorizeCheckRequest{req, foreign}}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("foreign batch: %v", err)
	}
	verdict.mu.Lock()
	verdict.check = false
	verdict.mu.Unlock()
	decision, err = client.Check(ctx, req)
	if err != nil || decision.GetAllowed() {
		t.Fatalf("revoked grant: %v, %v", decision, err)
	}
	authority.fail(domain.ErrBasicCredentialRefused)
	if _, err := client.WhoAmI(ctx, &iamv1.WhoAmIRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential at me: %v", err)
	}
	if _, err := client.Check(ctx, req); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked credential at check: %v", err)
	}
	authority.fail(errors.New("private database detail"))
	if _, err := client.WhoAmI(ctx, &iamv1.WhoAmIRequest{}); status.Code(err) != codes.Unavailable || status.Convert(err).Message() != "credential authority unavailable" {
		t.Fatalf("authority outage must be sanitized: %v", err)
	}
}

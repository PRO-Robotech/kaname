// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_federated_test.go — federation IN: unit tests for the
// federated IssueSAKeyUseCase path.
//
// RED-then-GREEN, test-first. These tests fail
// without the federated branch in usecases.go (no Hydra request, wrong
// response shape, redactor scheduled needlessly) and pass once it lands.
package sa_keys

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ---- Mocks ----

type stubSAClientRepo struct {
	inserted  domain.ServiceAccountOAuthClient
	insertOK  bool
	accountID domain.AccountID
	getRow    domain.ServiceAccountOAuthClient
	getErr    error
}

func (s *stubSAClientRepo) Get(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error) {
	if s.getRow.ID != "" || s.getErr != nil {
		return s.getRow, s.getErr
	}
	return domain.ServiceAccountOAuthClient{}, errors.New("not implemented")
}
func (s *stubSAClientRepo) Insert(ctx context.Context, tx service.Tx, c domain.ServiceAccountOAuthClient) (domain.ServiceAccountOAuthClient, error) {
	s.inserted = c
	s.insertOK = true
	c.CreatedAt = time.Now().UTC()
	return c, nil
}
func (s *stubSAClientRepo) DeleteByID(ctx context.Context, tx service.Tx, id domain.SAOAuthClientID) error {
	return nil
}
func (s *stubSAClientRepo) List(ctx context.Context, svaID domain.ServiceAccountID, pageToken string, pageSize int32) ([]domain.ServiceAccountOAuthClient, string, error) {
	return nil, "", nil
}

type stubHydra struct {
	gotReq  clients.CreateOAuthClientRequest
	created bool
}

func (s *stubHydra) CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	s.gotReq = req
	s.created = true
	return clients.HydraOAuthClient{ClientID: "hydra-cli-fake"}, nil
}
func (s *stubHydra) DeleteOAuthClient(ctx context.Context, clientID string) error { return nil }

type stubTx struct{}

func (s *stubTx) Begin(ctx context.Context) (service.Tx, error) { return noopTx{}, nil }

// noopTx implements the opaque service.Tx (Commit/Rollback only); the repo stub
// above ignores the tx and never issues SQL, so no driver methods are needed.
type noopTx struct{}

func (noopTx) Commit(ctx context.Context) error   { return nil }
func (noopTx) Rollback(ctx context.Context) error { return nil }

// stubOpsRepo — in-memory operations.Repo.
type stubOpsRepo struct {
	mu       sync.Mutex
	created  bool
	done     bool
	lastResp *anypb.Any
	lastErr  *status.Status
}

func (s *stubOpsRepo) Create(ctx context.Context, op operations.Operation) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = true
	return nil
}
func (s *stubOpsRepo) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = true
	return nil
}
func (s *stubOpsRepo) Get(ctx context.Context, id string) (*operations.Operation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &operations.Operation{ID: id, Done: s.done}, nil
}
func (s *stubOpsRepo) List(ctx context.Context, f operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (s *stubOpsRepo) MarkDone(ctx context.Context, id string, response *anypb.Any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.lastResp = response
	return nil
}
func (s *stubOpsRepo) MarkError(ctx context.Context, id string, st *status.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.lastErr = st
	return nil
}
func (s *stubOpsRepo) Cancel(ctx context.Context, id string) error { return nil }

// waitForOp polls until MarkDone has fired. `operations.Run` is async — it
// spawns a goroutine that invokes the use-case function and then MarkDone.
func waitForOp(t *testing.T, ops *stubOpsRepo) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ops.mu.Lock()
		done := ops.done
		ops.mu.Unlock()
		if done {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("operation never marked done")
}

// anyUnmarshalTo decodes an Any value into m, ignoring the TypeUrl since the
// caller knows the target type. Stub-test convenience — production code uses
// anypb.UnmarshalTo with the proper type registry.
func anyUnmarshalTo(a *anypb.Any, m proto.Message) error {
	if a == nil {
		return errors.New("nil any")
	}
	return proto.Unmarshal(a.GetValue(), m)
}

// ---- Tests ----

// TestIssue_FederatedPath_HydraRequestShape verifies the federated path
// registers the Hydra client with jwt-bearer + no JWKS, and the response
// carries NO key material.
func TestIssue_FederatedPath_HydraRequestShape(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)
	u.HydraClientNamePrefix = "kacho-sak-"
	u.AudiencePrefix = "https://example/api"

	in := IssueInput{
		ServiceAccountID: "sva_test",
		CreatedByUserID:  "usr_admin",
		TrustedSubjects: []domain.TrustedSubject{
			{
				Issuer:         "https://token.actions.githubusercontent.com",
				SubjectPattern: "^repo:acme/infra:ref:refs/heads/main$",
			},
		},
	}

	op, err := u.Execute(context.Background(), in)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil {
		t.Fatal("nil op")
	}
	waitForOp(t, ops)

	if !hydra.created {
		t.Fatal("Hydra CreateOAuthClient never called")
	}
	if got, want := hydra.gotReq.TokenEndpointAuthMethod, "none"; got != want {
		t.Errorf("TokenEndpointAuthMethod = %q, want %q", got, want)
	}
	if len(hydra.gotReq.GrantTypes) != 1 || hydra.gotReq.GrantTypes[0] != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("GrantTypes = %v, want [urn:ietf:params:oauth:grant-type:jwt-bearer]", hydra.gotReq.GrantTypes)
	}
	if hydra.gotReq.JWKS != nil {
		t.Errorf("federated client must NOT carry JWKS, got %+v", hydra.gotReq.JWKS)
	}
	if len(hydra.gotReq.Audience) != 1 || hydra.gotReq.Audience[0] != "https://example/api/sa/sva_test" {
		t.Errorf("Audience = %v", hydra.gotReq.Audience)
	}

	if !repo.insertOK {
		t.Fatal("repo.Insert not called")
	}
	if len(repo.inserted.TrustedSubjects) != 1 {
		t.Fatalf("TrustedSubjects len = %d, want 1", len(repo.inserted.TrustedSubjects))
	}
	if repo.inserted.PublicKeyPEM != "" || repo.inserted.KeyAlgorithm != "" {
		t.Errorf("federated row must not carry public_key_pem/key_algorithm, got %+v", repo.inserted)
	}

	if ops.lastResp == nil {
		t.Fatal("MarkDone response nil")
	}
	resp := &iamv1.IssueSAKeyResponse{}
	if err := anyUnmarshalTo(ops.lastResp, resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.PrivateKeyPem != "" || resp.PublicKeyPem != "" || resp.Algorithm != "" {
		t.Errorf("federated response must omit key material; got priv-len=%d pub-len=%d alg=%q",
			len(resp.PrivateKeyPem), len(resp.PublicKeyPem), resp.Algorithm)
	}
	if resp.ClientId != "hydra-cli-fake" {
		t.Errorf("ClientId = %q", resp.ClientId)
	}
}

// TestIssue_FederatedPath_InvalidTrustedSubject_Rejected — bad regex must
// surface as InvalidArgument before any Hydra/DB call.
func TestIssue_FederatedPath_InvalidTrustedSubject_Rejected(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test",
		CreatedByUserID:  "usr_admin",
		TrustedSubjects: []domain.TrustedSubject{
			{Issuer: "https://x", SubjectPattern: "(["}, // invalid RE2
		},
	})
	if grpcstatus.Code(err) != codes.InvalidArgument {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
	if hydra.created {
		t.Error("Hydra must not be called on validation failure")
	}
	if repo.insertOK {
		t.Error("repo must not be called on validation failure")
	}
}

// TestIssue_PrivateKeyJWT_Path_StillWorks — regression: empty
// TrustedSubjects keeps legacy private_key_jwt behaviour intact.
func TestIssue_PrivateKeyJWT_Path_StillWorks(t *testing.T) {
	repo := &stubSAClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	u := NewIssueSAKeyUseCase(repo, &stubTx{}, hydra, ops)

	_, err := u.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva_test",
		CreatedByUserID:  "usr_admin",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)

	if hydra.gotReq.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("legacy path must use private_key_jwt, got %q", hydra.gotReq.TokenEndpointAuthMethod)
	}
	if hydra.gotReq.JWKS == nil {
		t.Fatal("legacy path must carry JWKS")
	}
	if repo.inserted.PublicKeyPEM == "" || repo.inserted.KeyAlgorithm != "ES256" {
		t.Errorf("legacy row must carry public_key_pem + ES256; got pem-len=%d alg=%q",
			len(repo.inserted.PublicKeyPEM), repo.inserted.KeyAlgorithm)
	}
}

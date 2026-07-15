// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// usecase_test.go — unit-тесты use-case'ов UserTokenService на mock-портах.
// Зеркалит sa_keys usecase-тесты. Трассируются в account-tokens-tab-USR-*.
package user_tokens

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ---- Mocks ----

type stubUserClientRepo struct {
	inserted  domain.UserOAuthClient
	getRow    domain.UserOAuthClient
	getErr    error
	listRows  []domain.UserOAuthClient
	deleted   bool
	accountID domain.AccountID
}

// AccountForUser — резолвер account'а User (порт UserClientRepo). Дефолт —
// фиксированный account; тесты account_id-стемпинга подставляют свой.
func (s *stubUserClientRepo) AccountForUser(ctx context.Context, id domain.UserID) (domain.AccountID, error) {
	if s.accountID != "" {
		return s.accountID, nil
	}
	return "acc00000000000000001", nil
}

func (s *stubUserClientRepo) Get(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error) {
	return s.getRow, s.getErr
}
func (s *stubUserClientRepo) Insert(ctx context.Context, tx service.Tx, c domain.UserOAuthClient) (domain.UserOAuthClient, error) {
	s.inserted = c
	c.CreatedAt = time.Now().UTC()
	return c, nil
}
func (s *stubUserClientRepo) DeleteByID(ctx context.Context, tx service.Tx, id domain.UserOAuthClientID) error {
	s.deleted = true
	return nil
}
func (s *stubUserClientRepo) List(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.UserOAuthClient, string, error) {
	return s.listRows, "", nil
}

type stubHydra struct {
	gotReq  clients.CreateOAuthClientRequest
	deleted string
}

func (s *stubHydra) CreateOAuthClient(ctx context.Context, req clients.CreateOAuthClientRequest) (clients.HydraOAuthClient, error) {
	s.gotReq = req
	return clients.HydraOAuthClient{ClientID: "hydra-usr-fake"}, nil
}
func (s *stubHydra) DeleteOAuthClient(ctx context.Context, clientID string) error {
	s.deleted = clientID
	return nil
}

type stubTx struct{}

func (s *stubTx) Begin(ctx context.Context) (service.Tx, error) { return noopTx{}, nil }

type noopTx struct{}

func (noopTx) Commit(ctx context.Context) error   { return nil }
func (noopTx) Rollback(ctx context.Context) error { return nil }

// stubAudit — захватывает эмитированные audit-события.
type stubAudit struct {
	events []service.AuditEvent
}

func (a *stubAudit) EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error {
	a.events = append(a.events, ev)
	return nil
}

// stubOpsRepo — in-memory operations.Repo.
type stubOpsRepo struct {
	mu       sync.Mutex
	done     bool
	lastResp *anypb.Any
	lastErr  *rpcstatus.Status
}

func (s *stubOpsRepo) Create(ctx context.Context, op operations.Operation) error { return nil }
func (s *stubOpsRepo) CreateWithPrincipal(ctx context.Context, op operations.Operation, p operations.Principal) error {
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
func (s *stubOpsRepo) MarkError(ctx context.Context, id string, st *rpcstatus.Status) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.done = true
	s.lastErr = st
	return nil
}
func (s *stubOpsRepo) Cancel(ctx context.Context, id string) error { return nil }

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
	t.Fatal("operation did not complete in time")
}

// panicRedactor / errRedactor — зеркало sa_keys redaction-тестов.
type panicRedactor struct{}

func (panicRedactor) RedactResponseField(context.Context, string, []string) error {
	panic("redactor boom")
}

type errRedactor struct{ err error }

func (e errRedactor) RedactResponseField(context.Context, string, []string) error {
	return e.err
}

// ---- Tests ----

// TestIssue_HappyPath (USR-01): Execute → Operation; response несёт одноразовый
// private_key_pem + client_id + key_id + algorithm=ES256 + token{uoc…}. Hydra
// зарегистрирован private_key_jwt с owner=user_id.
func TestIssue_HappyPath(t *testing.T) {
	repo := &stubUserClientRepo{}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, hydra, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		Description:     "laptop CLI",
		TTLSeconds:      7776000,
		CreatedByUserID: "usr00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if op == nil {
		t.Fatal("nil operation")
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}

	var resp iamv1.IssueUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp.GetPrivateKeyPem() == "" {
		t.Error("private_key_pem must be present exactly once in the Issue response")
	}
	if resp.GetClientId() == "" {
		t.Error("client_id must be present")
	}
	if resp.GetAlgorithm() != "ES256" {
		t.Errorf("algorithm = %q, want ES256", resp.GetAlgorithm())
	}
	tok := resp.GetToken()
	if tok == nil || tok.GetId() == "" || tok.GetId()[:3] != "uoc" {
		t.Errorf("token.id = %q, want uoc prefix", tok.GetId())
	}
	if tok.GetUserId() != "usr00000000000000001" {
		t.Errorf("token.user_id = %q", tok.GetUserId())
	}
	if resp.GetKeyId() != tok.GetId() {
		t.Errorf("key_id %q != token.id %q (kid == uoc id)", resp.GetKeyId(), tok.GetId())
	}
	if tok.GetKeyAlgorithm() != "ES256" {
		t.Errorf("token.key_algorithm = %q", tok.GetKeyAlgorithm())
	}
	// Hydra registration shape.
	if hydra.gotReq.TokenEndpointAuthMethod != "private_key_jwt" {
		t.Errorf("hydra auth method = %q, want private_key_jwt", hydra.gotReq.TokenEndpointAuthMethod)
	}
	if hydra.gotReq.Owner != "usr00000000000000001" {
		t.Errorf("hydra owner = %q, want user id (principal maps to user:<id>)", hydra.gotReq.Owner)
	}
	if hydra.gotReq.JWKS == nil || len(hydra.gotReq.JWKS.Keys) != 1 {
		t.Error("hydra request must carry the public JWK")
	}
}

// TestIssue_ValidationErrors (USR-06/07): sync InvalidArgument до создания Operation.
func TestIssue_ValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		in   IssueInput
	}{
		{"malformed user id", IssueInput{UserID: "not-a-user", CreatedByUserID: "usr00000000000000001"}},
		{"empty created_by", IssueInput{UserID: "usr00000000000000001"}},
		{"negative ttl", IssueInput{UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001", TTLSeconds: -1}},
		{"description too long", IssueInput{UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001", Description: longStr(257)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			uc := NewIssueUserTokenUseCase(&stubUserClientRepo{}, &stubTx{}, &stubHydra{}, &stubOpsRepo{})
			_, err := uc.Execute(context.Background(), tc.in)
			if grpcstatus.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", grpcstatus.Code(err))
			}
		})
	}
}

// TestIssue_AuditNoSecret (USR-05/SEC-01): audit-событие issued эмитится без
// секретного материала.
func TestIssue_AuditNoSecret(t *testing.T) {
	repo := &stubUserClientRepo{}
	ops := &stubOpsRepo{}
	audit := &stubAudit{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops).WithAuditEmitter(audit)

	_, err := uc.Execute(context.Background(), IssueInput{
		UserID: "usr00000000000000001", CreatedByUserID: "usr00000000000000001", Description: "cli",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if len(audit.events) != 1 {
		t.Fatalf("audit events = %d, want 1", len(audit.events))
	}
	ev := audit.events[0]
	if ev.EventType != "iam.user_token.issued" {
		t.Errorf("event type = %q", ev.EventType)
	}
	for k, v := range ev.Payload {
		if s, ok := v.(string); ok {
			if k == "private_key_pem" || k == "client_secret" {
				t.Errorf("audit payload must never carry secret field %q", k)
			}
			_ = s
		}
	}
	if _, hasTok := ev.Payload["token_id"]; !hasTok {
		t.Error("audit payload must carry token_id")
	}
}

// TestRevoke_CrossUserIsolation (USR-08): токен другого user → NotFound, delete
// не выполняется.
func TestRevoke_CrossUserIsolation(t *testing.T) {
	repo := &stubUserClientRepo{
		getRow: domain.UserOAuthClient{
			ID:            "uoc00000000000000001",
			UserID:        "usr00000000000000002", // принадлежит другому user
			OAuthClientID: "hydra-x",
		},
	}
	ops := &stubOpsRepo{}
	uc := NewRevokeUserTokenUseCase(repo, &stubTx{}, &stubHydra{}, ops)

	_, err := uc.Execute(context.Background(), RevokeInput{
		UserID: "usr00000000000000001", TokenID: "uoc00000000000000001",
	})
	if err != nil {
		t.Fatalf("Execute (sync) unexpected err: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr == nil || codes.Code(ops.lastErr.Code) != codes.NotFound {
		t.Fatalf("worker must fail NotFound (cross-user isolation), got %+v", ops.lastErr)
	}
	if repo.deleted {
		t.Error("cross-user revoke must NOT delete the row")
	}
}

// TestRevoke_HappyPath (USR-04): удаляет строку + Hydra-клиента, response несёт
// token_id + revoked_at.
func TestRevoke_HappyPath(t *testing.T) {
	repo := &stubUserClientRepo{
		getRow: domain.UserOAuthClient{
			ID:            "uoc00000000000000009",
			UserID:        "usr00000000000000001",
			OAuthClientID: "hydra-usr-9",
		},
	}
	hydra := &stubHydra{}
	ops := &stubOpsRepo{}
	uc := NewRevokeUserTokenUseCase(repo, &stubTx{}, hydra, ops)

	_, err := uc.Execute(context.Background(), RevokeInput{
		UserID: "usr00000000000000001", TokenID: "uoc00000000000000009",
	})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	waitForOp(t, ops)
	if ops.lastErr != nil {
		t.Fatalf("worker error: %v", ops.lastErr)
	}
	if !repo.deleted {
		t.Error("row must be deleted")
	}
	if hydra.deleted != "hydra-usr-9" {
		t.Errorf("hydra client must be deleted, got %q", hydra.deleted)
	}
	var resp iamv1.RevokeUserTokenResponse
	if err := ops.lastResp.UnmarshalTo(&resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.GetTokenId() != "uoc00000000000000009" {
		t.Errorf("token_id = %q", resp.GetTokenId())
	}
	if resp.GetRevokedAt() == nil {
		t.Error("revoked_at must be set")
	}
}

// TestList (USR-03): sync read проксирует строки репо.
func TestList(t *testing.T) {
	repo := &stubUserClientRepo{listRows: []domain.UserOAuthClient{
		{ID: "uoc00000000000000001", UserID: "usr00000000000000001"},
		{ID: "uoc00000000000000002", UserID: "usr00000000000000001"},
	}}
	uc := NewListUserTokensUseCase(repo)
	rows, _, err := uc.Execute(context.Background(), ListInput{UserID: "usr00000000000000001"})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d, want 2", len(rows))
	}
}

// TestScheduleSecretRedact_PanicDoesNotCrashProcess — паника в detached
// redaction-goroutine ловится recover-guard'ом (IAM на critical path каждого Check).
func TestScheduleSecretRedact_PanicDoesNotCrashProcess(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	uc := &IssueUserTokenUseCase{opsRepo: &stubOpsRepo{done: true}, redactor: panicRedactor{}, logger: logger}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("redaction panic escaped: %v", r)
		}
	}()
	uc.scheduleSecretRedact(context.Background(), "iop_x")
	if !bytes.Contains(buf.Bytes(), []byte("redaction")) {
		t.Error("recovered panic must be logged")
	}
}

// TestScheduleSecretRedact_ErrorIsLogged — провал RedactResponseField логируется на
// Error (застрявший plaintext секрет обязан быть обнаружим).
func TestScheduleSecretRedact_ErrorIsLogged(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError}))
	uc := &IssueUserTokenUseCase{opsRepo: &stubOpsRepo{done: true}, redactor: errRedactor{err: errors.New("update failed")}, logger: logger}
	uc.scheduleSecretRedact(context.Background(), "iop_x")
	if !bytes.Contains(buf.Bytes(), []byte("redaction failed")) {
		t.Error("redaction error must be logged on Error, not silently discarded")
	}
}

func longStr(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a'
	}
	return string(b)
}

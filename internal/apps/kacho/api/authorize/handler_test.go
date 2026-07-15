// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// handler_test.go — gRPC-handler unit tests for AuthorizeService.
package authorize

import (
	"context"
	stderrors "errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// stubFGA — minimal RelationQueries mock for handler tests.
type stubFGA struct {
	check bool
	// lastRelation records the relation of the most recent CheckWithContext
	// call so tests can assert the resolved/override relation reached FGA.
	lastRelation string
	// relations records every relation seen (batch fan-out order).
	relations []string
}

func (s *stubFGA) CheckWithContext(ctx context.Context, subject, relation, object string, ctxMap map[string]any) (bool, error) {
	s.lastRelation = relation
	s.relations = append(s.relations, relation)
	return s.check, nil
}
func (s *stubFGA) ListObjects(ctx context.Context, subject, relation, objectType string, ctxMap map[string]any, max int) ([]string, error) {
	return []string{"x", "y"}, nil
}
func (s *stubFGA) ListSubjects(ctx context.Context, objectType, objectID, relation string, ps int, pt string) ([]string, string, error) {
	return []string{"user:a", "user:b"}, "", nil
}
func (s *stubFGA) Expand(ctx context.Context, objectType, objectID, relation string) (*clients.ExpandTree, error) {
	return &clients.ExpandTree{Leaves: []string{"user:a"}}, nil
}
func (s *stubFGA) ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

func newHandler(check bool) *Handler {
	h, _ := newHandlerWithStub(check)
	return h
}

// newHandlerWithStub returns the handler plus the underlying stubFGA so tests
// can inspect which relation reached the FGA Check.
func newHandlerWithStub(check bool) (*Handler, *stubFGA) {
	stub := &stubFGA{check: check}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: stub,
		ModelID:   "test-model",
	})
	// whoAmI is required by the handler; tests that don't exercise WhoAmI pass
	// a use-case with nil deps — its Execute() returns Unavailable via the
	// documented defensive guards rather than panicking.
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)), stub
}

func TestHandler_Check_AllowedHappyPath(t *testing.T) {
	h := newHandler(true)
	resp, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_alice",
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_x"},
		Action:   "vpc.networks.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected allowed")
	}
	if resp.AuthorizationModelId != "test-model" {
		t.Errorf("model id echo: %q", resp.AuthorizationModelId)
	}
	if resp.CheckedAt == nil {
		t.Errorf("expected CheckedAt timestamp")
	}
	// Wave T conformance: proto-response timestamp truncated to whole seconds
	// (api-conventions; routed through shared.TimestampProto).
	if n := resp.GetCheckedAt().AsTime().Nanosecond(); n != 0 {
		t.Errorf("CheckedAt sub-second leaked: nanos=%d, want 0", n)
	}
}

func TestHandler_Check_InvalidArgumentSubject(t *testing.T) {
	h := newHandler(true)
	_, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Resource: &iamv1.ResourceRef{Type: "x", Id: "y"},
		Action:   "x.x.x",
	})
	if err == nil {
		t.Fatalf("expected error")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument; got %v: %s", st.Code(), st.Message())
	}
}

func TestHandler_BatchCheck_OrderPreserved(t *testing.T) {
	h := newHandler(true)
	resp, err := h.BatchCheck(context.Background(), &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{Subject: "user:a", Resource: &iamv1.ResourceRef{Type: "x", Id: "1"}, Action: "x.x.list"},
			{Subject: "user:b", Resource: &iamv1.ResourceRef{Type: "x", Id: "2"}, Action: "x.x.list"},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.Responses) != 2 {
		t.Fatalf("expected 2; got %d", len(resp.Responses))
	}
	if !resp.Responses[0].Allowed || !resp.Responses[1].Allowed {
		t.Errorf("both should be allowed")
	}
}

// TestHandler_BatchCheck_ForwardsRequiredRelation — M2: a batch item carrying
// an explicit required_relation must be honored verbatim, exactly like the
// single Check. The catalog override (e.g. admin-only RPC mapped to
// system_admin) must NOT be silently dropped on the batch path. Here the verb
// "list" would derive `viewer`, but the explicit override is "system_admin";
// the FGA Check MUST be invoked with "system_admin", proving the override was
// forwarded (and not the auto-derived viewer, which would slip admin gating).
func TestHandler_BatchCheck_ForwardsRequiredRelation(t *testing.T) {
	h, stub := newHandlerWithStub(true)
	_, err := h.BatchCheck(context.Background(), &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{
				Subject:          "user:a",
				Resource:         &iamv1.ResourceRef{Type: "x", Id: "1"},
				Action:           "x.x.list",     // would derive "viewer"
				RequiredRelation: "system_admin", // explicit override must win
			},
		},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(stub.relations) != 1 {
		t.Fatalf("expected exactly 1 FGA Check; got %v", stub.relations)
	}
	if stub.relations[0] != "system_admin" {
		t.Errorf("BatchCheck must forward required_relation to FGA; got relation %q (override dropped → derived viewer)", stub.relations[0])
	}
}

func TestHandler_ListObjects_InvalidAction(t *testing.T) {
	h := newHandler(true)
	_, err := h.ListObjects(context.Background(), &iamv1.ListObjectsRequest{
		Subject: "user:x", ResourceType: "y", Action: "bogus",
	})
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("expected InvalidArgument; got %v: %s", st.Code(), st.Message())
	}
}

func TestHandler_ListSubjects_Filter(t *testing.T) {
	h := newHandler(true)
	resp, err := h.ListSubjects(context.Background(), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "x", Id: "1"},
		Action:   "x.x.list",
		// All subjects start with "user:" — explicit filter for "user" still returns both.
		SubjectTypeFilter: "user",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(resp.Subjects) != 2 {
		t.Errorf("expected 2 subjects; got %d (%v)", len(resp.Subjects), resp.Subjects)
	}
	for _, s := range resp.Subjects {
		if !strings.HasPrefix(s, "user:") {
			t.Errorf("filter dropped non-user; got %q", s)
		}
	}
}

// fgaSecret — sensitive OpenFGA transport detail (store id, backend endpoint)
// a failing backend call could embed. It must NEVER reach the client-facing
// gRPC status message (CWE-209: information exposure through error message).
const fgaSecret = "openfga-store-id=01ABCDEF backend=http://fga.internal:8080"

// errFGA — an Authorizer stub whose query methods fail with a backend error
// carrying fgaSecret, to prove the handler collapses the raw text to a fixed,
// schema-free message instead of forwarding err.Error() verbatim.
type errFGA struct{ stubFGA }

func (e *errFGA) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return false, stderrors.New(fgaSecret)
}
func (e *errFGA) ListObjects(context.Context, string, string, string, map[string]any, int) ([]string, error) {
	return nil, stderrors.New(fgaSecret)
}
func (e *errFGA) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", stderrors.New(fgaSecret)
}
func (e *errFGA) Expand(context.Context, string, string, string) (*clients.ExpandTree, error) {
	return nil, stderrors.New(fgaSecret)
}

func newHandlerWithAuthorizer(a service.Authorizer) *Handler {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: a,
		ModelID:   "test-model",
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil))
}

// TestHandler_Authorize_RedactsBackendError — a failing OpenFGA backend call
// must surface as codes.Unavailable with the FIXED text "authorization backend
// unavailable"; the raw wrapped backend detail (store id / endpoint) must never
// appear in the client-facing message.
func TestHandler_Authorize_RedactsBackendError(t *testing.T) {
	h := newHandlerWithAuthorizer(&errFGA{})
	cases := []struct {
		name string
		call func() error
	}{
		{"ListObjects", func() error {
			_, err := h.ListObjects(context.Background(), &iamv1.ListObjectsRequest{
				Subject: "user:x", ResourceType: "y", Action: "x.x.list",
			})
			return err
		}},
		{"ListSubjects", func() error {
			_, err := h.ListSubjects(context.Background(), &iamv1.ListSubjectsRequest{
				Resource: &iamv1.ResourceRef{Type: "x", Id: "1"}, Action: "x.x.list",
			})
			return err
		}},
		{"ExpandRelations", func() error {
			_, err := h.ExpandRelations(context.Background(), &iamv1.ExpandRelationsRequest{
				Resource: &iamv1.ResourceRef{Type: "x", Id: "1"}, Relation: "viewer",
			})
			return err
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.call()
			if err == nil {
				t.Fatalf("expected error")
			}
			st, _ := status.FromError(err)
			if st.Code() != codes.Unavailable {
				t.Errorf("code = %v; want Unavailable", st.Code())
			}
			if strings.Contains(st.Message(), fgaSecret) {
				t.Errorf("LEAK: client message %q contains raw backend detail", st.Message())
			}
			if st.Message() != "authorization backend unavailable" {
				t.Errorf("message = %q; want fixed redacted text", st.Message())
			}
		})
	}
}

// TestHandler_BatchCheck_RedactsBackendUnavailable — when the FGA backend is
// unavailable mid-batch, the failing check must surface as codes.Unavailable
// with the FIXED "authorization backend unavailable" text (mirroring the
// standalone Check sibling), NOT as a per-item Allowed=false whose deny_reason
// echoes the raw transport error (store id / endpoint leak) nor as a misleading
// permanent Internal/PermissionDenied.
func TestHandler_BatchCheck_RedactsBackendUnavailable(t *testing.T) {
	h := newHandlerWithAuthorizer(&errFGA{})
	resp, err := h.BatchCheck(context.Background(), &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{Subject: "user:x", Resource: &iamv1.ResourceRef{Type: "y", Id: "1"}, Action: "x.x.list"},
		},
	})
	if err == nil {
		t.Fatalf("expected whole-batch Unavailable; got resp=%v err=nil", resp)
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable {
		t.Errorf("code = %v; want Unavailable (retryable, fail-closed)", st.Code())
	}
	if strings.Contains(st.Message(), fgaSecret) {
		t.Errorf("LEAK: client message %q contains raw backend detail", st.Message())
	}
	if st.Message() != "authorization backend unavailable" {
		t.Errorf("message = %q; want fixed redacted text", st.Message())
	}
}

func TestHandler_Expand_ReturnsTree(t *testing.T) {
	h := newHandler(true)
	resp, err := h.ExpandRelations(context.Background(), &iamv1.ExpandRelationsRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_x"},
		Relation: "viewer",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if resp.Resource.GetType() != "vpc_network" || resp.Resource.GetId() != "vpcn_x" {
		t.Errorf("resource echo mismatch")
	}
	if resp.Tree == nil || len(resp.Tree.Leaves) == 0 {
		t.Errorf("expected leaves; got %+v", resp.Tree)
	}
}

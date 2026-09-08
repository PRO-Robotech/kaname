// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// handler_test.go — gRPC-handler unit tests for AuthorizeService.
package authorize

import (
	"context"
	stderrors "errors"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// stubVerdict — дублёр ИСТОЧНИКА ВЕРДИКТА (`service.Authorizer`) для проб транспорта.
//
// Поверхность — ровно та, что объявляет порт после снятия внешнего движка: вопрос
// об объекте, перечисление субъектов страницей, основания права, уже имеющиеся
// отношения субъекта. Ни перечисления объектов, ни чтения кортежей, ни сведений о
// хранилище здесь нет — их нет и у настоящего.
//
// Mutex-guarded: BatchCheck resolves its items concurrently, so a fixture safe
// only for a sequential caller reports its OWN unsafety under -race as if it were
// the handler's.
type stubVerdict struct {
	check bool

	mu sync.Mutex
	// relations records every relation seen. Under a concurrent batch this is
	// COMPLETION order, not request order, so it answers "which relations reached
	// the verdict source" and must NOT carry a per-item ordering assertion. The
	// ordering that is contractual is the order of RESPONSES, asserted from the
	// response itself in TestHandler_BatchCheck_OrderPreserved.
	relations []string
}

func (s *stubVerdict) CheckWithContext(_ context.Context, _, relation, _ string, _ map[string]any) (bool, error) {
	s.mu.Lock()
	s.relations = append(s.relations, relation)
	s.mu.Unlock()
	return s.check, nil
}

func (s *stubVerdict) ListSubjects(_ context.Context, _, _, _ string, _ int, _ string) ([]string, string, error) {
	return []string{"user:a", "user:b"}, "", nil
}

func (s *stubVerdict) Sources(_ context.Context, _, _, _ string) ([]string, error) {
	return []string{"user:a"}, nil
}

func (s *stubVerdict) DirectRelations(_ context.Context, _, _, _ string, _ int) ([]string, error) {
	return nil, nil
}

func newHandler(check bool) *Handler {
	h, _ := newHandlerWithStub(check)
	return h
}

// Every RPC below is invoked as a verified cluster-internal module PDP peer
// (moduleCertCtx). A policy-decision query carries no tenant principal, and what
// makes it legitimate is the verified module certificate on the internal
// listener — not the absence of a principal. Naming that keeps these
// transport-shaping tests on the production-posture path rather than the
// insecure-stand opt-out.

// newHandlerWithStub returns the handler plus the underlying stubVerdict so tests
// can inspect which relation reached the verdict source.
func newHandlerWithStub(check bool) (*Handler, *stubVerdict) {
	stub := &stubVerdict{check: check}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: stub,
	})
	// whoAmI is required by the handler; tests that don't exercise WhoAmI pass
	// a use-case with nil deps — its Execute() returns Unavailable via the
	// documented defensive guards rather than panicking.
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)), stub
}

func TestHandler_Check_AllowedHappyPath(t *testing.T) {
	h := newHandler(true)
	resp, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
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
	_, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
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
	resp, err := h.BatchCheck(moduleCertCtx(), &iamv1.BatchAuthorizeCheckRequest{
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
// the verdict source MUST be asked about "system_admin", proving the override was
// forwarded (and not the auto-derived viewer, which would slip admin gating).
func TestHandler_BatchCheck_ForwardsRequiredRelation(t *testing.T) {
	h, stub := newHandlerWithStub(true)
	_, err := h.BatchCheck(moduleCertCtx(), &iamv1.BatchAuthorizeCheckRequest{
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
		t.Fatalf("expected exactly 1 verdict query; got %v", stub.relations)
	}
	if stub.relations[0] != "system_admin" {
		t.Errorf("BatchCheck must forward required_relation; got relation %q (override dropped → derived viewer)", stub.relations[0])
	}
}

func TestHandler_ListSubjects_Filter(t *testing.T) {
	h := newHandler(true)
	resp, err := h.ListSubjects(moduleCertCtx(), &iamv1.ListSubjectsRequest{
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

// backendSecret — чувствительная деталь ХРАНИЛИЩА, которую отказавший вызов может
// нести в тексте ошибки (адрес, имя базы, пользователь). Она НИКОГДА не должна
// попасть в клиентское сообщение gRPC-статуса (CWE-209).
//
// Со снятием внешнего движка предмет проверки не изменился, изменился только
// источник текста: теперь под вердиктом лежит СВОЯ база, и её сообщение об отказе
// несёт координаты подключения ровно так же, как прежде их нёс адрес движка.
const backendSecret = "host=pg.internal:5432 user=kaname db=kaname"

// errVerdict — дублёр источника вердикта, чьи запросы падают ошибкой с
// backendSecret: доказывает, что край сводит сырой текст к фиксированному
// сообщению, а не пересылает `err.Error()` дословно.
type errVerdict struct{ stubVerdict }

func (e *errVerdict) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return false, stderrors.New(backendSecret)
}

func (e *errVerdict) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", stderrors.New(backendSecret)
}

func (e *errVerdict) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, stderrors.New(backendSecret)
}

func newHandlerWithAuthorizer(a service.Authorizer) *Handler {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: a,
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil))
}

// TestHandler_Authorize_RedactsBackendError — отказавший вызов к источнику
// вердикта обязан выйти наружу как codes.Unavailable с ФИКСИРОВАННЫМ текстом
// "authorization backend unavailable"; сырая деталь подключения не должна
// появиться в клиентском сообщении никогда.
func TestHandler_Authorize_RedactsBackendError(t *testing.T) {
	h := newHandlerWithAuthorizer(&errVerdict{})
	cases := []struct {
		name string
		call func() error
	}{
		{"ListSubjects", func() error {
			_, err := h.ListSubjects(moduleCertCtx(), &iamv1.ListSubjectsRequest{
				Resource: &iamv1.ResourceRef{Type: "x", Id: "1"}, Action: "x.x.list",
			})
			return err
		}},
		// Тип назван так, как его знает модель: ExpandRelations отвергает пару,
		// которой тип не объявляет, ТЕРМИНАЛЬНО и до обращения к источнику
		// (#1290). С выдуманным типом проба спрашивала бы про порядок отказов, а
		// её предмет — редактирование текста НЕДОСТУПНОГО источника.
		{"ExpandRelations", func() error {
			_, err := h.ExpandRelations(moduleCertCtx(), &iamv1.ExpandRelationsRequest{
				Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_1"}, Relation: "viewer",
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
			if strings.Contains(st.Message(), backendSecret) {
				t.Errorf("LEAK: client message %q contains raw backend detail", st.Message())
			}
			if st.Message() != "authorization backend unavailable" {
				t.Errorf("message = %q; want fixed redacted text", st.Message())
			}
		})
	}
}

// TestHandler_BatchCheck_RedactsBackendUnavailable — when the verdict source is
// unavailable mid-batch, the failing check must surface as codes.Unavailable
// with the FIXED "authorization backend unavailable" text (mirroring the
// standalone Check sibling), NOT as a per-item Allowed=false whose deny_reason
// echoes the raw transport error nor as a misleading permanent
// Internal/PermissionDenied.
func TestHandler_BatchCheck_RedactsBackendUnavailable(t *testing.T) {
	h := newHandlerWithAuthorizer(&errVerdict{})
	resp, err := h.BatchCheck(moduleCertCtx(), &iamv1.BatchAuthorizeCheckRequest{
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
	if strings.Contains(st.Message(), backendSecret) {
		t.Errorf("LEAK: client message %q contains raw backend detail", st.Message())
	}
	if st.Message() != "authorization backend unavailable" {
		t.Errorf("message = %q; want fixed redacted text", st.Message())
	}
}

func TestHandler_Expand_ReturnsTree(t *testing.T) {
	h := newHandler(true)
	resp, err := h.ExpandRelations(moduleCertCtx(), &iamv1.ExpandRelationsRequest{
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

// BatchCheckWithContext — ПАКЕТНАЯ ДВЕРЬ К ТОМУ ЖЕ ОРАКУЛУ, из которого отвечает
// пообъектная. Своего ответа у неё нет намеренно: дублёр, отвечающий партии не
// то, что отвечает по одному, скрыл бы ровно то расхождение, ради которого он и
// подставляется.
func (s *stubVerdict) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := s.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// DirectRelationsMany — та же диагностика о странице, тем же оракулом.
func (s *stubVerdict) DirectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string, limit int) (map[string][]string, error) {
	out := make(map[string][]string, len(objectIDs))
	for _, objectID := range objectIDs {
		rels, err := s.DirectRelations(ctx, subject, objectType, objectID, limit)
		if err != nil {
			return nil, err
		}
		if len(rels) > 0 {
			out[objectID] = rels
		}
	}
	return out, nil
}

// BatchCheckWithContext — ПАКЕТНАЯ ДВЕРЬ К ТОМУ ЖЕ ОРАКУЛУ, из которого отвечает
// пообъектная. Своего ответа у неё нет намеренно: дублёр, отвечающий партии не
// то, что отвечает по одному, скрыл бы ровно то расхождение, ради которого он и
// подставляется.
func (e *errVerdict) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := e.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// DirectRelationsMany — та же диагностика о странице, тем же оракулом.
func (e *errVerdict) DirectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string, limit int) (map[string][]string, error) {
	out := make(map[string][]string, len(objectIDs))
	for _, objectID := range objectIDs {
		rels, err := e.DirectRelations(ctx, subject, objectType, objectID, limit)
		if err != nil {
			return nil, err
		}
		if len(rels) > 0 {
			out[objectID] = rels
		}
	}
	return out, nil
}

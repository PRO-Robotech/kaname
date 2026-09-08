// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// authorityStub — configurable authzguard.RelationChecker for the inner
// caller-authority gate. allow[relation+"|"+object] == true grants that tuple.
type authorityStub struct {
	allow map[string]bool
	err   error
	calls int
}

func (a *authorityStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	a.calls++
	if a.err != nil {
		return false, a.err
	}
	return a.allow[relation+"|"+object], nil
}

func newHandlerWithAuthority(svcCheck bool, auth *authorityStub) *Handler {
	stub := &stubVerdict{check: svcCheck}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: stub,
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)).WithCallerAuthority(auth)
}

// newHandlerWithAuthorityProd builds the handler in the DEFAULT posture, which
// fails closed for an anonymous/system principal carrying no verified module
// cert (the public-listener bypass). It is spelled out explicitly here so the
// production intent stays readable at the call sites, even though the same
// posture is now what an unset handler already has.
func newHandlerWithAuthorityProd(svcCheck bool, auth *authorityStub) *Handler {
	return newHandlerWithAuthority(svcCheck, auth).WithInsecureAnonymousPeer(false)
}

// newHandlerWithAuthorityInsecure builds the handler for a stand WITHOUT mTLS,
// which must opt in explicitly.
func newHandlerWithAuthorityInsecure(svcCheck bool, auth *authorityStub) *Handler {
	return newHandlerWithAuthority(svcCheck, auth).WithInsecureAnonymousPeer(true)
}

// moduleCertCtx injects a verified mTLS module-cert SAN into ctx, simulating a
// cluster-internal module PDP peer call over the :9091 internal listener.
func moduleCertCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-vpc", true)
}

func userCtx(id string) context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: id, Type: "user"})
}

func requireDenied(t *testing.T, err error) {
	t.Helper()
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("want PermissionDenied, got %v", err)
	}
}

// TestCallerAuthority_Check_ForeignSubject_Denied — the confused-deputy case:
// a tenant principal (alice) queries a decision about a DIFFERENT subject (bob)
// on a resource it does not administer → PermissionDenied, without ever reaching
// the FGA decision.
func TestCallerAuthority_Check_ForeignSubject_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.get",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_Check_SelfQuery_Allowed — a tenant may always ask about
// itself; the gate lets the decision proceed.
func TestCallerAuthority_Check_SelfQuery_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	resp, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_alice",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("self-query must pass the gate: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to be allowed")
	}
	if auth.calls != 1 { // one cluster-admin Check (self path short-circuits before it? no — self returns first)
		// self-query returns before any authority Check
		if auth.calls != 0 {
			t.Errorf("self-query should not hit the authority checker; calls=%d", auth.calls)
		}
	}
}

// TestCallerAuthority_Check_ClusterAdmin_Allowed — a cluster-admin may query any
// subject/resource.
func TestCallerAuthority_Check_ClusterAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"system_admin|cluster:cluster_root": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_admin"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("cluster-admin must pass the gate: %v", err)
	}
}

// TestCallerAuthority_Check_ResourceAdmin_Allowed — a tenant that holds `admin`
// on the queried resource may ask about other subjects on it.
func TestCallerAuthority_Check_ResourceAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"admin|account:acc_a": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("resource-admin must pass the gate: %v", err)
	}
}

// TestCallerAuthority_Anonymous_PassesThrough — on a stand that EXPLICITLY opted
// out of mTLS there is no certificate to tell the two listeners apart, so a call
// with no principal is not gated here and the decision proceeds. The opt-out is
// what makes this legal; without it the same call is denied (see
// caller_authority_default_posture_test.go).
func TestCallerAuthority_Anonymous_PassesThrough(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityInsecure(true, auth)
	resp, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("anonymous module PDP call must pass through: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to proceed")
	}
	if auth.calls != 0 {
		t.Errorf("anonymous path must not hit the authority checker; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_Anonymous_ProdMode_NoCert_Denied — the public-listener
// bypass (CWE-863). In production an anonymous/system caller that presents NO
// verified module cert (i.e. reached the PUBLIC :9090 listener, which has no
// module-cert floor) must be DENIED, not blanket-allowed. Before the fail-closed
// fix this Check returned the underlying decision (fail-open oracle).
func TestCallerAuthority_Anonymous_ProdMode_NoCert_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	_, err := h.Check(context.Background(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_victim",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	requireDenied(t, err)
	if auth.calls != 0 {
		t.Errorf("denied public anonymous call must not reach the FGA oracle; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_Anonymous_ProdMode_NoCert_ListSubjects_Denied — the same
// fail-closed posture for the enumeration RPC on the public listener.
func TestCallerAuthority_Anonymous_ProdMode_NoCert_ListSubjects_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	_, err := h.ListSubjects(context.Background(), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.listAccessBindings",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_Anonymous_ProdMode_VerifiedModuleCert_Allowed — a GENUINE
// cluster-internal module PDP peer (verified mTLS module SAN on :9091) still
// passes the inner gate in production; the internal listener's verified-cert
// floor governs it. This is the path the fail-closed fix must NOT break.
func TestCallerAuthority_Anonymous_ProdMode_VerifiedModuleCert_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthorityProd(true, auth)
	resp, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_any"},
		Action:   "iam.accounts.get",
	})
	if err != nil {
		t.Fatalf("verified module PDP peer must pass through in prod: %v", err)
	}
	if !resp.GetAllowed() {
		t.Errorf("expected the underlying decision to proceed for the module peer")
	}
	if auth.calls != 0 {
		t.Errorf("module-peer path must not hit the authority checker; calls=%d", auth.calls)
	}
}

// TestCallerAuthority_ListSubjects_NoAuthority_Denied — enumerating who can act
// on a resource requires administering it; a bare tenant is denied.
func TestCallerAuthority_ListSubjects_NoAuthority_Denied(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListSubjects(userCtx("usr_alice"), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"},
		Action:   "iam.accounts.listAccessBindings",
	})
	requireDenied(t, err)
}

// TestCallerAuthority_ListSubjects_ResourceAdmin_Allowed — a resource-admin may
// enumerate its resource's subjects.
func TestCallerAuthority_ListSubjects_ResourceAdmin_Allowed(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{
		"admin|account:acc_a": true,
	}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.ListSubjects(userCtx("usr_alice"), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"},
		Action:   "iam.accounts.listAccessBindings",
	})
	if err != nil {
		t.Fatalf("resource-admin ListSubjects must pass the gate: %v", err)
	}
}

// TestCallerAuthority_BatchCheck_OneForeign_DeniesBatch — a single unauthorized
// item denies the whole batch.
func TestCallerAuthority_BatchCheck_OneForeign_DeniesBatch(t *testing.T) {
	auth := &authorityStub{allow: map[string]bool{}}
	h := newHandlerWithAuthority(true, auth)
	_, err := h.BatchCheck(userCtx("usr_alice"), &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{Subject: "user:usr_alice", Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_a"}, Action: "iam.accounts.get"},
			{Subject: "user:usr_bob", Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_victim"}, Action: "iam.accounts.get"},
		},
	})
	requireDenied(t, err)
}

// ── #665: тот же класс на внутреннем страже AuthorizeService ─────────────────

// TestCallerAuthority_StoreOutage_IsUnavailableNotDenied — «хранилище отношений
// не ответило» обязано приезжать НЕДОСТУПНОСТЬЮ, а не отказом в правах.
//
// Утверждается наблюдаемое: код, который получает вызывающий, на трёх исходах
// одного и того же вопроса. Разница между двумя отказами — обещание вызывающему:
// отказ в правах говорит «повтор бессмыслен» (решение зависит от тройки субъект
// / отношение / объект, и одинаковый повтор не меняет ни одного из трёх),
// недоступность о правах не говорит ничего.
//
// Fail-closed не ослабляется ни на йоту: во всех трёх случаях, кроме
// разрешающего, вызов отвергнут.
func TestCallerAuthority_StoreOutage_IsUnavailableNotDenied(t *testing.T) {
	req := func() *iamv1.AuthorizeCheckRequest {
		return &iamv1.AuthorizeCheckRequest{
			Subject:  "user:usr_bob",
			Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_x"},
			Action:   "iam.accounts.get",
		}
	}

	t.Run("хранилище не ответило", func(t *testing.T) {
		auth := &authorityStub{err: errors.New("relation store unreachable")}
		h := newHandlerWithAuthorityProd(true, auth)
		_, err := h.Check(userCtx("usr_alice"), req())
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("want Unavailable, got %v", err)
		}
	})

	// Отрицание: хранилище ОТВЕТИЛО «нет» — это решение, и повтор его не изменит.
	t.Run("явный отказ", func(t *testing.T) {
		auth := &authorityStub{allow: map[string]bool{}}
		h := newHandlerWithAuthorityProd(true, auth)
		_, err := h.Check(userCtx("usr_alice"), req())
		requireDenied(t, err)
	})

	// Положительный контроль: право есть → проходит. Без него оба отрицания выше
	// зеленели бы и на страже, который отвергает всё.
	t.Run("право есть", func(t *testing.T) {
		auth := &authorityStub{allow: map[string]bool{"admin|account:acc_x": true}}
		h := newHandlerWithAuthorityProd(true, auth)
		if _, err := h.Check(userCtx("usr_alice"), req()); err != nil {
			t.Fatalf("вызывающий с правом обязан пройти, получено %v", err)
		}
	})
}

// TestCallerAuthority_StoreOutageOnTheSuperGateAlone_IsUnavailable — вопрос об
// администраторе кластера задаётся ПЕРВЫМ, и его неполадка тоже не отказ.
//
// Проба стоит отдельно, потому что путь другой: подстановочный идентификатор
// ресурса выводит запрос из полосы «право на этот объект» (спрашивать не о чем),
// и неполадка сверх-гейта остаётся ЕДИНСТВЕННЫМ вопросом, оставшимся без ответа.
// Без этой пробы починка закрыла бы только ту половину, где объект назван, а
// вторая продолжала бы отвечать терминальным отказом на мигание хранилища.
func TestCallerAuthority_StoreOutageOnTheSuperGateAlone_IsUnavailable(t *testing.T) {
	auth := &authorityStub{err: errors.New("relation store unreachable")}
	h := newHandlerWithAuthorityProd(true, auth)

	_, err := h.Check(userCtx("usr_alice"), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_bob",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "*"},
		Action:   "iam.accounts.get",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("want Unavailable, got %v", err)
	}
}

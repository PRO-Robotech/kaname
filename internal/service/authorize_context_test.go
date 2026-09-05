// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorize_context_test.go — условный контекст, доезжающий до решающей стороны,
// обязан быть СЕРВЕРНЫМ в части свойств принципала и соединения.
//
// AuthorizeService выставлен на ПУБЛИЧНОМ листенере, а внутренний страж
// caller-authority разрешает вопрос о себе, — значит арендатор иначе мог бы
// прислать в теле запроса acr_value / amr_claims / mfa_at / client_ip и
// удовлетворить условие mfa_fresh / source_ip_in_range, НЕ обладая заявленной
// гарантией (CWE-807 / security.md «решение о доступе не опирается на
// недоверенный ввод»). Пробы закрепляют, что служба вырезает эти ключи и до
// решения доходят только серверные значения (current_time, доверенный acr).
//
// Предмет от смены решающей стороны не изменился: вырезание идёт ДО того, как
// контекст кому-либо передан, поэтому проба утверждает про службу, а не про то,
// кто отвечает за ней.
package service

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
)

func TestAuthorize_Check_StripsForgedSecurityContext(t *testing.T) {
	m := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m})

	_, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.update",
		Context: map[string]any{
			// Forged principal/connection assurance a self-querying tenant could send.
			"acr_value":          "3",
			"amr_claims":         []any{"webauthn"},
			"mfa_at":             int64(9_999_999_999),
			"client_ip":          "10.0.0.1",
			"source_ip":          "10.0.0.1",
			"valid_until":        int64(9_999_999_999),
			"device_attestation": "trusted",
			// A genuinely request-scoped, non-security attribute is allowed through.
			"tenant_hint": "keep-me",
		},
	})
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	cc := m.lastCondCtx
	if cc == nil {
		t.Fatal("no condCtx captured")
	}
	for _, k := range []string{"amr_claims", "mfa_at", "client_ip", "source_ip", "valid_until", "device_attestation"} {
		if _, ok := cc[k]; ok {
			t.Errorf("server-authoritative key %q must be stripped from client context, got %v", k, cc[k])
		}
	}
	// No trusted acr in ctx → the forged acr_value must NOT survive.
	if v, ok := cc["acr_value"]; ok {
		t.Errorf("forged acr_value must not reach the relation store without a trusted source, got %v", v)
	}
	// current_time is always server-forced.
	if _, ok := cc["current_time"]; !ok {
		t.Error("current_time must be server-forced into condCtx")
	}
	// Non-security request-scoped attributes pass through unchanged.
	if cc["tenant_hint"] != "keep-me" {
		t.Errorf("non-security attribute dropped: %v", cc["tenant_hint"])
	}
}

func TestAuthorize_Check_OverlaysTrustedACROverForgedValue(t *testing.T) {
	m := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: m})

	// The interceptor chain places the FD-4-trusted acr on ctx.
	ctx := grpcsrv.WithTrustedACR(context.Background(), "2", true)
	_, err := svc.Check(ctx, CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.update",
		Context:  map[string]any{"acr_value": "3"}, // forged higher assurance
	})
	if err != nil {
		t.Fatalf("Check err: %v", err)
	}
	if got := m.lastCondCtx["acr_value"]; got != "2" {
		t.Errorf("acr_value = %v; want the trusted ctx value \"2\", never the forged \"3\"", got)
	}
}

// Здесь стояла третья проба — та же санитария условного контекста на пути
// ПЕРЕЧИСЛЕНИЯ ОБЪЕКТОВ. Снята вместе с предметом: перечисление снято с
// контракта (оно отвечало ограниченным префиксом без продолжения, см.
// authorize_service.go). Оставлять её было бы утверждением о пути, которого нет.

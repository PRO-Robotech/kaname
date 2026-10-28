// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// check_context_authn_args_ignored_test.go — доводы о своей аутентификации,
// присланные в `context` вопроса Check, на исход НЕ влияют (kaname#801).
//
// Предмет — ИСХОД ответа, а не состав переданного словаря: вопрос с доводами
// аутентификации в `context` и тот же вопрос без них получают одинаковые
// `allowed` и `denyReasons`. Состав словаря у решающей стороны уже держит проба
// службы (`service/authorize_context_test.go`); здесь утверждается то, что видит
// спросивший, — через транспорт, Check и пункт BatchCheck.
//
// Дублёр источника вердикта сделан НАМЕРЕННО ДОВЕРЧИВЫМ: он разрешает, если в
// условном контексте есть хоть один довод о способе, уровне, моменте
// аутентификации или о соединении. Настоящая форма требует всех доводов условия
// разом; доверчивый дублёр делает пробу чувствительной к утечке КАЖДОГО ключа
// по отдельности, а не только всей их совокупности.
//
// Законный близнец — доверенный уровень, положенный цепочкой перехватчиков в
// контекст вызова: он доезжает до решающей стороны и меняет исход. Без
// близнеца проба зеленела бы и на дублёре, который условного контекста не
// читает вовсе.
package authorize

import (
	"context"
	"slices"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// authnArgsServerNow — часы службы в пробе: подделанное «сейчас» отличимо от них.
var authnArgsServerNow = time.Unix(1_900_000_000, 0)

// forgedAuthnArgs — доводы, которые спросивший мог бы приложить к вопросу о себе,
// чтобы выполнить условие о способе, уровне и моменте аутентификации либо о
// соединении. Каждый — отдельной строкой: проба судит каждый ключ порознь.
var forgedAuthnArgs = map[string]any{
	"acr_value":          "3",
	"amr_claims":         []any{"webauthn"},
	"mfa_at":             float64(authnArgsServerNow.Unix()),
	"current_time":       float64(authnArgsServerNow.Add(-time.Hour).Unix()),
	"client_ip":          "10.0.0.1",
	"source_ip":          "10.0.0.1",
	"valid_until":        float64(authnArgsServerNow.Add(time.Hour).Unix()),
	"device_attestation": "trusted",
}

// credulousVerdict — источник вердикта, разрешающий по ЛЮБОМУ доводу
// аутентификации в условном контексте.
type credulousVerdict struct {
	*stubVerdict
}

func (c *credulousVerdict) CheckWithContext(_ context.Context, _, _, _ string, condCtx map[string]any) (bool, error) {
	if condCtx["acr_value"] == "3" {
		return true, nil
	}
	if amr, ok := condCtx["amr_claims"].([]any); ok && slices.Contains(amr, any("webauthn")) {
		return true, nil
	}
	for _, k := range []string{"mfa_at", "client_ip", "source_ip", "valid_until", "device_attestation"} {
		if _, ok := condCtx[k]; ok {
			return true, nil
		}
	}
	if now, ok := condCtx["current_time"].(int64); !ok || now != authnArgsServerNow.Unix() {
		return true, nil
	}
	return false, nil
}

func (c *credulousVerdict) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := c.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

func newCredulousHandler() *Handler {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: &credulousVerdict{stubVerdict: &stubVerdict{}},
		Now:       func() time.Time { return authnArgsServerNow },
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)).WithModuleRoster(testModuleRoster())
}

// authnArgsOutcome — то, что видит спросивший: вердикт и причины отказа.
type authnArgsOutcome struct {
	allowed bool
	reasons []string
}

func authnArgsQuestion(t *testing.T, args map[string]any) *iamv1.AuthorizeCheckRequest {
	t.Helper()
	req := &iamv1.AuthorizeCheckRequest{
		Subject:          "user:usr_alice",
		Resource:         &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_x"},
		Action:           "vpc.networks.update",
		RequiredRelation: "editor",
	}
	if args != nil {
		st, err := structpb.NewStruct(args)
		if err != nil {
			t.Fatalf("context %v: %v", args, err)
		}
		req.Context = st
	}
	return req
}

func checkOutcome(t *testing.T, ctx context.Context, h *Handler, args map[string]any) authnArgsOutcome {
	t.Helper()
	resp, err := h.Check(ctx, authnArgsQuestion(t, args))
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	return authnArgsOutcome{allowed: resp.GetAllowed(), reasons: resp.GetDenyReasons()}
}

func batchItemOutcome(t *testing.T, ctx context.Context, h *Handler, args map[string]any) authnArgsOutcome {
	t.Helper()
	resp, err := h.BatchCheck(ctx, &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{authnArgsQuestion(t, args)},
	})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if n := len(resp.GetResponses()); n != 1 {
		t.Fatalf("BatchCheck: ответов %d, ждали 1", n)
	}
	r := resp.GetResponses()[0]
	return authnArgsOutcome{allowed: r.GetAllowed(), reasons: r.GetDenyReasons()}
}

// TestCheck_AuthnArgsInContextDoNotChangeTheOutcome — вопрос с доводами
// аутентификации в `context` и без них получает один исход.
func TestCheck_AuthnArgsInContextDoNotChangeTheOutcome(t *testing.T) {
	h := newCredulousHandler()
	ctx := moduleCertCtx()

	for name, ask := range map[string]func(*testing.T, context.Context, *Handler, map[string]any) authnArgsOutcome{
		"Check":      checkOutcome,
		"BatchCheck": batchItemOutcome,
	} {
		t.Run(name, func(t *testing.T) {
			bare := ask(t, ctx, h, nil)
			if bare.allowed {
				t.Fatalf("предпосылка: вопрос без доводов разрешён — дублёр не отличит подделку от отсутствия")
			}
			cases := map[string]map[string]any{"все доводы разом": forgedAuthnArgs}
			for k, v := range forgedAuthnArgs {
				cases[k] = map[string]any{k: v}
			}
			for label, args := range cases {
				got := ask(t, ctx, h, args)
				if got.allowed != bare.allowed || !slices.Equal(got.reasons, bare.reasons) {
					t.Errorf("%s: доводы %v из context изменили исход: allowed=%v reasons=%q; без них allowed=%v reasons=%q",
						label, args, got.allowed, got.reasons, bare.allowed, bare.reasons)
				}
			}
		})
	}
}

// TestCheck_TrustedAssuranceFromTheCallReachesTheVerdict — законный близнец:
// уровень, положенный в контекст вызова доверенной цепочкой, исход меняет. Тот
// же уровень, присланный в `context`, — нет.
func TestCheck_TrustedAssuranceFromTheCallReachesTheVerdict(t *testing.T) {
	h := newCredulousHandler()
	trusted := grpcsrv.WithTrustedACR(moduleCertCtx(), "3", true)

	if got := checkOutcome(t, trusted, h, nil); !got.allowed {
		t.Fatalf("Check: доверенный уровень 3 не дошёл до решения: allowed=%v reasons=%q", got.allowed, got.reasons)
	}
	if got := batchItemOutcome(t, trusted, h, nil); !got.allowed {
		t.Fatalf("BatchCheck: доверенный уровень 3 не дошёл до решения: allowed=%v reasons=%q", got.allowed, got.reasons)
	}
	if got := checkOutcome(t, moduleCertCtx(), h, map[string]any{"acr_value": "3"}); got.allowed {
		t.Fatalf("Check: уровень из context разрешил вопрос, хотя доверенного уровня у вызова нет")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestCatalogPublication_PresentedHumanAndDescriptorFloor проверяет оба метода
// с контекстом ПОСЛЕ проверки Bearer читателем предъявленного. Копии каталога
// соседнего шлюза нет: ступень обязана действовать по своему дескриптору.
func TestCatalogPublication_PresentedHumanAndDescriptorFloor(t *testing.T) {
	for _, tc := range []struct {
		method string
		acr    string
	}{
		{iamv1.CatalogPublicationService_PlanPublication_FullMethodName, "1"},
		{iamv1.CatalogPublicationService_ApplyPublication_FullMethodName, "2"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			if got, present := catalogPublicationACR(tc.method); !present || got != tc.acr {
				t.Fatalf("ступень контракта %q, ожидалась %q", got, tc.acr)
			}
			for _, prod := range []bool{true, false} {
				policy := NewPublicCallerPolicy(prod, PublicPeerCallableRPCs(), nil, callerorigin.IsPresentedCredential).
					WithModuleRoster(testModuleRoster())
				if got := policy.requiredACRMin(tc.method); got != tc.acr {
					t.Fatalf("ступень публичного пути %q, ожидалась %q", got, tc.acr)
				}
				ctx := presentedCredentialCtx("user", tc.acr)
				if err := policy.allow(ctx, tc.method); err != nil {
					t.Errorf("проверенный человек, prod=%v: %v", prod, err)
				}
				if err := RequireCatalogPublicationACR(ctx, tc.method); err != nil {
					t.Errorf("проверка хендлера, prod=%v: %v", prod, err)
				}
				for _, acr := range []string{"", "invalid", "0"} {
					err := policy.allow(presentedCredentialCtx("user", acr), tc.method)
					if status.Code(err) != codes.Unauthenticated {
						t.Errorf("acr=%q, prod=%v: ожидался Unauthenticated, получено %v", acr, prod, err)
					}
					if _, ok := stepUpTrailer(err); !ok {
						t.Errorf("acr=%q: указание повысить уровень не несёт RFC9470", acr)
					}
				}
				if tc.acr == "2" {
					err := policy.allow(presentedCredentialCtx("user", "1"), tc.method)
					requireStepUpToTwo(t, err, "публикация модели")
				}
				for name, ctx := range map[string]context.Context{
					"module":            newVPCCtx(),
					"trusted-forwarded": gatewayACRCtx("2"),
					"presented-machine": presentedCredentialCtx("service_account", "2"),
					"unnamed":           context.Background(),
					"forged-bearer":     metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer not-verified")),
					"no-origin":         operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr-operator", Type: "user"}),
					"empty-user":        operations.WithPrincipal(presentedCredentialCtx("user", "2"), operations.Principal{Type: "user"}),
				} {
					if err := policy.allow(ctx, tc.method); status.Code(err) != codes.PermissionDenied {
						t.Errorf("%s, prod=%v: ожидался PermissionDenied, получено %v", name, prod, err)
					}
					if err := RequireCatalogPublicationACR(ctx, tc.method); status.Code(err) != codes.PermissionDenied {
						t.Errorf("%s, проверка хендлера: ожидался PermissionDenied, получено %v", name, err)
					}
				}
			}
		})
	}
}

func TestCatalogPublication_UnknownMethodFailsClosed(t *testing.T) {
	err := RequireCatalogPublicationACR(presentedCredentialCtx("user", "2"), "/kaname.cloud.iam.v1.CatalogPublicationService/Unknown")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("неизвестный метод: ожидался Unavailable, получено %v", err)
	}
}

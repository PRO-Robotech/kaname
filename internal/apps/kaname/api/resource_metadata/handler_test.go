// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type readFunc func(context.Context, string, string, string) (domain.ResourceMetadata, error)

func (f readFunc) ReadAuthorizedMirrorMetadata(ctx context.Context, subject, dottedType, objectID string) (domain.ResourceMetadata, error) {
	return f(ctx, subject, dottedType, objectID)
}

func TestGetUsesContextPrincipalAndPreservesSeparateMaps(t *testing.T) {
	for _, principalType := range []string{"user", "service_account"} {
		t.Run(principalType, func(t *testing.T) {
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: principalType, ID: "caller"})
			labels := map[string]string{"owner": "description"}
			accessLabels := map[string]string{"owner": "authorization"}
			calls := 0
			h := NewHandler(readFunc(func(gotCtx context.Context, subject, dottedType, objectID string) (domain.ResourceMetadata, error) {
				calls++
				if gotCtx != ctx || subject != principalType+":caller" || dottedType != "registry.registries" || objectID != "external-id" {
					t.Fatalf("unexpected read: %q %q %q", subject, dottedType, objectID)
				}
				return domain.ResourceMetadata{ResourceType: dottedType, ResourceID: objectID, Labels: labels, AccessLabels: accessLabels}, nil
			}))
			got, err := h.Get(ctx, &iamv1.GetResourceMetadataRequest{ResourceType: "registry.registries", ResourceId: "external-id"})
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || got.GetResourceType() != "registry.registries" || got.GetResourceId() != "external-id" || !reflect.DeepEqual(got.GetLabels(), labels) || !reflect.DeepEqual(got.GetAccessLabels(), accessLabels) {
				t.Fatalf("unexpected metadata: %v; calls=%d", got, calls)
			}
		})
	}
}

func TestGetRejectsUnresolvablePrincipalsBeforeReader(t *testing.T) {
	h := NewHandler(readFunc(func(context.Context, string, string, string) (domain.ResourceMetadata, error) {
		t.Fatal("unauthenticated call reached reader")
		return domain.ResourceMetadata{}, nil
	}))
	contexts := []context.Context{context.Background()}
	for _, principal := range []operations.Principal{
		{Type: "system", ID: "anonymous"},
		{Type: "system", ID: "bootstrap"},
		{Type: "unknown", ID: "caller"},
		{Type: "user"},
		{Type: "user", ID: "caller#member"},
	} {
		contexts = append(contexts, operations.WithPrincipal(context.Background(), principal))
	}
	for _, ctx := range contexts {
		got, err := h.Get(ctx, nil)
		if got != nil || status.Code(err) != codes.PermissionDenied || status.Convert(err).Message() != "permission denied" {
			t.Fatalf("unexpected refusal: %v, %v", got, err)
		}
	}
}

func TestGetMapsReaderErrorsWithoutInternalDetails(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "caller"})
	for _, tc := range []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{"denied", iamerr.ErrPermissionDenied, codes.PermissionDenied, "permission denied"},
		{"internal", errors.New("private database connection details"), codes.Internal, "internal error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandler(readFunc(func(context.Context, string, string, string) (domain.ResourceMetadata, error) {
				return domain.ResourceMetadata{}, tc.err
			}))
			got, err := h.Get(ctx, &iamv1.GetResourceMetadataRequest{ResourceType: "registry.registries", ResourceId: "external-id"})
			if got != nil || status.Code(err) != tc.code || status.Convert(err).Message() != tc.message {
				t.Fatalf("unexpected refusal: %v, %v", got, err)
			}
		})
	}
}

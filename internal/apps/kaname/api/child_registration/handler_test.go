// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package child_registration

import (
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"

	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func TestChildRegistrationRejectsUnknownCoordinates(t *testing.T) {
	handler := NewHandler(internaliam.NewUserChildRegistration(nil))
	ctx := operations.WithPrincipal(t.Context(), operations.Principal{Type: "user", ID: "usr-actor"})
	request := &iamv1.RegisterChildRequest{ResourceType: "example.child", ResourceId: "parent/child"}
	_, err := handler.Register(ctx, request)
	require.Equal(t, codes.Unavailable, status.Code(err), "корректная форма доходит до сценария")

	raw := protowire.AppendTag(nil, 19, protowire.BytesType)
	request.ProtoReflect().SetUnknown(protowire.AppendString(raw, "example_container:another"))
	_, err = handler.Register(ctx, request)
	refusal := status.Convert(err)
	require.Equal(t, codes.PermissionDenied, refusal.Code())
	require.Equal(t, "permission denied", refusal.Message())
	require.Empty(t, refusal.Details())
}

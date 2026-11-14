// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Публичный отказ не раскрывает source/authority, а неполадка backend
// сохраняет повторяемую полосу и не превращается в отсутствие права.
func TestBindingDecisionRefusalIsOpaqueAndBackendFailureStaysDistinct(t *testing.T) {
	cases := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{"denied_sentinel", iamerr.ErrPermissionDenied, codes.PermissionDenied, "permission denied"},
		{"denied_detail", iamerr.Wrapf(iamerr.ErrPermissionDenied, "Grant authority denied: private-source"), codes.PermissionDenied, "permission denied"},
		{"denied_status", status.Error(codes.PermissionDenied, "private actor checkpoint"), codes.PermissionDenied, "permission denied"},
		{"missing_source", iamerr.Wrapf(iamerr.ErrNotFound, "private-role"), codes.PermissionDenied, "permission denied"},
		{"backend_sentinel", iamerr.Wrapf(iamerr.ErrUnavailable, "private database address"), codes.Unavailable, shared.UnavailableMessage},
		{"backend_status", status.Error(codes.Unavailable, "authz backend unavailable"), codes.Unavailable, "authz backend unavailable"},
		{"retry_exhausted", status.Error(codes.Aborted, "authority retry exhausted"), codes.Aborted, "authority retry exhausted"},
		{"cancelled", context.Canceled, codes.Unavailable, shared.UnavailableMessage},
		{"unknown_failure", errors.New("private SQL detail"), codes.Internal, "internal error"},
	}
	require.NoError(t, bindingDecisionError(nil))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := bindingDecisionError(tc.err)
			require.Equal(t, tc.code, status.Code(err))
			require.Equal(t, tc.message, status.Convert(err).Message())
		})
	}
}

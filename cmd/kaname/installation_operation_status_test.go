// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type terminalInstallationStatusRepo struct {
	operations.Repo
	operation *operations.Operation
	reads     int
}

func (r *terminalInstallationStatusRepo) Get(context.Context, string) (*operations.Operation, error) {
	r.reads++
	return r.operation, nil
}

func TestWaitInstallationOperationStatusCode(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  int32
		want codes.Code
	}{
		{"OK", 0, codes.OK},
		{"PermissionDenied", 7, codes.PermissionDenied},
		{"Unauthenticated", 16, codes.Unauthenticated},
		{"Negative", -1, codes.Unknown},
		{"AboveLastCode", 17, codes.Unknown},
		{"MinInt32", -2147483648, codes.Unknown},
		{"MaxInt32", 2147483647, codes.Unknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &terminalInstallationStatusRepo{operation: &operations.Operation{
				Done: true, Error: &statuspb.Status{Code: tc.raw, Message: "operation failed"},
			}}
			err := waitInstallationOperation(context.Background(), repo, "operation-status")
			require.Equal(t, 1, repo.reads)
			require.Equal(t, tc.want, status.Code(err))
			if tc.want == codes.OK {
				require.NoError(t, err)
			} else {
				require.Equal(t, "operation failed", status.Convert(err).Message())
			}
		})
	}
}

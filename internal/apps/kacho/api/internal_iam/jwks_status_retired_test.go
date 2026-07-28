// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package internal_iam

// jwks_status_retired_test.go — GetJWKSStatus is withdrawn, not answered.
//
// The RPC reported the contents of `oidc_jwks_keys`, a table dropped in
// migration 0065 because iam owns no signing keyset: Hydra issues and signs,
// and what iam serves on :9097 is a short-TTL byte-identical mirror of Hydra's
// public keyset. After the drop the method was kept as a constant empty
// response — advertised on the internal listener, catalogued, floor-listed, and
// documented in the runbook as carrying no diagnostic signal. Nothing called
// it: not a service, not the edge, not the console, not one regression case.
//
// A read RPC that decides nothing and that nobody calls has three lawful
// outcomes and no fourth: implement it, reject it explicitly, or withdraw it.
// Answering an empty set forever is none of them — it keeps a promise on the
// contract that no one is accountable for. It is withdrawn.
//
// This file goes away together with the proto declaration: once the RPC leaves
// `internal_iam_service.proto` (with its number AND name reserved), the
// generated server interface loses the method and this test stops compiling —
// which is the signal that the last step landed.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

// TestGetJWKSStatus_Withdrawn — iam serves no implementation for the retired
// RPC. The call reaches the generated Unimplemented default, which is what
// withdrawal looks like on the wire while the declaration is still published.
func TestGetJWKSStatus_Withdrawn(t *testing.T) {
	h := NewHandler(NewLookupSubjectUseCase(nil), nil)

	resp, err := h.GetJWKSStatus(context.Background(), &emptypb.Empty{})

	assert.Nil(t, resp, "a withdrawn RPC answers nothing")
	assert.Equal(t, codes.Unimplemented, status.Code(err),
		"iam must not serve GetJWKSStatus: it reports on a store that no longer exists")
}

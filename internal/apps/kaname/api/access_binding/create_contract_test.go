// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// create_contract_test.go — the Create request must not offer a parameter the
// service does not act on.
//
// The condition overlay was such a parameter: a caller could name a condition on
// the binding, be told the grant succeeded, and get an unconditional grant. No
// decision path ever read it (neither the per-RPC check nor the materialisation),
// the row it had to point at could not be created through any API, and the
// builtin variant had nowhere to be stored at all. Offering it promised an ABAC
// gate that did not exist — which is worse than refusing, because a refusal is
// visible immediately and a missing gate is only visible in its consequences.
//
// So the two fields are OFF the contract, with tag and name reserved (a future
// design starts from a clean number rather than inheriting a meaning nobody
// implemented). The tenant-facing condition resource that once stood behind those
// fields has since been retired too — the same reasoning, applied to the rest of
// the surface: what remains is the condition ON A TUPLE, which the model declares
// and the server keys itself.
//
// This test reads the descriptor, so re-adding a field — by any route, including
// a regenerated stub — turns it red.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/reflect/protoreflect"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

func createRequestDescriptor() protoreflect.MessageDescriptor {
	return (&iamv1.CreateAccessBindingRequest{}).ProtoReflect().Descriptor()
}

// TestCreateAccessBindingRequest_NoUnreadConditionFields — the removed names are
// gone from the request.
func TestCreateAccessBindingRequest_NoUnreadConditionFields(t *testing.T) {
	fields := createRequestDescriptor().Fields()
	for _, name := range []string{"condition_id", "builtin_condition"} {
		assert.Nil(t, fields.ByName(protoreflect.Name(name)),
			"%s is not read by any decision path; it must not be offered on Create", name)
	}
}

// TestCreateAccessBindingRequest_ReservedTagsAndNames — the tags and names are
// tombstoned, so a later field cannot silently inherit the old meaning from a
// client that still sends it.
func TestCreateAccessBindingRequest_ReservedTagsAndNames(t *testing.T) {
	d := createRequestDescriptor()

	reservedTags := map[int32]bool{}
	for i := 0; i < d.ReservedRanges().Len(); i++ {
		r := d.ReservedRanges().Get(i)
		for n := r[0]; n < r[1]; n++ {
			reservedTags[int32(n)] = true
		}
	}
	for _, tag := range []int32{6, 7} {
		assert.True(t, reservedTags[tag], "tag %d must stay reserved (never reused)", tag)
	}

	reservedNames := map[string]bool{}
	for i := 0; i < d.ReservedNames().Len(); i++ {
		reservedNames[string(d.ReservedNames().Get(i))] = true
	}
	for _, name := range []string{"condition_id", "builtin_condition"} {
		assert.True(t, reservedNames[name], "name %q must stay reserved", name)
	}
}

// TestCreateAccessBindingRequest_ExpiresAtStays — the lifetime is the field that
// WAS implemented rather than removed; it must remain on the contract.
func TestCreateAccessBindingRequest_ExpiresAtStays(t *testing.T) {
	require.NotNil(t, createRequestDescriptor().Fields().ByName("expires_at"),
		"expires_at is honoured end-to-end and stays on the contract")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// target_vocabulary_parse_test.go — the same property as
// domain/access_binding_target_vocabulary_test.go, asserted where the caller
// actually meets it: the request parse path.
//
// The domain test states which strings the registry knows. This one states what a
// client observes when it sends them — accepted and carried through, or refused
// synchronously with the field named. Neither answers the other: the predicate can
// be right while the parse path routes around it, and the parse path can look
// right while the predicate answers for a vocabulary nothing emits.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

func parseSingleTarget(t *testing.T, dotted, id string) (any, error) {
	t.Helper()
	return targetFromProto(&iamv1.AccessTarget{
		Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
			Resources: []*iamv1.ResourceRef{{Type: dotted, Id: id}},
		}},
	})
}

// A per-object grant on block storage must be expressible. kacho-storage owns
// Volume / Snapshot / Image; before the compute copy was retired the same grant
// was expressible as compute.disk / compute.image / compute.snapshot. If the
// successor names are refused, the only remaining way to grant a volume is the
// whole-anchor arm — every object under the anchor, present and future.
func TestTargetParse_BlockStorageIsExpressiblePerObject(t *testing.T) {
	for _, tc := range []struct{ dotted, id string }{
		{"storage.volumes", "vol-aaaaaaaaaaaaaaaaa"},
		{"storage.snapshots", "snp-aaaaaaaaaaaaaaaaa"},
		{"storage.images", "img-aaaaaaaaaaaaaaaaa"},
	} {
		tgt, err := targetFromProto(&iamv1.AccessTarget{
			Target: &iamv1.AccessTarget_Resources{Resources: &iamv1.AccessTargetResources{
				Resources: []*iamv1.ResourceRef{{Type: tc.dotted, Id: tc.id}},
			}},
		})
		require.NoErrorf(t, err, "per-object target %q rejected — the grant is only expressible as the whole anchor", tc.dotted)
		require.Lenf(t, tgt.Resources, 1, "target %q parsed to no resource", tc.dotted)
		assert.Equal(t, tc.dotted, tgt.Resources[0].Type)
		assert.Equal(t, tc.id, tgt.Resources[0].ID)
	}
}

// The retired block-storage names stay refused, and the refusal names the field.
// Paired with the case above: "storage is accepted" and "compute is refused" are
// each meaningless alone.
func TestTargetParse_RetiredBlockStorageIsRefused(t *testing.T) {
	for _, dotted := range []string{"compute.disk", "compute.image", "compute.snapshot"} {
		_, err := parseSingleTarget(t, dotted, "x")
		require.Errorf(t, err, "per-object target %q accepted — compute does not serve it", dotted)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code())
		assert.Contains(t, st.Message(), "target.resources[].type")
		assert.Contains(t, st.Message(), dotted)
	}
}

// A type spelled the way the feed does NOT spell it must be refused at the
// boundary rather than stored. Reconciliation compares the target's string to the
// feed's string, so such a binding is created, reconciled, and grants nothing —
// the caller sees success and gets no access, which is worse than a refusal
// because only the consequence is visible.
func TestTargetParse_MisspelledTypeIsRefusedNotSilentlyStored(t *testing.T) {
	misspelled := []string{
		"vpc.route_table", "vpc.security_group", "vpc.network_interface",
		"iam.service_account", "loadbalancer.nlb", "loadbalancer.target_group",
	}
	for _, dotted := range misspelled {
		_, err := parseSingleTarget(t, dotted, "x")
		require.Errorf(t, err, "per-object target %q accepted — no object is ever emitted under that spelling, so the binding grants nothing", dotted)
		st, ok := status.FromError(err)
		require.True(t, ok)
		assert.Equal(t, codes.InvalidArgument, st.Code(), dotted)
	}
	// Positive control in the same call: the spelling the feed DOES emit is
	// accepted, so the block above is not passing because everything is refused.
	for _, dotted := range []string{"vpc.routeTable", "vpc.securityGroup", "vpc.networkInterface", "iam.serviceAccount", "loadbalancer.networkLoadBalancers", "loadbalancer.targetGroups"} {
		_, err := parseSingleTarget(t, dotted, "x")
		require.NoErrorf(t, err, "per-object target %q rejected — this is the spelling the materialization feed emits", dotted)
	}
}

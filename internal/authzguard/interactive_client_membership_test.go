// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// interactive_client_membership_test.go — IAM-INT-1: the five
// InternalInteractiveClientService RPCs are admitted by the internal listener's
// chain on the SAME terms as the other admin surface, and their membership is
// asserted rather than inherited.
//
// WHY AN EXPLICIT TEST AND NOT A DERIVED ONE. A gate that read the permission
// catalog and demanded every `Internal*` entry appear in
// GatewayFrontedInternalRPCs would be wrong: measured on this tree, 11 of the 16
// iam Internal* entries absent from that list are absent BY DESIGN — the PDP
// (`Check`), the hot-path chicken-and-egg lookups (`IsRevoked`,
// `InternalUserService/Get`), the Hydra hook callbacks, and the fga-proxy writes
// gated in-handler by RelationWriteGate. Deriving the rule from the catalog
// would turn each of those documented exemptions into a finding, and the first
// false red would get the gate switched off. So membership is stated, exactly as
// the package already states it for every other admin RPC, and the exemption set
// stays expressed by absence.
//
// WHAT WOULD BREAK WITHOUT THIS. The gateway catalog and the in-service registry
// are two copies of one decision. When only the catalog learns about a new RPC,
// the edge admits an admin caller and the backend chain then applies neither the
// gateway-only caller policy nor the acr floor to it — the RPC is reachable on
// looser terms than the RPCs beside it, and nothing says so out loud.

import "testing"

// interactiveClientRPCs — the five RPCs, split by the band each belongs to.
var (
	interactiveClientReads = []string{
		"/kacho.cloud.iam.v1.InternalInteractiveClientService/Get",
		"/kacho.cloud.iam.v1.InternalInteractiveClientService/List",
	}
	interactiveClientMutations = []string{
		"/kacho.cloud.iam.v1.InternalInteractiveClientService/Create",
		"/kacho.cloud.iam.v1.InternalInteractiveClientService/Update",
		"/kacho.cloud.iam.v1.InternalInteractiveClientService/Delete",
	}
)

// TestInteractiveClientRPCs_AreGatewayFronted — all five are admin surface the
// api-gateway fronts on behalf of a human operator. A direct dial from any other
// module is a privilege-escalation attempt, exactly as for InternalClusterService.
func TestInteractiveClientRPCs_AreGatewayFronted(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range GatewayFrontedInternalRPCs() {
		set[m] = struct{}{}
	}
	for _, m := range append(append([]string{}, interactiveClientReads...), interactiveClientMutations...) {
		if _, ok := set[m]; !ok {
			t.Errorf("GatewayFrontedInternalRPCs is missing admin RPC %q — the edge would front it "+
				"while the backend chain applied neither the gateway-only caller policy nor the acr floor", m)
		}
	}
}

// TestInteractiveClientReads_AreUnderTheReadFloor — the two reads pass the
// `system_viewer@cluster` floor. They are reads of the admin surface, so they sit
// with InternalSessionRevocationsService/ListByUser, not with the hot-path
// exemptions.
//
// Соседом здесь назывался InternalAuthorizeService/ReadTuples — службы с таким
// именем в контракте больше нет (снята вместе с внешним движком прав), и указание
// на неё послало бы читателя искать образец, которого не существует.
func TestInteractiveClientReads_AreUnderTheReadFloor(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range ReadFloorRPCs() {
		set[m] = struct{}{}
	}
	for _, m := range interactiveClientReads {
		if _, ok := set[m]; !ok {
			t.Errorf("ReadFloorRPCs is missing admin READ RPC %q", m)
		}
	}
}

// TestInteractiveClientMutations_AreNotUnderTheReadFloor — the paired negative.
// Without it the test above would keep passing if someone put ALL FIVE under the
// read floor, which would read as "covered" while quietly describing a mutation
// as a read. The mutations are governed by the caller policy and the acr floor
// (catalog acr=2), not by the viewer floor.
func TestInteractiveClientMutations_AreNotUnderTheReadFloor(t *testing.T) {
	set := make(map[string]struct{})
	for _, m := range ReadFloorRPCs() {
		set[m] = struct{}{}
	}
	for _, m := range interactiveClientMutations {
		if _, ok := set[m]; ok {
			t.Errorf("ReadFloorRPCs contains MUTATION %q — the read floor is for reads; a mutation "+
				"listed here is described as something it is not", m)
		}
	}
}

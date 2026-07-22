// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzmap_test

import (
	"context"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/fgatest"
)

// nlb_listener_project_test.go — regression lock for #68.
//
// kacho-nlb emits an `nlb_listener:<id> #project @project:<proj>` owner-hierarchy
// tuple (services/nlb/.../fga_intent.go, FGARelationProject) exactly like it does
// for nlb_network_load_balancer and nlb_target_group — but the FGA model's
// `nlb_listener` type defined NO `project` relation (only load_balancer/admin/
// editor/viewer/v_*). OpenFGA therefore REJECTED every listener project-tuple
// ("relation 'nlb_listener#project' not found") → the iam fga_outbox drainer
// dead-lettered it (apply_permanent_poison) → the listener's project-hierarchy
// never materialized → listener authz/access broke (nlb `listener` newman suite
// red on a fresh 0-tuple stand). Same defect class as registry Defect A: an
// emitter↔model mismatch. Fix = add `define project: [project]` (Contract-A
// direct-relation, parity with nlb_network_load_balancer at the same tier).
func TestNlbListenerModel_DefinesProjectRelation(t *testing.T) {
	dsl := registryModelBlock(t) // whole model.fga DSL block (not registry-specific)
	body := typeBody(t, dsl, "nlb_listener")
	re := regexp.MustCompile(`(?m)^\s*define project:\s*\[project\]`)
	require.Truef(t, re.MatchString(body),
		"nlb_listener must define `project: [project]` so the nlb-emitted project "+
			"owner-hierarchy tuple is a valid FGA write (no dead-letter poison), parity "+
			"with nlb_network_load_balancer / nlb_target_group (#68). body:\n%s", body)

	// Parity guard: the two peer nlb types already carry it — if this ever regresses,
	// the listener drifts back out of the project hierarchy.
	for _, peer := range []string{"nlb_network_load_balancer", "nlb_target_group"} {
		pb := typeBody(t, dsl, peer)
		require.Truef(t, re.MatchString(pb), "%s should still define project: [project]", peer)
	}
}

// readConfigMapModelJSON returns the pre-transformed OpenFGA-JSON model from the
// openfga-bootstrap ConfigMap `model.json` block (the exact model the deployed
// stand loads), so the OpenFGA-Check test exercises the DEPLOYED authz model.
func readConfigMapModelJSON(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(findConfigMap(t))
	require.NoError(t, err)
	lines := strings.Split(string(raw), "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) == "model.json: |-" && i+1 < len(lines) {
			return []byte(strings.TrimSpace(lines[i+1]))
		}
	}
	t.Skip("model.json block not found in ConfigMap")
	return nil
}

// TestNlbListenerModel_ProjectTuple_OpenFGACheck loads the DEPLOYED model into a
// real OpenFGA and proves #68 end-to-end: (1) the nlb-emitted
// `nlb_listener #project @project` tuple is now a VALID write (pre-fix OpenFGA
// rejected it → the drainer poison), (2) a materialized owner resolves the
// listener's v_* verbs, and (3) a cross-account subject is denied (the project
// link leaks no access). Real OpenFGA container; skipped under -short.
func TestNlbListenerModel_ProjectTuple_OpenFGACheck(t *testing.T) {
	h := fgatest.NewFromModelJSON(t, readConfigMapModelJSON(t))
	ctx := context.Background()
	const listener = "nlb_listener:lst-68test"

	// (1) The project owner-hierarchy tuple nlb emits is now a valid FGA write.
	//     h.Write t.Fatalf's on an OpenFGA reject — pre-#68 this failed with
	//     "relation 'nlb_listener#project' not found".
	h.Write(t, "project:prj-68test", "project", listener)

	// (2) Owner's materialized direct v_* resolves.
	h.Write(t, "service_account:sva-owner68", "v_get", listener)
	h.Write(t, "service_account:sva-owner68", "v_update", listener)
	for _, rel := range []string{"v_get", "v_update"} {
		ok, err := h.Client.CheckWithContextConsistent(ctx, "service_account:sva-owner68", rel, listener, nil)
		require.NoError(t, err)
		require.Truef(t, ok, "listener owner must resolve %s", rel)
	}

	// (3) A cross-account SA with no tuple on this listener is DENIED (the project
	//     relation is a structural hierarchy link, not a grant — no leakage).
	for _, rel := range []string{"v_get", "v_update", "v_delete"} {
		ok, err := h.Client.CheckWithContextConsistent(ctx, "service_account:sva-cross68", rel, listener, nil)
		require.NoError(t, err)
		require.Falsef(t, ok, "cross-account SA must NOT resolve %s on the listener", rel)
	}
}

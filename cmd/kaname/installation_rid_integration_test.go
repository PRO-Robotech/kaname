// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"
)

// The complete accepted RID inventory stays explicit while the executable
// scenarios are being connected. Missing execution is a FIXTURE_INCOMPLETE
// failure under the opt-in gate, never a vacuous PASS or a product defect.
// Ordinary package runs skip the entire leased runtime obligation. No holder
// may be marked complete by substituting the already-green narrow pool1 test.
type ridPredicate struct {
	name string
	run  func(*testing.T)
}

func runInstallationRID(t *testing.T, predicates ...ridPredicate) {
	t.Helper()
	if os.Getenv("KANAME_RID_ACCEPTANCE") != "1" {
		t.Skip("NOT_EXECUTED: full RID requires a frozen, explicitly leased acceptance job")
	}
	for _, predicate := range predicates {
		if predicate.run == nil {
			t.Errorf("FIXTURE_INCOMPLETE (not a product verdict): %s", predicate.name)
		}
	}
	if t.Failed() {
		t.FailNow()
	}
	for _, predicate := range predicates {
		t.Run(predicate.name, predicate.run)
	}
}

func TestRID_01_CleanInstallAndRenewal(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "real standalone F0 -> verified O -> standing C -> full serve delivery"},
		ridPredicate{name: "exact creator and axes; C I A distinct; I not admin"},
		ridPredicate{name: "actual token expiry renewal with same live key and unchanged IDs createdAt counts"},
		ridPredicate{name: "expired standing key refusal and valid-time-only twin"},
		ridPredicate{name: "pace1 and pace5 large repeated concurrent authentication and cancellation"})
}
func TestRID_02_ConcurrentAndRepeat(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "axis reorder sequential repeat preserves IDs and createdAt"},
		ridPredicate{name: "two real absent-pair arrivals -> one GD and two successful Operations"},
		ridPredicate{name: "raw Any metadata index and response identities agree on both Operations"},
		ridPredicate{name: "stop before writer before commit after commit before terminal; primary recovery"},
		ridPredicate{name: "cancellation and reconciler overlap preserve terminal refusal"})
}
func TestRID_03_DelegatedGrantAndIssuerBounds(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "real production listener grant Operation Get ACTIVE with installation delegationId"},
		ridPredicate{name: "out-of-axis role denial and same-subject legal role twin"},
		ridPredicate{name: "I Create denied without Operation; caller-only C twin succeeds"},
		ridPredicate{name: "allowed anonymous system-class succeeds; authenticated refused"})
}
func TestRID_04_CreatorRetirement(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "independent verified O gateway RevokeAdmin materialized before I grant and apply"},
		ridPredicate{name: "new grant and apply denied; old G and GD ACTIVE and no self-restoration"},
		ridPredicate{name: "O explicit GrantAdmin only -> same request succeeds with same delegationId"})
}
func TestRID_05_CreatorDeletionAndNewID(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "normal full key revoke and reference census; Delete and Get NOT_FOUND"},
		ridPredicate{name: "old creator credentials unauthenticated; new same-name C2 does not resurrect GD"},
		ridPredicate{name: "active delegate reference blocks Delete; revoke-only twin permits Delete"},
		ridPredicate{name: "O explicitly grants C2; old GD revoked; explicit new Create restores issuance"})
}
func TestRID_06_RevokeDuringApply(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "apply at real before-pair barrier; O commits revoke before release"},
		ridPredicate{name: "overlap and sequential reinstall refuse; old G and GD revoked; replacement zero"},
		ridPredicate{name: "no-revoke overlap twin preserves original ID"},
		ridPredicate{name: "explicit C Create recovery preserves revoked history and new issuer grant works"})
}
func TestRID_07_ExistingPairConflict(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "independent lawful role target subject creator conflicts each FAILED_PRECONDITION"},
		ridPredicate{name: "each failure preserves complete pair and grants without update or revoke"},
		ridPredicate{name: "one-axis-only twin for each conflict is idempotent exact match"})
}
func TestRID_08_SnapshotPagesAndFutureAccount(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "same verified O initial A plus normal B T; actual admission1+2 of3/hour"},
		ridPredicate{name: "actual window expiry then same O creates D only after frozen N3 pageSize2 snapshot"},
		ridPredicate{name: "first run N3 includes system-tenant excludes canonical SYS and D; repeat N4 stable IDs"},
		ridPredicate{name: "full pages compared to canonical primary census"},
		ridPredicate{name: "actual empty census success; second-page BeginTx unknown fault INTERNAL before Operations"},
		ridPredicate{name: "fault-only removed twin and retry converge without duplicates"})
}
func TestRID_09_WholeDeliveryPreflight(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "complete M1 M2 fresh worlds both orders for foreign role target subject delegate"},
		ridPredicate{name: "every invalid axis preserves catalog roles own seed SA groups joins grants GD snapshots"},
		ridPredicate{name: "single-field legal twin writes both full manifests and every N pair"})
}
func TestRID_10_MidRunFaultAndRetirement(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "first pair committed observed; unknown Writer BeginTx only after normal second Operation Create"},
		ridPredicate{name: "second Operation done INTERNAL internal error; first kept; no later pairs"},
		ridPredicate{name: "independent O RevokeAdmin at same boundary; denial before next Operation"},
		ridPredicate{name: "remove only fault or restore only admin; retry N stable first ID; no-fault twins"})
}
func TestRID_11_InputAuthnAuthorityBackend(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "every accepted result-table input authn authority backend row on absent and ACTIVE pair"},
		ridPredicate{name: "exact exit stage field pair completedPairs; no bootstrap I fallback or self-provision"},
		ridPredicate{name: "each fact-only legal twin succeeds and converges; missing S1 A before writes"},
		ridPredicate{name: "real structured stdout stderr and absence of raw or JSON-escaped credential key token values"})
}
func TestRID_12_ClosedShapeAndBounds(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "absent and empty GD field normal full seed success zero GD"},
		ridPredicate{name: "unknown field each empty or duplicate axis and17roles17types5subjects rejected before all writes"},
		ridPredicate{name: "UNSPECIFIED unknown enum iam module role type rejected exact fields"},
		ridPredicate{name: "all17 lawful catalog types and roles retained; legal16/16/4 N pairs"},
		ridPredicate{name: "single-bad-field-only repair twins; array reorder idempotence"})
}

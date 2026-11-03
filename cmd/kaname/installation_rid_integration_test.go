// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
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
		t.Run(predicate.name, func(t *testing.T) {
			if predicate.run == nil {
				t.Fatalf("FIXTURE_INCOMPLETE (not a product verdict): %s", predicate.name)
			}
			predicate.run(t)
		})
	}
}

func TestRID_01_CleanInstallAndRenewal(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "real standalone F0 -> verified O -> standing C -> full serve delivery", run: ridNativeFirstInstall},
		ridPredicate{name: "exact creator and axes; C I A distinct; I not admin", run: ridNativeExactIdentityAxes},
		ridPredicate{name: "actual token expiry renewal with same live key and unchanged IDs createdAt counts", run: ridNativeTokenRenewal},
		ridPredicate{name: "expired standing key refusal and valid-time-only twin", run: ridNativeExpiredKeyTimeTwin},
		ridPredicate{name: "pace1 and pace5 large repeated concurrent authentication and cancellation", run: ridStandingAuthentication})
}
func TestRID_02_ConcurrentAndRepeat(t *testing.T) {
	var observed []nativeInstallationOperationObservation
	concurrent := func(t *testing.T) { observed = ridNativeConcurrentAbsentPair(t) }
	metadata := func(t *testing.T) {
		if len(observed) == 0 {
			concurrent(t)
		}
		requireRID02RawOperationEvidence(t, observed)
	}
	runInstallationRID(t,
		ridPredicate{name: "axis reorder sequential repeat preserves IDs and createdAt", run: ridNativeSequentialAxisRepeat},
		ridPredicate{name: "two real absent-pair arrivals -> one GD and two successful Operations", run: concurrent},
		ridPredicate{name: "raw Any metadata index and response identities agree on both Operations", run: metadata},
		ridPredicate{name: "stop before writer before commit after commit before terminal; primary recovery", run: ridNativeCrashPrimaryRecovery},
		ridPredicate{name: "cancellation and reconciler overlap preserve terminal refusal", run: ridNativeCancellationReconcilerOverlap})
}
func TestRID_03_DelegatedGrantAndIssuerBounds(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "real production listener grant Operation Get ACTIVE with installation delegationId", run: ridNativeDelegatedGrant},
		ridPredicate{name: "out-of-axis role denial and same-subject legal role twin", run: ridNativeDelegatedAxes},
		ridPredicate{name: "I Create denied without Operation; caller-only C twin succeeds", run: ridNativeIssuerCannotDelegate},
		ridPredicate{name: "allowed anonymous system-class succeeds; authenticated refused", run: ridNativeAnonymousClass})
}
func TestRID_04_CreatorRetirement(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "independent verified O gateway RevokeAdmin materialized before I grant and apply", run: ridNativeCreatorRetired},
		ridPredicate{name: "new grant and apply denied; old G and GD ACTIVE and no self-restoration", run: ridNativeRetirementApplyDenied},
		ridPredicate{name: "O explicit GrantAdmin only -> same request succeeds with same delegationId", run: ridNativeRetirementExplicitTwin})
}
func TestRID_05_CreatorDeletionAndNewID(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "normal full key revoke and reference census; Delete and Get NOT_FOUND", run: ridNativeCreatorDelete},
		ridPredicate{name: "old creator credentials unauthenticated; new same-name C2 does not resurrect GD", run: ridNativeSameNameDoesNotRestore},
		ridPredicate{name: "active delegate reference blocks Delete; revoke-only twin permits Delete", run: ridNativeActiveDelegateDeleteGuard},
		ridPredicate{name: "O explicitly grants C2; old GD revoked; explicit new Create restores issuance", run: ridNativeCreatorExplicitReplacement})
}
func TestRID_06_RevokeDuringApply(t *testing.T) {
	runInstallationRID(t,
		ridPredicate{name: "apply at real before-pair barrier; O commits revoke before release", run: ridNativeRevokeBeforePair},
		ridPredicate{name: "overlap and sequential reinstall refuse; old G and GD revoked; replacement zero", run: ridNativeRevokeOverlapAndSequential},
		ridPredicate{name: "no-revoke overlap twin preserves original ID", run: ridNativeNoRevokeOverlapTwin},
		ridPredicate{name: "explicit C Create recovery preserves revoked history and new issuer grant works", run: ridNativeRevokeExplicitRecovery})
}
func TestRID_07_ExistingPairConflict(t *testing.T) {
	var observed []rid07Observation
	conflicts := func(t *testing.T) { observed = rid07Matrix(t, false) }
	preserved := func(t *testing.T) {
		if len(observed) == 0 {
			conflicts(t)
		}
		requireRID07Preserved(t, observed)
	}
	twins := func(t *testing.T) { requireRID07Preserved(t, rid07Matrix(t, true)) }
	runInstallationRID(t,
		ridPredicate{name: "independent lawful role target subject creator conflicts each FAILED_PRECONDITION", run: conflicts},
		ridPredicate{name: "each failure preserves complete pair and grants without update or revoke", run: preserved},
		ridPredicate{name: "one-axis-only twin for each conflict is idempotent exact match", run: twins})
}
func TestRID_08_SnapshotPagesAndFutureAccount(t *testing.T) {
	// One complete real-hour world supplies immutable evidence to the first four
	// named predicates. Selecting any one alone still executes the entire world.
	var future *rid08FutureProof
	var empty *rid08EmptyProof
	var fault *rid08FaultProof
	ensureFuture := func(t *testing.T) *rid08FutureProof {
		if future == nil {
			future = rid08FutureWorld(t)
		}
		require.NotNil(t, future)
		return future
	}
	ensureFault := func(t *testing.T) *rid08FaultProof {
		if fault == nil {
			require.True(t, t.Run("real-second-page-fault-twin-retry", func(t *testing.T) { fault = rid08FaultWorld(t) }))
		}
		require.NotNil(t, fault)
		return fault
	}
	runInstallationRID(t,
		ridPredicate{name: "same verified O initial A plus normal B T; actual admission1+2 of3/hour", run: func(t *testing.T) {
			p := ensureFuture(t)
			require.EqualValues(t, 1, p.Initial.Admitted)
			require.EqualValues(t, 3, p.Full.Admitted)
			require.EqualValues(t, 3, p.Full.Limit)
			require.EqualValues(t, 3600, p.Full.WindowSeconds)
			require.Equal(t, p.Initial.User, p.Full.User)
			require.Equal(t, p.Initial.CarrierDigest, p.Full.CarrierDigest)
			require.Len(t, p.AccountsN3, 3)
		}},
		ridPredicate{name: "actual window expiry then same O creates D only after frozen N3 pageSize2 snapshot", run: func(t *testing.T) {
			p := ensureFuture(t)
			require.False(t, p.Expired.DBNow.Before(p.Full.Started.Add(time.Hour)))
			require.False(t, p.Snapshot.CompletedAt.Before(p.Expired.DBNow))
			require.False(t, p.DCommitted.Before(p.Snapshot.CompletedAt))
			require.False(t, p.Released.Before(p.DCommitted))
			require.Equal(t, p.Operator, p.AfterD.User)
			require.EqualValues(t, 1, p.AfterD.Admitted)
			require.Equal(t, 2, p.Snapshot.PageSize)
			require.NotContains(t, rid08IDs(p.Snapshot.Accounts), p.D)
		}},
		ridPredicate{name: "first run N3 includes system-tenant excludes canonical SYS and D; repeat N4 stable IDs", run: func(t *testing.T) {
			p := ensureFuture(t)
			ids := rid08IDs(p.Snapshot.Accounts)
			require.Len(t, ids, 3)
			require.Contains(t, ids, p.TenantNamedSystem)
			require.NotContains(t, ids, p.System)
			require.NotContains(t, ids, p.D)
			require.Len(t, p.First.Delegations, 6)
			require.Len(t, p.RepeatSnapshot.Accounts, 4)
			require.Contains(t, rid08IDs(p.RepeatSnapshot.Accounts), p.D)
			require.Len(t, p.Repeat.Delegations, 8)
			for id, value := range p.First.Delegations {
				require.Equal(t, value, p.Repeat.Delegations[id])
				require.Equal(t, p.First.Created[id], p.Repeat.Created[id])
				require.Equal(t, p.FirstRaw[id], p.RepeatRaw[id])
			}
		}},
		ridPredicate{name: "full pages compared to canonical primary census", run: func(t *testing.T) {
			p := ensureFuture(t)
			require.Equal(t, 3, p.Snapshot.Pages)
			require.Equal(t, 3, p.RepeatSnapshot.Pages)
			require.Equal(t, p.AccountsN3, rid08IDs(p.Snapshot.Accounts))
			require.GreaterOrEqual(t, p.First.SAPages, 3)
			require.GreaterOrEqual(t, p.First.GDPages, len(p.First.Accounts))
			require.Equal(t, p.First.ServiceAccounts, p.Repeat.ServiceAccounts)
			require.Len(t, p.FirstRaw, 6)
			require.Len(t, p.RepeatRaw, 8)
		}},
		ridPredicate{name: "actual empty census success; second-page BeginTx unknown fault INTERNAL before Operations", run: func(t *testing.T) {
			require.True(t, t.Run("normal-delete-real-empty", func(t *testing.T) { empty = rid08EmptyWorld(t) }))
			require.NotNil(t, empty)
			require.Empty(t, empty.Snapshot.Accounts)
			require.Empty(t, empty.Public.Delegations)
			p := ensureFault(t)
			require.Empty(t, p.FailedOpsBefore)
			require.Equal(t, p.FailedOpsBefore, p.FailedOpsAfter)
			require.JSONEq(t, "[]", p.FaultGDHistory)
		}},
		ridPredicate{name: "fault-only removed twin and retry converge without duplicates", run: func(t *testing.T) {
			p := ensureFault(t)
			require.Len(t, p.TwinSnapshot.Accounts, 3)
			require.Len(t, p.Twin.Delegations, 6)
			require.Equal(t, p.Twin, p.Retry)
			require.Equal(t, p.TwinSnapshot.Accounts, p.RetrySnapshot.Accounts)
		}})
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

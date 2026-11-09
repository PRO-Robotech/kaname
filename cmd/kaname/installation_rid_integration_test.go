// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Полная принятая ведомость RID остаётся явной при подключении исполняемых
// сценариев. Отсутствующее выполнение — отказ FIXTURE_INCOMPLETE
// при явном включении, а не пустой PASS или дефект продукта.
// Штатные запуски пакета пропускают всё арендованное обязательство исполнения. Держатель
// не может считаться полным за счёт подстановки уже успешного узкого теста pool1.
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
		ridPredicate{name: "explicit account registration writer authority, missing/revoked/wildcard refusals and lawful twins", run: ridRegistrationWriterAuthorityTwins},
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
	// Один полный мир настоящего часа даёт неизменяемое доказательство первым четырём
	// именованным предикатам. Выбор любого одного всё равно выполняет весь мир.
	var future *rid08FutureProof
	futureAttempted := false
	var empty *rid08EmptyProof
	var fault *rid08FaultProof
	ensureFuture := func(t *testing.T) *rid08FutureProof {
		if !futureAttempted {
			futureAttempted = true
			future = rid08FutureWorld(t)
		}
		require.NotNil(t, future, "future-world prerequisite failed earlier; no duplicate real-hour run")
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
	var observed []rid09Observation
	attempted := false
	negative := func(t *testing.T) { attempted = true; observed = rid09Matrix(t, false, nil) }
	preserved := func(t *testing.T) {
		if !attempted {
			negative(t)
		}
		rid09RequireMatrixPreserved(t, observed)
	}
	twins := func(t *testing.T) {
		result := rid09Matrix(t, true, nil)
		require.Len(t, result, 8)
		for _, p := range result {
			require.True(t, p.Twin)
			require.NotNil(t, p.GDPublic)
			require.Len(t, p.GDPublic.Delegations, 6)
			require.False(t, p.Return.ErrorPresent)
		}
	}
	runInstallationRID(t,
		ridPredicate{name: "complete M1 M2 fresh worlds both orders for foreign role target subject delegate", run: negative},
		ridPredicate{name: "every invalid axis preserves catalog roles own seed SA groups joins grants GD snapshots", run: preserved},
		ridPredicate{name: "single-field legal twin writes both full manifests and every N pair", run: twins})
}
func TestRID_10_MidRunFaultAndRetirement(t *testing.T) {
	proofs := map[string]*rid10Proof{}
	attempted := map[string]bool{}
	ensure := func(t *testing.T, mode string, twin bool) *rid10Proof {
		t.Helper()
		key := mode
		if twin {
			key += "-lawful-twin"
		}
		if !attempted[key] {
			attempted[key] = true
			require.True(t, t.Run(key, func(t *testing.T) { proofs[key] = rid10Run(t, mode, twin) }))
		}
		require.NotNil(t, proofs[key], "selected predicate requires its actual successful scenario, never an empty receipt")
		return proofs[key]
	}
	runInstallationRID(t,
		ridPredicate{name: "first pair committed observed; unknown Writer BeginTx only after normal second Operation Create", run: func(t *testing.T) {
			p := ensure(t, "fault", false)
			require.Len(t, p.Accounts, 3)
			require.NotEqual(t, p.System, p.NamedSystem)
			require.Equal(t, []string{p.First.ID}, p.AtBoundary)
			require.NotNil(t, p.Failure)
			require.NotEqual(t, p.First.ID, p.Failure.ID)
			require.NotEqual(t, p.First.Winner, p.Failure.Proposed)
			require.True(t, p.Returned.FaultInjected && p.Returned.FaultContextLive && p.Returned.ControlOK)
		}},
		ridPredicate{name: "second Operation done INTERNAL internal error; first kept; no later pairs", run: func(t *testing.T) {
			p := ensure(t, "fault", false)
			require.NotNil(t, p.Failure)
			require.True(t, p.Failure.Done && p.Failure.MessageMatches)
			require.EqualValues(t, 13, p.Failure.Code)
			require.Len(t, p.AfterFailure, 2)
			require.Contains(t, p.AfterFailure, p.First.ID)
			require.Equal(t, p.First.Winner, p.PairIDs[p.First.Account])
			require.Equal(t, p.First.CreatedAt, p.Created[p.First.Account])
			require.NotEmpty(t, p.FirstG)
		}},
		ridPredicate{name: "independent O RevokeAdmin at same boundary; denial before next Operation", run: func(t *testing.T) {
			p := ensure(t, "retirement", false)
			require.Equal(t, p.AtBoundary, p.AfterFailure)
			require.Nil(t, p.Failure)
			require.EqualValues(t, 7, p.Returned.Code)
			require.True(t, p.Returned.MessageMatches && p.Returned.ControlOK)
			require.EqualValues(t, 1, p.Returned.WriterArrivals)
		}},
		ridPredicate{name: "remove only fault or restore only admin; retry N stable first ID; no-fault twins", run: func(t *testing.T) {
			// Запускаем оба независимых близнеца до зависимых сравнений квитанций;
			// один неудачный отрицательный случай не должен подавлять перепись свежего мира.
			for _, mode := range []string{"fault", "retirement"} {
				t.Run(mode+"-independent-twin", func(t *testing.T) { ensure(t, mode, true) })
			}
			for _, mode := range []string{"fault", "retirement"} {
				p := ensure(t, mode, false)
				twin := ensure(t, mode, true)
				require.Len(t, p.Recovery, 3)
				require.Len(t, p.PairIDs, 3)
				require.Len(t, twin.PairIDs, 3)
				require.Equal(t, p.First.Winner, p.PairIDs[p.First.Account])
				require.Equal(t, p.First.CreatedAt, p.Created[p.First.Account])
				require.EqualValues(t, 0, twin.Returned.Code)
				require.Equal(t, 3, twin.Returned.Completed)
				require.True(t, twin.Returned.ControlOK && twin.Returned.MessageMatches)
			}
		}})
}
func TestRID_11_InputAuthnAuthorityBackend(t *testing.T) {
	var negatives, twins []rid11Proof
	var negativeAttempted, twinAttempted bool
	ensure := func(t *testing.T, twin bool) []rid11Proof {
		if twin {
			if !twinAttempted {
				twinAttempted = true
				twins = rid11Matrix(t, true, nil)
			}
			require.Len(t, twins, 31)
			return twins
		}
		if !negativeAttempted {
			negativeAttempted = true
			negatives = rid11Matrix(t, false, nil)
		}
		require.Len(t, negatives, 31)
		return negatives
	}
	runInstallationRID(t,
		ridPredicate{name: "every accepted result-table input authn authority backend row on absent and ACTIVE pair", run: func(t *testing.T) {
			observed := ensure(t, false)
			seen := map[string]bool{}
			for _, p := range observed {
				require.False(t, seen[p.Case.key()])
				seen[p.Case.key()] = true
				require.Equal(t, p.Case.expected(), p.Expected)
				if p.Case.Mode == "S2" {
					require.Len(t, p.Accounts, 3)
					require.Contains(t, p.Accounts, p.NamedSystem)
					require.NotContains(t, p.Accounts, p.CanonicalSystem)
				}
			}
		}},
		ridPredicate{name: "exact exit stage field pair completedPairs; no bootstrap I fallback or self-provision", run: func(t *testing.T) {
			for _, p := range ensure(t, false) {
				require.Equal(t, int32(p.Case.returnCode()), p.Returned.Code)
				require.True(t, p.Returned.ErrorPresent && p.Returned.MessageMatches)
				require.False(t, p.Ready)
				require.Zero(t, p.Expected.CompletedPairs)
				require.Empty(t, p.Expected.DelegateID)
				require.Equal(t, p.PairRowsBefore, p.PairRowsAfter)
				if p.Case.Variant != "census" {
					ridRequireWholeDeliveryUnchanged(t, p.Before, p.After)
				}
			}
		}},
		ridPredicate{name: "each fact-only legal twin succeeds and converges; missing S1 A before writes", run: func(t *testing.T) {
			// Каждый допустимый близнец состояния опускает только своё именованное вмешательство.
			// Отрицательные случаи вывода из обращения отдельно доказывают: Revoke сохраняет C, затем Delete удаляет C.
			lawful := ensure(t, true)
			byCase := map[string]rid11Proof{}
			for _, p := range lawful {
				byCase[p.Case.key()] = p
				require.True(t, p.Ready)
				require.False(t, p.Returned.ErrorPresent)
				require.EqualValues(t, 0, p.Returned.Code)
				require.NotEmpty(t, p.Issuer)
				require.NotNil(t, p.CreatorCurrent)
				rid11RequireSameIdentity(t, p.CreatorBefore, *p.CreatorCurrent)
				require.NotNil(t, p.IssuerAfter)
				require.Equal(t, p.Issuer, p.IssuerAfter.Public.Id)
				require.Empty(t, p.MutationOperations)
				require.Nil(t, p.CreatorAfterRevoke)
				require.Nil(t, p.DeletedAfterMutation)
				require.Nil(t, p.DeletedAfterRun)
				if p.Case.Active {
					require.NotNil(t, p.IssuerBefore)
					rid11RequireSameIdentity(t, *p.IssuerBefore, *p.IssuerAfter)
				}
			}
			for _, p := range ensure(t, false) {
				twin, ok := byCase[p.Case.key()]
				require.True(t, ok)
				require.Equal(t, p.ManifestSHA256, twin.ManifestSHA256)
				if p.Case.Variant == "revoked-key" || p.Case.Variant == "deleted-creator" {
					require.NotNil(t, p.CreatorAfterRevoke)
					rid11RequireSameIdentity(t, p.CreatorBefore, *p.CreatorAfterRevoke)
					require.NotNil(t, p.KeysAfterRevoke)
					require.True(t, p.KeysAfterRevoke.PublicListExecuted)
					require.Zero(t, p.KeysAfterRevoke.PublicRows)
					require.Zero(t, p.KeysAfterRevoke.PrimaryKeyRows)
					require.Zero(t, p.KeysAfterRevoke.PrimaryCreatorKeys)
					require.NotNil(t, p.KeysAfterRun)
					require.Zero(t, p.KeysAfterRun.PrimaryKeyRows)
					require.Zero(t, p.KeysAfterRun.PrimaryCreatorKeys)
					require.True(t, p.PublicTokenRefused)
					require.Equal(t, "UNAUTHENTICATED", p.Expected.Code)
					if p.Case.Variant == "revoked-key" {
						require.Len(t, p.MutationOperations, 1)
						require.NotNil(t, p.CreatorCurrent)
						rid11RequireSameIdentity(t, p.CreatorBefore, *p.CreatorCurrent)
						require.True(t, p.KeysAfterRun.PublicListExecuted)
						require.Zero(t, p.KeysAfterRun.PublicRows)
						require.Nil(t, p.DeletedAfterMutation)
						require.Nil(t, p.DeletedAfterRun)
					} else {
						require.Len(t, p.MutationOperations, 2)
						require.NotEqual(t, p.MutationOperations[0], p.MutationOperations[1])
						require.Nil(t, p.CreatorCurrent)
						for _, absent := range []*rid11AbsentIdentity{p.DeletedAfterMutation, p.DeletedAfterRun} {
							require.NotNil(t, absent)
							require.Equal(t, 404, absent.HTTPStatus)
							require.Equal(t, 5, absent.Code)
							require.Zero(t, absent.PrimaryRows)
						}
					}
				}
				if p.Case.Active {
					require.NotNil(t, p.IssuerBefore)
					require.NotNil(t, p.IssuerAfter)
					rid11RequireSameIdentity(t, *p.IssuerBefore, *p.IssuerAfter)
					require.Equal(t, p.HistoryBeforeMutation, p.HistoryAfterRun)
				}
				if p.Case.Variant == "account" {
					require.Equal(t, "S1", p.Case.Mode)
					require.Equal(t, "tenantAccountId", p.Expected.Field)
					ridRequireWholeDeliveryUnchanged(t, p.Before, p.After)
				}
			}
		}},
		ridPredicate{name: "real structured stdout stderr and absence of raw or JSON-escaped credential key token values", run: func(t *testing.T) {
			for _, matrix := range [][]rid11Proof{ensure(t, false), ensure(t, true)} {
				for _, p := range matrix {
					require.True(t, p.RawStreamsAudited && p.Returned.CaptureOK)
					if !p.Case.Twin && (p.Case.Variant == "deleted-creator" || p.Case.Variant == "revoked-key" || p.Case.Variant == "bad-signature") {
						require.True(t, p.PublicTokenRefused)
					}
				}
			}
		}})
}
func TestRID_12_ClosedShapeAndBounds(t *testing.T) {
	var noGD, negative, twins []*rid12Proof
	attempted := map[string]bool{}
	ensure := func(t *testing.T, kind string) []*rid12Proof {
		t.Helper()
		var target *[]*rid12Proof
		switch kind {
		case "no-GD":
			target = &noGD
		case "negative":
			target = &negative
		case "lawful-twin":
			target = &twins
		default:
			t.Fatal("unknown RID12 matrix kind")
		}
		if !attempted[kind] {
			attempted[kind] = true // до любого t.Fatal; без слепых повторов последующими предикатами
			*target = rid12Matrix(t, kind, nil)
		}
		want := 15
		if kind == "no-GD" {
			want = 2
		}
		require.Len(t, *target, want, "earlier matrix failed; evidence reuse cannot allocate replacement PG worlds")
		return *target
	}
	runInstallationRID(t,
		ridPredicate{name: "absent and empty GD field normal full seed success zero GD", run: func(t *testing.T) {
			for _, p := range ensure(t, "no-GD") {
				require.True(t, p.NoGD)
				require.False(t, p.Invalid)
				require.False(t, p.Return.ErrorPresent)
				require.Zero(t, p.Return.CapturedRecords)
				require.Zero(t, p.Return.IssuedTokens)
				require.Empty(t, p.Census.Delegations)
				require.Empty(t, p.Raw)
				require.NotEmpty(t, p.Census.ServiceAccounts)
				require.NotEqual(t, p.Before.Delivery, p.After.Delivery)
			}
		}},
		ridPredicate{name: "unknown field each empty or duplicate axis and17roles17types5subjects rejected before all writes", run: func(t *testing.T) {
			rid12RequireNegative(t, ensure(t, "negative"))
		}},
		ridPredicate{name: "UNSPECIFIED unknown enum iam module role type rejected exact fields", run: func(t *testing.T) {
			proofs := ensure(t, "negative")
			rid12RequireNegative(t, proofs)
			found := map[string]bool{}
			for _, p := range proofs {
				switch p.Name {
				case "subject-unspecified", "subject-unknown", "iam-role", "iam-type", "iam-module":
					found[p.Name] = true
					require.NotEmpty(t, p.Input.Field)
					if p.Name == "iam-module" {
						require.Equal(t, "manifests[1].roles[0].id", p.Input.Field)
					}
				}
			}
			require.Len(t, found, 5)
		}},
		ridPredicate{name: "all17 lawful catalog types and roles retained; legal16/16/4 N pairs", run: func(t *testing.T) {
			proofs := ensure(t, "lawful-twin")
			boundary := 0
			for _, p := range proofs {
				require.False(t, p.Invalid)
				require.False(t, p.NoGD)
				require.False(t, p.Return.ErrorPresent)
				require.Len(t, p.Census.Delegations, 6)
				if p.Name == "roles17" || p.Name == "types17" || p.Name == "subjects5" {
					boundary++
					declarations := rid12Declarations(t, p.Input)
					m := declarations["ridbounds"]
					require.NotNil(t, m)
					require.Len(t, m.Roles, 17)
					require.Len(t, m.Resources, 17)
					require.Len(t, m.Seed.GrantDelegations[0].RoleIDs, 16)
					require.Len(t, m.Seed.GrantDelegations[0].TargetTypes, 16)
					require.Len(t, m.Seed.GrantDelegations[0].SubjectTypes, 4)
				}
			}
			require.Equal(t, 3, boundary)
		}},
		ridPredicate{name: "single-bad-field-only repair twins; array reorder idempotence", run: func(t *testing.T) {
			proofs := ensure(t, "lawful-twin")
			require.Len(t, proofs, 15)
			repeated := 0
			for _, p := range proofs {
				require.Equal(t, p.Input.LegalM2Digest, p.Input.M2Digest)
				if p.Reordered {
					repeated++
					require.Equal(t, "roles17", p.Name)
					require.Equal(t, p.Census, p.RepeatCensus)
					require.Equal(t, p.Raw, p.RepeatRaw)
					require.Len(t, p.Raw, 6)
					require.False(t, p.RepeatReturn.ErrorPresent)
				}
			}
			require.Equal(t, 1, repeated, "one second full startup in the same boundary lawful world")
		}})
}

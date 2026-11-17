// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Test-binary-only bridge: compare real readers and the private adapter in the
// SAME actual RR transaction. The caller owns the fixture and rolls it back.
func BindingCapturedGroupDifferentialForTest(t *testing.T, ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, binding domain.AccessBindingID, ids []string) {
	t.Helper()
	var isolation string
	require.NoError(t, tx.QueryRow(ctx, `SHOW transaction_isolation`).Scan(&isolation))
	require.Equal(t, "repeatable read", isolation)
	var halves catalog.Halves
	require.NoError(t, json.Unmarshal(bundle.CanonicalCatalog(), &halves))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	engine := reconcile.New(nil, slog.Default(), catalog.Fixed{F: facts})
	reader := &abReader{tx: tx}
	b, err := reader.Get(ctx, binding)
	require.NoError(t, err)
	b.Subjects, err = reader.ListSubjects(ctx, binding)
	require.NoError(t, err)
	roles, err := loadRolesWithLifecycleMode(ctx, tx, []string{string(b.RoleID)}, rowLock(""))
	require.NoError(t, err)
	bs := bindingScopeFrom(facts, b, roles[b.RoleID])
	legacy := &bindingSnapshotStore{reconcileStore: &reconcileStore{tx: tx, cat: facts}}
	life, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	require.NoError(t, err)
	source, err := newResourceSourceCapture(tx, &relverdict.AdministrativeReadBudget{}, life)
	require.NoError(t, err)
	parents, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	sequence := &bindingSequenceCapture{parents: parents, binding: binding}
	for i, id := range ids {
		coord := reconcile.MemberCoord{ObjectType: "iam.group", ObjectID: id}
		oldObject, oldPresent, err := legacy.GetIAMDirectObject(ctx, coord.ObjectType, id)
		require.NoError(t, err)
		ancestors, err := legacy.AncestorObjects(ctx, coord.ObjectType, id)
		require.NoError(t, err)
		old, err := engine.CaptureStagedBindingCoordinate(ctx, legacy, bs, coord, oldObject, oldPresent, ancestors)
		require.NoError(t, err)
		before := source.budget.RemainingReads()
		captured, object, present, err := sequence.captureGroup(ctx, legacy, id)
		require.NoError(t, err)
		require.Equal(t, before-3, source.budget.RemainingReads(), "three actual canonical SQL reads, including empty witnesses")
		require.Equal(t, oldObject, object)
		require.Equal(t, oldPresent, present)
		got, err := engine.CaptureStagedBindingCoordinate(ctx, captured, bs, coord, object, present, ancestors)
		require.NoError(t, err)
		require.Equal(t, old.Current, got.Current, "all statuses and rule_fp order")
		require.ElementsMatch(t, old.Ledger, got.Ledger, "unordered SQL ledger preserves multiplicity")
		require.Equal(t, old.Desired, got.Desired)
		require.Equal(t, old.Live, got.Live)
		if i < 2 {
			require.Len(t, got.Current, 3)
			require.Len(t, got.Ledger, 4)
		}
		if i == 0 {
			require.NotEmpty(t, got.Desired)
		}
		// ORDER BY is absent from the old ledger SQL. Normalize only that
		// unordered input before comparing the unchanged command compiler.
		orderLedger := func(rows []reconcile.LedgerRow) {
			slices.SortFunc(rows, func(a, b reconcile.LedgerRow) int {
				x, _ := json.Marshal(a)
				y, _ := json.Marshal(b)
				return strings.Compare(string(x), string(y))
			})
		}
		orderLedger(old.Ledger)
		orderLedger(got.Ledger)
		for _, converge := range []bool{false, true} {
			a, e := reconcile.CompileCapturedBindingCoordinate(ctx, old, coord, converge)
			require.NoError(t, e)
			b, e := reconcile.CompileCapturedBindingCoordinate(ctx, got, coord, converge)
			require.NoError(t, e)
			// applyDiff iterates currentByKey (a Go map) for removals;
			// compare exact command multiplicities without inventing an order.
			require.ElementsMatch(t, a, b)
			if i == 1 {
				require.False(t, present)
				require.NotEmpty(t, got.Current)
				require.NotEmpty(t, got.Ledger)
				require.NotEmpty(t, b, "missing group retains cleanup commands")
				kinds := map[string]bool{}
				for _, command := range b {
					kinds[command.Kind] = true
				}
				for _, kind := range []string{"forget", "delete", "member_delete"} {
					require.True(t, kinds[kind], kind)
				}
			}
		}
		before = source.budget.RemainingReads()
		require.NoError(t, sequence.captureCoordinate(ctx, coord.ObjectType, id, got, nil, captured))
		require.Equal(t, before-1, source.budget.RemainingReads(), "cache hits plus retained real ancestor read")
		if i == 0 {
			membersKey := resourceSourceKey{kind: resourceSourceObjectMembers, typ: coord.ObjectType, id: id}
			ledgerKey := resourceSourceKey{kind: resourceSourceObjectLedger, typ: coord.ObjectType, id: id}
			require.Greater(t, len(source.entries[membersKey]), len(got.Current), "foreign binding rows remain in witness")
			require.Greater(t, len(source.entries[ledgerKey]), len(got.Ledger))
			_, err = captured.CurrentMembersForObject(ctx, "acb_wrong", coord.ObjectType, id)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			_, err = captured.CurrentMembersForObject(ctx, binding, "iam.account", id)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			_, err = captured.LedgerTuplesForMember(ctx, binding, reconcile.MemberCoord{ObjectType: coord.ObjectType, ObjectID: "grp_wrong"})
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			_, _, _, err = sequence.captureGroup(ctx, legacy, "")
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			cancelled, cancelRead := context.WithCancel(ctx)
			cancelRead()
			_, err = captured.CurrentMembersForObject(cancelled, binding, coord.ObjectType, id)
			require.ErrorIs(t, err, context.Canceled)
			source.sealed = true
			_, err = captured.CurrentMembersForObject(ctx, binding, coord.ObjectType, id)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			source.sealed = false
			otherStage := *sequence
			require.ErrorIs(t, captured.check(ctx, &otherStage, coord.ObjectType, id), kaname.ErrSourceUnconfirmed)
			child, err := tx.Begin(ctx)
			require.NoError(t, err)
			otherStore := &bindingSnapshotStore{reconcileStore: &reconcileStore{tx: child, cat: facts}}
			_, _, _, err = sequence.captureGroup(ctx, otherStore, id)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "same backend, different transaction object")
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			require.NoError(t, child.Rollback(cleanup))
			cancel()
			original := slices.Clone(source.entries[membersKey])
			for _, mutate := range []func(*resourceSourceRow){
				func(row *resourceSourceRow) { row.state = `[]` },
				func(row *resourceSourceRow) { row.value = json.RawMessage(`null`) },
				func(row *resourceSourceRow) {
					var value map[string]any
					require.NoError(t, json.Unmarshal(row.value, &value))
					value["object_id"] = "grp_wrong"
					row.value, err = json.Marshal(value)
					require.NoError(t, err)
					var envelope []json.RawMessage
					require.NoError(t, json.Unmarshal([]byte(row.state), &envelope))
					envelope[2] = row.value
					raw, e := json.Marshal(envelope)
					require.NoError(t, e)
					row.state = string(raw)
				},
			} {
				bad := slices.Clone(original)
				mutate(&bad[0])
				source.entries[membersKey] = bad
				_, _, _, err = sequence.captureGroup(ctx, legacy, id)
				require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
				source.entries[membersKey] = original
			}
		}
		if i == 2 {
			require.False(t, present)
			require.Empty(t, got.Current)
			require.Empty(t, got.Ledger)
			for _, kind := range []resourceSourceKind{resourceSourceIAMObject, resourceSourceObjectMembers, resourceSourceObjectLedger} {
				rows, exists := source.entries[resourceSourceKey{kind: kind, typ: coord.ObjectType, id: id}]
				require.True(t, exists, "known empty, not missing witness")
				require.Empty(t, rows)
			}
		}
	}
}

func TestBindingCapturedGroupRejectsMalformedVersionEnvelope(t *testing.T) {
	for _, row := range []resourceSourceRow{
		{state: `null`, value: json.RawMessage(`{}`)},
		{state: `["x","(0,1)",{}]`, value: json.RawMessage(`{}`)},
		{state: `["123","not-a-tid",{}]`, value: json.RawMessage(`{}`)},
		{state: `["123","(0,1)",{"id":"a"}]`, value: json.RawMessage(`{"id":"b"}`)},
		{state: `["123","(0,1)",null]`, value: json.RawMessage(`null`)},
	} {
		_, err := bindingCapturedValue(row)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
	_, err := bindingCapturedText(map[string]json.RawMessage{}, "binding_id")
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

// No product hook: the test owns a real stage and observes its budget object.
// RC uses the production entry/locks/prepare and always rolls back; successful
// full apply/commit is tested by the original delta measurements separately.
type BindingCapturedBudgetForTest struct {
	SourceKeys, Coordinates, Groups, Commands, Descriptors int
	AfterRRRows, AfterRRReads                              int
	BeforePrepareRows, BeforePrepareReads                  int
	AfterPrepareRows, AfterPrepareReads                    int
}

func ProbeBindingCapturedBudgetForTest(t *testing.T, ctx context.Context, repo *Repository, bundle *granteffect.Bundle, id domain.AccessBindingID) BindingCapturedBudgetForTest {
	t.Helper()
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	p, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := p.stage(ctx, id, false)
	require.NoError(t, err)
	defer stage.close()
	require.NotNil(t, stage.sequence)
	s := stage.sequence
	budget := s.parents.source.budget
	out := BindingCapturedBudgetForTest{SourceKeys: len(s.parents.source.entries), Coordinates: len(s.coordinates), AfterRRRows: budget.RemainingRows(), AfterRRReads: budget.RemainingReads()}
	for _, coordinate := range s.coordinates {
		if coordinate.Type == "iam.group" {
			out.Groups++
		}
		out.Commands += len(coordinate.Commands)
	}
	in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityBinding, Bundle: bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
	var accounts []string
	if !stage.global {
		for a := range stage.accounts {
			accounts = append(accounts, a)
		}
		slices.Sort(accounts)
		in.Plan.Mode = kaname.AuthorityFenceAccounts
		for _, a := range accounts {
			in.Plan.Accounts = append(in.Plan.Accounts, domain.AccountID(a))
			in.Owners = append(in.Owners, kaname.AuthorityOwnerRef{Kind: "account", ID: a})
		}
	}
	expected := stage.epochs
	if accounts != nil {
		expected = map[string]json.RawMessage{"": stage.epochs[""], "$generation": stage.epochs["$generation"]}
		for _, a := range accounts {
			value, ok := stage.epochs[a]
			require.True(t, ok)
			expected[a] = value
		}
	}
	encoded, err := json.Marshal(expected)
	require.NoError(t, err)
	w, err := repo.coordinatedAuthorityWriterWithBegin(ctx, in, "participant", stage.conn.BeginTx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		require.NoError(t, w.Rollback(cleanup))
	}()
	var at time.Time
	require.NoError(t, w.tx.QueryRow(ctx, `SELECT kaname.authority_binding_epoch_lock($1::text[],$2::jsonb)`, accounts, encoded).Scan(&at))
	store := &reconcileStore{tx: w.tx, cat: p.facts, decisionAt: at}
	require.NoError(t, store.AcquireBindingLock(ctx, id))
	require.NoError(t, store.LockBindingsAndRoles(ctx, []domain.AccessBindingID{id}))
	_, err = (&abReader{tx: w.tx}).Get(ctx, id)
	require.NoError(t, err)
	require.NoError(t, grantMutationPreflight(ctx, w.tx, "binding"))
	require.NoError(t, lockGrantChildren(ctx, w.tx))
	require.NoError(t, prelockBindingCommands(ctx, w.tx))
	out.BeforePrepareRows, out.BeforePrepareReads = budget.RemainingRows(), budget.RemainingReads()
	require.NoError(t, s.prepare(ctx, w.tx, id, accounts, encoded))
	require.Same(t, budget, s.parents.source.budget, "whole attempt retains one budget")
	out.AfterPrepareRows, out.AfterPrepareReads = budget.RemainingRows(), budget.RemainingReads()
	// SQL prepare returns commands + maximum descriptors as logical_rows.
	// Derive the exact observed maximum size from that returned charge.
	out.Descriptors = out.BeforePrepareRows - out.AfterPrepareRows - out.Commands
	require.GreaterOrEqual(t, out.Descriptors, 0)
	require.Equal(t, out.AfterRRRows, out.BeforePrepareRows)
	require.Equal(t, out.AfterRRReads, out.BeforePrepareReads)
	require.Less(t, out.AfterPrepareReads, out.BeforePrepareReads)
	require.GreaterOrEqual(t, out.AfterPrepareReads, 0)
	return out
}

// Exhaust the unchanged read cap with real SQL on distinct absent predicates.
// Cache hits or a prepaid fake charge cannot satisfy this negative control.
func BindingCapturedGroupReadLimitForTest(t *testing.T, ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle, binding domain.AccessBindingID) {
	t.Helper()
	life, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	require.NoError(t, err)
	budget := &relverdict.AdministrativeReadBudget{}
	source, err := newResourceSourceCapture(tx, budget, life)
	require.NoError(t, err)
	parents, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	sequence := &bindingSequenceCapture{parents: parents, binding: binding}
	store := &bindingSnapshotStore{reconcileStore: &reconcileStore{tx: tx}}
	for i := 0; i < 1365; i++ {
		_, _, present, e := sequence.captureGroup(ctx, store, fmt.Sprintf("grp-captured-cap-%d", i))
		require.NoError(t, e)
		require.False(t, present)
	}
	require.Equal(t, 1, budget.RemainingReads())
	_, _, _, err = sequence.captureGroup(ctx, store, "grp-captured-cap-last")
	require.ErrorIs(t, err, kaname.ErrSourceReadLimit)
	require.Zero(t, budget.RemainingReads())
	require.Len(t, source.entries, 4096, "4096 completed distinct actual source SQLs; next read refused")
	require.Empty(t, sequence.coordinates, "partial capture never becomes a completed coordinate")
}

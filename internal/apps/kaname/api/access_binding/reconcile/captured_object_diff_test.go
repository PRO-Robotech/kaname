// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func capturedDiffFixture(id string) CapturedObjectDiff {
	return CapturedObjectDiff{Binding: BindingScope{BindingID: domain.AccessBindingID(id), RoleID: "role", Active: true, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "user"}}}, Live: map[MemberCoord]bool{{ObjectType: "vpc.network", ObjectID: "network"}: true}}
}
func capturedDiffTuple() domain.MembershipTuple {
	return domain.MembershipTuple{User: "user:user", Relation: "v_get", Object: "network:network"}
}
func capturedDiffCurrent(id, fp string) domain.TargetMember {
	return domain.TargetMember{BindingID: domain.AccessBindingID(id), RoleID: "role", RuleFP: fp, ObjectType: "vpc.network", ObjectID: "network", VerificationStatus: domain.VerificationActive}
}
func capturedDiffDesired(fp string, status domain.VerificationStatus) DesiredMember {
	out := DesiredMember{RuleFP: fp, ObjectType: "vpc.network", ObjectID: "network", Status: status}
	if status == domain.VerificationActive {
		out.Tuples = []domain.MembershipTuple{capturedDiffTuple()}
	}
	return out
}
func capturedDiffLedger() []LedgerRow {
	return []LedgerRow{{Member: MemberCoord{ObjectType: "vpc.network", ObjectID: "network"}, Tuple: capturedDiffTuple()}}
}

func TestCapturedObjectDiffActiveRejectedPreservesForgetBeforeDelete(t *testing.T) {
	in := capturedDiffFixture("binding")
	in.Current = []domain.TargetMember{capturedDiffCurrent("binding", "rule")}
	in.Desired = []DesiredMember{capturedDiffDesired("rule", domain.VerificationRejected)}
	in.Ledger = capturedDiffLedger()
	commands, err := CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{in})
	require.NoError(t, err)
	var kinds []string
	for _, command := range commands {
		kinds = append(kinds, command.Kind)
	}
	require.Equal(t, []string{"members", "forget", "audit", "delete"}, kinds)
	require.Equal(t, capturedDiffLedger(), commands[1].Rows)
	require.Equal(t, []domain.MembershipTuple{capturedDiffTuple()}, commands[3].Tuples)
	require.Len(t, in.Ledger, 1, "компиляция не меняет caller snapshot")
}

func TestCapturedObjectDiffSurvivingRuleKeepsSharedLedger(t *testing.T) {
	in := capturedDiffFixture("binding")
	in.Current = []domain.TargetMember{capturedDiffCurrent("binding", "old"), capturedDiffCurrent("binding", "surviving")}
	in.Desired = []DesiredMember{capturedDiffDesired("surviving", domain.VerificationActive)}
	in.Ledger = capturedDiffLedger()
	commands, err := CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{in})
	require.NoError(t, err)
	require.Len(t, commands, 1)
	require.Equal(t, "member_delete", commands[0].Kind)
	require.Equal(t, "old", commands[0].RuleFP)
}

func TestCapturedObjectDiffFanoutSubtractsNewWriteFromDeferredDelete(t *testing.T) {
	old := capturedDiffFixture("old")
	old.Current = []domain.TargetMember{capturedDiffCurrent("old", "rule")}
	old.Ledger = capturedDiffLedger()
	fresh := capturedDiffFixture("new")
	fresh.Additive = true
	fresh.Desired = []DesiredMember{capturedDiffDesired("rule", domain.VerificationActive)}
	commands, err := CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{old, fresh})
	require.NoError(t, err)
	writes := 0
	for _, command := range commands {
		require.NotEqual(t, "delete", command.Kind)
		if command.Kind == "write" {
			writes += len(command.Tuples)
		}
	}
	require.Equal(t, 1, writes)
}

func TestCapturedObjectDiffMissingMirrorObservationFailsClosed(t *testing.T) {
	in := capturedDiffFixture("binding")
	in.Live = nil
	in.Desired = []DesiredMember{capturedDiffDesired("rule", domain.VerificationActive)}
	_, err := CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{in})
	require.ErrorIs(t, err, ErrIncompleteObjectDiff)
	in.Additive = true
	_, err = CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{in})
	require.ErrorIs(t, err, ErrIncompleteObjectDiff)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = CompileCapturedObjectDiff(ctx, []CapturedObjectDiff{in})
	require.ErrorIs(t, err, context.Canceled)
}

// Проверяется настоящий producer и его wire payload, а не вручную собранный JSON.
func TestCapturedObjectDiffCommandPayloadArrays(t *testing.T) {
	for _, tc := range []struct {
		name     string
		additive bool
		status   domain.VerificationStatus
		kinds    []string
	}{
		{name: "empty_full", kinds: []string{}},
		{name: "empty_additive", additive: true, kinds: []string{"members", "write", "record"}},
		{name: "rejected_additive", additive: true, status: domain.VerificationRejected, kinds: []string{"members", "write", "record"}},
		{name: "rejected_full", status: domain.VerificationRejected, kinds: []string{"members", "audit"}},
		{name: "active_additive", additive: true, status: domain.VerificationActive, kinds: []string{"members", "write", "record"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := capturedDiffFixture("binding")
			in.Additive = tc.additive
			if tc.status != "" {
				in.Desired = []DesiredMember{capturedDiffDesired("rule", tc.status)}
			}
			commands, err := CompileCapturedObjectDiff(context.Background(), []CapturedObjectDiff{in})
			require.NoError(t, err)
			kinds := make([]string, 0, len(commands))
			for _, command := range commands {
				kinds = append(kinds, command.Kind)
				encoded, marshalErr := json.Marshal(command)
				require.NoError(t, marshalErr)
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(encoded, &fields))
				field := map[string]string{"members": "Members", "record": "Refs", "forget": "Rows", "write": "Tuples", "delete": "Tuples"}[command.Kind]
				if field != "" {
					require.NotEmpty(t, fields[field], "закрытое поле команды обязательно")
					require.Equal(t, byte('['), fields[field][0], "payload должен быть массивом, включая пустой")
					if tc.status == "" || (tc.additive && tc.status == domain.VerificationRejected) {
						require.Equal(t, "[]", string(fields[field]), "пустой проход не создаёт эффекты")
					}
				}
			}
			require.Equal(t, tc.kinds, kinds, "команды и их порядок сохраняются")
			if tc.status == domain.VerificationActive {
				require.Equal(t, []domain.TargetMember{capturedDiffCurrent("binding", "rule")}, commands[0].Members)
				require.Equal(t, []domain.MembershipTuple{capturedDiffTuple()}, commands[1].Tuples)
				require.Equal(t, []EmittedTupleRef{{BindingID: "binding", Member: MemberCoord{ObjectType: "vpc.network", ObjectID: "network"}, Tuple: capturedDiffTuple()}}, commands[2].Refs)
			}
			if !tc.additive && tc.status == domain.VerificationRejected {
				expected := capturedDiffCurrent("binding", "rule")
				expected.VerificationStatus = domain.VerificationRejected
				require.Equal(t, []domain.TargetMember{expected}, commands[0].Members)
				require.Equal(t, "binding", string(commands[1].Binding))
				require.Equal(t, MemberCoord{ObjectType: "vpc.network", ObjectID: "network"}, commands[1].Member)
			}
		})
	}
}

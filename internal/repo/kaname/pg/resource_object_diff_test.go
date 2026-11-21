// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/stretchr/testify/require"
)

func TestResourceCoordinateDiffRetainsStaleMembersAndLedger(t *testing.T) {
	binding := domain.AccessBinding{ID: "abn_object", RoleID: "rol_object", Status: domain.AccessBindingStatusActive,
		ResourceType: "account", ResourceID: "acc_object", Scope: domain.ScopeAccount,
		Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr_object"}}}
	capture := &resourceOutputCapture{object: domain.ResourceRef{Type: "iam.account", ID: "acc_object"},
		selected: map[string]bool{"abn_object": true}, bindings: map[string]domain.AccessBinding{"abn_object": binding}, roles: map[string]domain.Role{"rol_object": {ID: "rol_object", Lifecycle: domain.RoleLifecycle{State: domain.RoleLifecycleDeclared}}}}
	memberKey := resourceSourceKey{kind: resourceSourceObjectMembers, typ: "iam.account", id: "acc_object"}
	ledgerKey := resourceSourceKey{kind: resourceSourceObjectLedger, typ: "iam.account", id: "acc_object"}
	source := &resourceSourceCapture{budget: &relverdict.AdministrativeReadBudget{}, entries: map[resourceSourceKey][]resourceSourceRow{
		memberKey: {{value: json.RawMessage(`{"binding_id":"abn_object","role_id":"rol_object","rule_fp":"retired","object_type":"iam.account","object_id":"acc_object","verification_status":"ACTIVE"}`)}},
		ledgerKey: {{value: json.RawMessage(`{"binding_id":"abn_object","member_object_type":"iam.account","member_object_id":"acc_object","fga_user":"user:usr_object","relation":"viewer","object":"account:acc_object"}`)}},
	}}
	parents := &resourceParentCapture{source: source}
	object := domain.MirrorObject{ObjectType: "iam.account", ObjectID: "acc_object"}
	inputs, err := capture.coordinateDiffInputs(context.Background(), parents, catalogfixture.Facts(), object, false, nil, false)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	require.Empty(t, inputs[0].Desired)
	require.Len(t, inputs[0].Current, 1)
	require.Len(t, inputs[0].Ledger, 1)
	commands, err := reconcile.CompileCapturedObjectDiff(context.Background(), inputs)
	require.NoError(t, err)
	require.NotEmpty(t, commands)
	// Доказанное отсутствие объекта не отбрасывает старый состав до diff.
	require.Equal(t, "retired", inputs[0].Current[0].RuleFP)
	// Holder нужен для fold proof, но без выбора member/match не запускает
	// materialization: кандидатный census и защитный census различаются.
	capture.selected = map[string]bool{}
	unselected, err := capture.coordinateDiffInputs(context.Background(), parents, catalogfixture.Facts(), object, false, nil, false)
	require.NoError(t, err)
	require.Empty(t, unselected)
	capture.selected["abn_object"] = true
	delete(source.entries, ledgerKey)
	_, err = capture.coordinateDiffInputs(context.Background(), parents, catalogfixture.Facts(), object, false, nil, false)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	source.entries[ledgerKey] = []resourceSourceRow{{value: json.RawMessage(`{"binding_id":"abn_object","member_object_type":"iam.account","member_object_id":"foreign","fga_user":"user:usr_object","relation":"viewer","object":"account:acc_object"}`)}}
	_, err = capture.coordinateDiffInputs(context.Background(), parents, catalogfixture.Facts(), object, false, nil, false)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

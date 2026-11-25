// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveCollateralBindingsUnionsCapturedPredicates(t *testing.T) {
	p := parentCaptureFixture(t)
	ref := domain.ResourceRef{Type: "iam.serviceAccount", ID: "svc-1"}
	old := domain.MirrorObject{
		ObjectType: ref.Type, ObjectID: ref.ID, Labels: map[string]string{"team": "red"},
		AccessLabels: map[string]string{"zone": "west"}, ParentAccountIDs: []string{"acc-a"},
	}
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: ref.Type, id: ref.ID}, map[string]any{
		"id": ref.ID, "account_id": "acc-a", "labels": old.Labels, "access_labels": old.AccessLabels,
	})
	next := old
	next.AccessLabels = map[string]string{"team": "red", "zone": "west"}
	overlay := map[domain.ResourceRef]domain.MirrorObject{ref: next}
	const proposal = `{"labels":{"team":"red"},"access_labels":{"team":"red","zone":"west"}}`
	key := func(kind resourceSourceKind) resourceSourceKey {
		return resourceSourceKey{kind: kind, typ: ref.Type, id: ref.ID, projection: proposal}
	}
	hit := func(id string, changes bool) any { return map[string]any{"binding_id": id, "changes": changes} }
	parentCaptureRows(t, p, key(resourceSourceMetadataBindings), hit("changed", true), hit("own", true))
	parentCaptureRows(t, p, key(resourceSourceMetadataAuthoredBindings), hit("only-authored", true), hit("changed", true))
	parentCaptureRows(t, p, key(resourceSourceMetadataBindingCoverage), hit("covers", false), hit("changed", true))
	parentCaptureRows(t, p, key(resourceSourceMetadataHistoricalCarriers), map[string]string{"binding_id": "revoked", "role_id": "rol-other"})
	for _, id := range []string{"changed", "only-authored", "covers", "revoked", "own"} {
		owner := "rol-other"
		if id == "own" {
			owner = "rol-moving"
		}
		parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceBinding, typ: "binding", id: id}, map[string]string{"id": id, "role_id": owner})
	}
	ids, err := p.captureAccessLabelMoveCollateralBindings(t.Context(), overlay, "rol-moving")
	require.NoError(t, err)
	require.Equal(t, []domain.AccessBindingID{"changed", "covers", "only-authored", "revoked"}, ids)

	parentCaptureRows(t, p, key(resourceSourceMetadataHistoricalCarriers), map[string]string{"binding_id": "revoked", "role_id": "rol-moving"})
	_, err = p.captureAccessLabelMoveCollateralBindings(t.Context(), overlay, "rol-moving")
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestAccessLabelMoveCollateralScopesKeepPendingCandidatesAndRevokedLedger(t *testing.T) {
	p := parentCaptureFixture(t)
	const typ = "registry.registries"
	const roleID domain.RoleID = "rol-foreign"
	const id domain.AccessBindingID = "acb-foreign"
	const account = "acc-owner"
	predicate := map[string]string{"team": "red"}
	role := domain.Rules{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, MatchAccessLabels: predicate}}
	facts, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules:   []string{"registry"},
		Resources: []catalog.ResourceRow{{Module: "registry", Resource: "registries", ObjectType: "registry_registry"}},
		Verbs:     []catalog.VerbRow{{Module: "registry", Resource: "registries", Verb: "get", PerObject: true}},
	}})
	require.NoError(t, err)
	rules, err := domain.EncodeRules(role)
	require.NoError(t, err)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(roleID)}, map[string]any{
		"id": roleID, "account_id": account, "labels": map[string]string{}, "permissions": []string{}, "rules": json.RawMessage(rules), "live": true,
	})
	fp := role[0].Fingerprint()
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceRoleSelectors, typ: "role", id: string(roleID)},
		map[string]any{"rule_fp": fp, "role_id": roleID})
	key := func(kind resourceSourceKind) resourceSourceKey {
		return resourceSourceKey{kind: kind, typ: "binding", id: string(id)}
	}
	binding := map[string]any{
		"id": id, "role_id": roleID, "scope": domain.ScopeAccount, "resource_type": "account", "resource_id": account,
		"created_at": time.Unix(100, 0).UTC(), "status": domain.AccessBindingStatusPending, "subject_type": "user", "subject_id": "usr-x",
		"labels": map[string]string{}, "target": map[string]bool{"allInScope": true},
	}
	parentCaptureRows(t, p, key(resourceSourceBinding), binding)
	parentCaptureRows(t, p, key(resourceSourceBindingSubjects), map[string]any{
		"binding_id": id, "subject_type": "user", "subject_id": "usr-x", "ordinal": 0, "resource_type": "account", "resource_id": account,
	})
	previous := domain.ResourceRef{Type: typ, ID: "removed"}
	parentCaptureRows(t, p, key(resourceSourceBindingMembers))
	parentCaptureRows(t, p, key(resourceSourceBindingLedger), map[string]any{
		"binding_id": id, "member_object_type": typ, "member_object_id": previous.ID,
		"fga_user": "user:usr-x", "relation": "v_get", "object": "registry_registry:removed",
	})
	object := domain.ResourceRef{Type: typ, ID: "registry-x"}
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: typ, id: object.ID}, map[string]any{
		"object_type": typ, "object_id": object.ID, "parent_account_id": account, "labels": predicate, "access_labels": map[string]string{},
	})
	raw, err := json.Marshal(resourceSelectorPredicate{
		RuleFP: fp, Scope: domain.ScopeAnchor{Type: "account", ID: account}, Arm: domain.ArmAccessLabels, Targets: []string{}, AccessLabels: predicate,
	})
	require.NoError(t, err)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceSelectorObjects, typ: typ, id: string(id), projection: string(raw)})
	overlay := map[domain.ResourceRef]domain.MirrorObject{object: {
		ObjectType: typ, ObjectID: object.ID, ParentAccountIDs: []string{account}, Labels: predicate, AccessLabels: predicate,
	}}
	scopes, err := p.captureAccessLabelMoveCollateralScopes(t.Context(), facts, []domain.AccessBindingID{id}, overlay)
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	require.Equal(t, scopes[0].Before, scopes[0].Proposed)
	require.Equal(t, string(roleID), scopes[0].Before.RoleID)
	require.False(t, scopes[0].Before.Active)
	require.ElementsMatch(t, []domain.ResourceRef{object, previous, {Type: "iam.account", ID: account}}, scopes[0].Coordinates)
	require.Len(t, scopes[0].Carrier.Ledger, 1)

	binding["status"] = domain.AccessBindingStatusRevoked
	binding["revoked_at"] = time.Unix(200, 0).UTC()
	parentCaptureRows(t, p, key(resourceSourceBinding), binding)
	scopes, err = p.captureAccessLabelMoveCollateralScopes(t.Context(), facts, []domain.AccessBindingID{id}, overlay)
	require.NoError(t, err)
	require.Len(t, scopes, 1)
	require.Equal(t, []domain.ResourceRef{previous}, scopes[0].Coordinates)
	require.Len(t, scopes[0].Carrier.Ledger, 1)
}

func TestAccessLabelMoveCollateralProjectionChecksCopyAgainstOldObject(t *testing.T) {
	old := domain.MirrorObject{ObjectType: "iam.serviceAccount", ObjectID: "svc-a",
		Labels: map[string]string{"team": "red"}, AccessLabels: map[string]string{"zone": "west"}}
	proposal, err := accessLabelMoveCollateralProjection(old, old)
	require.NoError(t, err)
	require.Empty(t, proposal)
	for _, labels := range []map[string]string{
		{"team": "red"}, {"zone": "east"}, {"zone": "west", "team": "blue"}, {"zone": "west", "missing": ""},
	} {
		next := old
		next.AccessLabels = labels
		_, err := accessLabelMoveCollateralProjection(old, next)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
	next := old
	next.ObjectType = "iam.serviceaccount"
	_, err = accessLabelMoveCollateralProjection(old, next)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

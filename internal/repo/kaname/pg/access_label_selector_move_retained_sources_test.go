// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelMoveRetainedSourcesCaptureExactOutputsAndUntouchedCarrier(t *testing.T) {
	source, tx, _ := resourceSourceFixture(t)
	p, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	const dotted, model = "registry.registries", "registry_registry"
	row := resourceCatalogRow{identity: domain.CatalogTypeIdentity{Module: "registry", Dotted: dotted, ObjectType: model}, live: true}
	for _, name := range []string{model, dotted} {
		p.catalogs[name] = &resourceCatalogCapture{input: name, rows: []resourceCatalogRow{row}}
	}
	for _, name := range []string{"cluster", "iam.cluster"} {
		p.catalogs[name] = &resourceCatalogCapture{input: name}
	}
	const id = "acb-untouched"
	const role = "rol-untouched"
	key := func(kind resourceSourceKind, typ, id string) resourceSourceKey {
		return resourceSourceKey{kind: kind, typ: typ, id: id}
	}
	parentCaptureRows(t, p, key(resourceSourceMirror, dotted, "ancestor"), map[string]string{"object_type": dotted, "object_id": "ancestor"})
	parentCaptureRows(t, p, key(resourceSourceMirror, dotted, "different"), map[string]string{"object_type": dotted, "object_id": "different"})
	parentCaptureRows(t, p, key(resourceSourceParentEdges, model, "different"), map[string]any{
		"parent_type": model, "parent_id": "ancestor", "depth": 1,
	})
	parentCaptureRows(t, p, key(resourceSourceFactLedgerHolders, model, "gone"), map[string]string{
		"binding_id": id, "member_object_type": dotted, "member_object_id": "different", "object": model + ":gone", "fga_user": "user:u", "relation": "viewer",
	})
	parentCaptureRows(t, p, key(resourceSourceBinding, "binding", id), map[string]any{
		"id": id, "role_id": role, "subject_type": "user", "subject_id": "u", "labels": map[string]string{}, "target": map[string]bool{"allInScope": true},
	})
	parentCaptureRows(t, p, key(resourceSourceRole, "role", role), map[string]any{
		"id": role, "live": true, "permissions": []string{}, "rules": []any{}, "labels": map[string]string{},
	})
	parentCaptureRows(t, p, key(resourceSourceRoleMoveCluster, "cluster", domain.ClusterSingletonID), map[string]string{"id": domain.ClusterSingletonID})

	scope := func(objects ...string) accessLabelSelectorMoveScope {
		var out accessLabelSelectorMoveScope
		for _, object := range objects {
			out.Carrier.Ledger = append(out.Carrier.Ledger, reconcile.LedgerRow{Tuple: domain.MembershipTuple{Object: object}})
		}
		return out
	}
	capture := accessLabelSelectorMoveCapture{
		Graphs: map[domain.ResourceRef]accessLabelMoveGraph{
			{Type: dotted, ID: "present"}: {Present: true, Object: domain.MirrorObject{ObjectType: dotted, ObjectID: "present"}, Ancestors: []domain.MirrorObject{{ObjectType: dotted, ObjectID: "ancestor"}}},
		},
		Carriers:   []accessLabelSelectorMoveScope{scope(model+":present", model+":gone")},
		Collateral: []accessLabelSelectorMoveScope{scope(model+":gone", "cluster:"+domain.ClusterSingletonID)},
	}
	retained, err := p.captureAccessLabelMoveRetainedSources(t.Context(), capture)
	require.NoError(t, err)
	require.Len(t, retained, 4)
	require.True(t, retained[domain.ResourceRef{Type: model, ID: "ancestor"}].graph.Present)
	physical := retained[domain.ResourceRef{Type: model, ID: "gone"}]
	require.False(t, physical.graph.Present)
	require.Equal(t, dotted, physical.output.object.Type)
	require.Contains(t, physical.output.bindings, id)
	require.Contains(t, physical.output.roles, role)
	member := physical.memberGraphs[domain.ResourceRef{Type: dotted, ID: "different"}]
	require.True(t, member.Present)
	require.Equal(t, "different", member.Object.ObjectID)
	require.Len(t, member.Ancestors, 1)
	require.Equal(t, "ancestor", member.Ancestors[0].ObjectID)
	require.Contains(t, source.entries, key(resourceSourceBindingMembers, "binding", id))
	require.Contains(t, source.entries, key(resourceSourceRoleVerbs, "role", role))
	require.Contains(t, source.entries, key(resourceSourceMirror, dotted, "gone"))
	for _, id := range []string{"present", "ancestor", "gone"} {
		require.Contains(t, source.entries, key(resourceSourceFactLedgerHolders, model, id))
		require.Contains(t, source.entries, key(resourceSourceObjectMembers, dotted, id))
		require.Contains(t, source.entries, key(resourceSourceRegistrationPointers, model, id))
	}
	cluster := retained[domain.ResourceRef{Type: "cluster", ID: domain.ClusterSingletonID}]
	require.True(t, cluster.clusterPresent)
	require.False(t, cluster.graph.Present)
	require.Contains(t, source.entries, key(resourceSourceClusterFactHolders, "cluster", domain.ClusterSingletonID))
	require.Contains(t, source.entries, key(resourceSourceFactLedgerHolders, "cluster", domain.ClusterSingletonID))
	require.Contains(t, source.entries, key(resourceSourceObjectLedger, "iam.cluster", domain.ClusterSingletonID))
}

func TestAccessLabelMoveRetainedSourcesRejectAmbiguousOrInvalidOutput(t *testing.T) {
	p := parentCaptureFixture(t)
	first := resourceCatalogRow{identity: domain.CatalogTypeIdentity{Dotted: "registry.a", ObjectType: "registry_x", Module: "registry"}, live: true}
	retired := resourceCatalogRow{identity: domain.CatalogTypeIdentity{Dotted: "registry.b", ObjectType: "registry_x", Module: "registry"}}
	p.catalogs["registry.a"] = &resourceCatalogCapture{rows: []resourceCatalogRow{first}}
	p.catalogs["registry_x"] = &resourceCatalogCapture{rows: []resourceCatalogRow{first, retired}}
	for _, typ := range []string{"registry.a", "registry_x"} {
		_, err := p.accessLabelMoveOutputCatalog(t.Context(), domain.ResourceRef{Type: typ, ID: "id"})
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
	_, err := p.accessLabelMoveOutputCatalog(t.Context(), domain.ResourceRef{Type: "cluster", ID: "other"})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	p.catalogs["cluster"] = &resourceCatalogCapture{}
	p.catalogs["iam.cluster"] = &resourceCatalogCapture{rows: []resourceCatalogRow{{identity: domain.CatalogTypeIdentity{ObjectType: "other", Dotted: "iam.cluster"}}}}
	_, err = p.accessLabelMoveOutputCatalog(t.Context(), domain.ResourceRef{Type: "cluster", ID: domain.ClusterSingletonID})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	key := resourceSourceKey{kind: resourceSourceRoleMoveCluster, typ: "cluster", id: domain.ClusterSingletonID}
	query, args, err := resourceSourceSQL(key, 3)
	require.NoError(t, err)
	require.Contains(t, query, "FROM ONLY kaname.clusters r WHERE r.id=$1 LIMIT $2")
	require.Equal(t, []any{domain.ClusterSingletonID, 3}, args)
	require.True(t, key.kind.roleMoveOnly())
	key.id = "other"
	_, _, err = resourceSourceSQL(key, 3)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)

	capture := accessLabelSelectorMoveCapture{Graphs: map[domain.ResourceRef]accessLabelMoveGraph{}, Collateral: []accessLabelSelectorMoveScope{{
		Carrier: accessLabelSelectorMoveCarrier{Ledger: []reconcile.LedgerRow{{Tuple: domain.MembershipTuple{Object: "registry.a:id"}}}},
	}}}
	_, err = p.captureAccessLabelMoveRetainedSources(t.Context(), capture)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, p.source.budget.Charge(p.source.budget.RemainingRows(), 0))
	_, err = p.captureAccessLabelMoveRetainedSources(t.Context(), capture)
	require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func parentPathGraph() ParentHierarchyGraph {
	scope := ContainerScope{Registered: true, ProjectID: "p", AccountID: "a"}
	return ParentHierarchyGraph{
		"probemod_item:i": {Ref: "probemod_item:i", Scope: scope, Parents: []string{"probemod_box:b"}},
		"probemod_box:b":  {Ref: "probemod_box:b", Scope: scope, Parents: []string{"project:p"}},
		"project:p":       {Ref: "project:p", Scope: scope},
	}
}

func TestParentHierarchyFullCanonicalPathAndClaims(t *testing.T) {
	graph := parentPathGraph()
	before := parentPathGraph()
	hs, err := BuildParentHierarchies("probemod_item:i", graph)
	require.NoError(t, err)
	require.Equal(t, []ParentHierarchy{{Links: []string{"probemod_item:i", "probemod_box:b", "project:p", "account:a"}, ProjectID: "p", AccountID: "a"}}, hs)
	require.Equal(t, before, graph, "построение не меняет снимок источника")
	for _, tc := range []struct {
		name  string
		claim ParentClaim
		allow bool
	}{
		{"complete", ParentClaim{ProjectID: "p", AccountID: "a", Chain: hs[0].Links}, true},
		{"subsequence", ParentClaim{Chain: []string{"probemod_box:b", "account:a"}}, true},
		{"empty", ParentClaim{}, true},
		{"forged_box", ParentClaim{Chain: []string{"probemod_box:other"}}, false},
		{"swapped", ParentClaim{Chain: []string{"probemod_box:b", "probemod_item:i"}}, false},
		{"duplicate", ParentClaim{Chain: []string{"probemod_box:b", "probemod_box:b"}}, false},
		{"foreign_project", ParentClaim{ProjectID: "q"}, false},
		{"foreign_account", ParentClaim{AccountID: "other"}, false},
		{"cluster_not_stored", ParentClaim{Chain: []string{"cluster:cluster_root"}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) { require.Equal(t, tc.allow, hs[0].Admits(tc.claim)) })
	}
	hs[0].Links[0] = "changed"
	require.Equal(t, before, graph, "выход не разделяет изменяемый slice с входом")
}

func TestParentHierarchyBranchesStaySeparate(t *testing.T) {
	graph := parentPathGraph()
	node := graph["probemod_item:i"]
	node.Parents = []string{"probemod_box:c", "probemod_box:b"}
	graph[node.Ref] = node
	graph["probemod_box:c"] = ParentHierarchyNode{Ref: "probemod_box:c", Scope: node.Scope, Parents: []string{"project:p"}}
	hs, err := BuildParentHierarchies(node.Ref, graph)
	require.NoError(t, err)
	require.Equal(t, []ParentHierarchy{
		{Links: []string{"probemod_item:i", "probemod_box:b", "project:p", "account:a"}, ProjectID: "p", AccountID: "a"},
		{Links: []string{"probemod_item:i", "probemod_box:c", "project:p", "account:a"}, ProjectID: "p", AccountID: "a"},
	}, hs)
	for _, h := range hs {
		require.False(t, h.Admits(ParentClaim{Chain: []string{"probemod_box:b", "probemod_box:c"}}))
	}
}

func TestParentHierarchySavedScopeCeiling(t *testing.T) {
	graph := parentPathGraph()
	node := graph["probemod_item:i"]
	node.Scope = ContainerScope{Registered: true}
	graph[node.Ref] = node
	// Даже существующие текущие указатели не дописывают пропущенный проект DP14.
	hs, err := BuildParentHierarchies(node.Ref, graph)
	require.NoError(t, err)
	require.Equal(t, []ParentHierarchy{{Links: []string{node.Ref}}}, hs)
	require.True(t, hs[0].Admits(ParentClaim{Chain: []string{node.Ref}}))
	require.False(t, hs[0].Admits(ParentClaim{ProjectID: "p"}))
	require.False(t, hs[0].Admits(ParentClaim{Chain: []string{node.Ref, "project:p"}}))
}

func TestParentHierarchyRejectsIncompleteWholeGraph(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(ParentHierarchyGraph)
	}{
		{"missing_root", func(g ParentHierarchyGraph) { delete(g, "probemod_item:i") }},
		{"missing_parent", func(g ParentHierarchyGraph) { delete(g, "probemod_box:b") }},
		{"unregistered", func(g ParentHierarchyGraph) { n := g["probemod_box:b"]; n.Scope.Registered = false; g[n.Ref] = n }},
		{"missing_owner", func(g ParentHierarchyGraph) { n := g["project:p"]; n.Scope.AccountID = ""; g[n.Ref] = n }},
		{"no_immediate_facts", func(g ParentHierarchyGraph) { n := g["probemod_box:b"]; n.Parents = nil; g[n.Ref] = n }},
		{"intermediate_ceiling", func(g ParentHierarchyGraph) {
			n := g["probemod_box:b"]
			n.Scope = ContainerScope{Registered: true}
			g[n.Ref] = n
		}},
		{"other_branch_missing", func(g ParentHierarchyGraph) {
			n := g["probemod_item:i"]
			n.Parents = append(n.Parents, "probemod_box:missing")
			g[n.Ref] = n
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := parentPathGraph()
			tc.change(g)
			hs, err := BuildParentHierarchies("probemod_item:i", g)
			require.ErrorIs(t, err, ErrParentHierarchyIncomplete)
			require.Nil(t, hs)
		})
	}
}

func TestParentHierarchyRejectsInvalidGraph(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(ParentHierarchyGraph)
	}{
		{"cycle", func(g ParentHierarchyGraph) {
			n := g["probemod_box:b"]
			n.Parents = []string{"probemod_item:i"}
			g[n.Ref] = n
		}},
		{"scope_project", func(g ParentHierarchyGraph) { n := g["probemod_box:b"]; n.Scope.ProjectID = "q"; g[n.Ref] = n }},
		{"scope_account", func(g ParentHierarchyGraph) { n := g["probemod_box:b"]; n.Scope.AccountID = "other"; g[n.Ref] = n }},
		{"project_key", func(g ParentHierarchyGraph) { n := g["project:p"]; n.Scope.ProjectID = "q"; g[n.Ref] = n }},
		{"account_without_project", func(g ParentHierarchyGraph) { n := g["probemod_item:i"]; n.Scope.ProjectID = ""; g[n.Ref] = n }},
		{"principal_parent", func(g ParentHierarchyGraph) { n := g["probemod_item:i"]; n.Parents = []string{"user:u"}; g[n.Ref] = n }},
		{"userset_parent", func(g ParentHierarchyGraph) {
			n := g["probemod_item:i"]
			n.Parents = []string{"probemod_box:b#owner"}
			g[n.Ref] = n
		}},
		{"project_parent", func(g ParentHierarchyGraph) { n := g["project:p"]; n.Parents = []string{"project:q"}; g[n.Ref] = n }},
		{"fifth_link", func(g ParentHierarchyGraph) {
			n := g["probemod_box:b"]
			n.Parents = []string{"probemod_outer:o"}
			g[n.Ref] = n
			g["probemod_outer:o"] = ParentHierarchyNode{Ref: "probemod_outer:o", Scope: n.Scope, Parents: []string{"project:p"}}
		}},
		{"fifth_parent", func(g ParentHierarchyGraph) {
			n := g["probemod_item:i"]
			n.Parents = []string{"probemod_box:b", "probemod_box:c", "probemod_box:d", "probemod_box:e", "probemod_box:f"}
			g[n.Ref] = n
		}},
		{"nodes_budget", func(g ParentHierarchyGraph) {
			for i := 0; i < MaxParentHierarchyNodes; i++ {
				ref := fmt.Sprintf("probemod_box:n%d", i)
				g[ref] = ParentHierarchyNode{Ref: ref, Scope: ContainerScope{Registered: true}}
			}
		}},
		{"edges_budget", func(g ParentHierarchyGraph) {
			for i := 0; i < MaxParentHierarchyEdges/4+1; i++ {
				ref := fmt.Sprintf("probemod_box:n%d", i)
				g[ref] = ParentHierarchyNode{Ref: ref, Scope: ContainerScope{Registered: true}, Parents: []string{"project:p", "project:q", "project:r", "project:s"}}
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := parentPathGraph()
			tc.change(g)
			hs, err := BuildParentHierarchies("probemod_item:i", g)
			require.ErrorIs(t, err, ErrParentHierarchyInvalid)
			require.Nil(t, hs)
		})
	}
}

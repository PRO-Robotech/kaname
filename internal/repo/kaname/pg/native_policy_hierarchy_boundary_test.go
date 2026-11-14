// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/hierarchy"
	"github.com/stretchr/testify/require"
)

func TestNativeBoundarySeparatesCompleteParentFanoutFromTraversalDepth(t *testing.T) {
	bundle := nativeBoundaryBundle(t)
	questions := newNativePolicyQuestions()
	require.NoError(t, questions.add(nativeBoundaryActor(), "viewer", "iam_role", "rol_native"))
	root := nativeReadNode{"iam_role", "rol_native"}
	for _, count := range []int{hierarchy.MaxImmediateParents, hierarchy.MaxImmediateParents + 1} {
		t.Run(fmt.Sprintf("parents=%d", count), func(t *testing.T) {
			snapshot := &nativeSnapshotFixture{owners: map[nativeReadNode]string{root: "acc_native"}, edges: map[nativeReadNode][]nativeReadNode{}}
			for i := 0; i < count; i++ {
				parent := nativeReadNode{"iam_role", fmt.Sprintf("rol_parent_%d", i)}
				snapshot.edges[root] = append(snapshot.edges[root], parent)
				snapshot.owners[parent] = "acc_native"
			}
			boundary, err := captureNativeReadBoundary(context.Background(), bundle, questions, snapshot, &nativeReadBudget{})
			require.NoError(t, err)
			require.Equal(t, count > hierarchy.MaxImmediateParents, boundary.global())
			roots, err := questions.ordered(context.Background())
			require.NoError(t, err)
			// Перечень дочитан целиком и при превышении границы; частичного local proof нет.
			require.Len(t, boundary.questions[roots[0]].scopes, count+1)
		})
	}
	for _, hops := range []int{hierarchy.MaxPointerHops, hierarchy.MaxPointerHops + 1} {
		t.Run(fmt.Sprintf("hops=%d", hops), func(t *testing.T) {
			snapshot := &nativeSnapshotFixture{owners: map[nativeReadNode]string{root: "acc_native"}, edges: map[nativeReadNode][]nativeReadNode{}}
			previous := root
			for i := 1; i <= hops; i++ {
				parent := nativeReadNode{"iam_role", fmt.Sprintf("rol_level_%d", i)}
				snapshot.edges[previous] = []nativeReadNode{parent}
				snapshot.owners[parent] = "acc_native"
				previous = parent
			}
			boundary, err := captureNativeReadBoundary(context.Background(), bundle, questions, snapshot, &nativeReadBudget{})
			require.NoError(t, err)
			require.Equal(t, hops > hierarchy.MaxPointerHops, boundary.global())
			roots, err := questions.ordered(context.Background())
			require.NoError(t, err)
			require.Len(t, boundary.questions[roots[0]].scopes, hierarchy.MaxPointerHops+1)
			require.Equal(t, hops > hierarchy.MaxPointerHops, boundary.globalReasons["native ancestor depth reaches query limit"])
		})
	}
}

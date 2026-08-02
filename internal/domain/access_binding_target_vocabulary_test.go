// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

// access_binding_target_vocabulary_test.go — the target type-registry must be the
// SAME vocabulary the reconciler intersects against, and nothing else.
//
// A per-object AccessBinding target is honoured in exactly one place: the
// reconciler calls AccessTarget.Contains(o.ObjectType, o.ObjectID) with
// o.ObjectType taken from the materialization feed (the mirror row / iam-native
// row), and keeps the object only on an exact string match. So the question
// "may a binding name this target type" has one correct answer — "can an object of
// that type ever reach Contains", i.e. is it in AllMaterializableTypes() — and any
// second, separately maintained answer is wrong in both directions at once:
//
//	a type the feed produces but the registry rejects  → the grant cannot be
//	  expressed per-object at all, so the only way to grant it is the whole-anchor
//	  arm. The registry then does not restrict the grant, it WIDENS it.
//	a type the registry accepts but the feed never produces → the binding is
//	  created, stored and reconciled, matches nothing, and grants nothing. Accepted
//	  and ignored (api-conventions.md), which is the failure the caller cannot see.
//
// Both halves are asserted here, and the negative half is DERIVED rather than
// listed: for every live type it re-spells the resource segment in the other
// convention and requires the re-spelling to be refused. A hand-written list of
// today's near-misses would close today's instance and let the next domain's
// through — the same reason the block-storage retire gate is driven off a table.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// snakeResource re-spells a camelCase dotted resource segment in snake_case
// ("routeTable" → "route_table"). It is how the near-miss twins of the live
// vocabulary are produced mechanically.
func snakeResource(resource string) string {
	var b strings.Builder
	for _, r := range resource {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
			b.WriteRune(r - 'A' + 'a')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// TestTargetTypeRegistryIsTheMaterializationFeed — the positive half: every type
// the reconciler can materialize must be nameable as a per-object target.
//
// Without this, the least-privilege arm is unavailable for that resource and the
// caller is pushed onto the whole-anchor arm — a broader grant than they asked
// for, produced by a validation that reads as a restriction.
func TestTargetTypeRegistryIsTheMaterializationFeed(t *testing.T) {
	feed := AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() is empty — this gate would assert nothing")
	t.Logf("scanned: AllMaterializableTypes()=%d dotted types", len(feed))

	var rejected []string
	for _, dotted := range feed {
		if !ValidTargetType(dotted) {
			rejected = append(rejected, dotted)
		}
	}
	require.Emptyf(t, rejected,
		"%d of %d materializable types cannot be named as a per-object target, so the only expressible grant on them is the whole-anchor arm: %v",
		len(rejected), len(feed), rejected)
}

// TestTargetTypeRegistryRefusesTypesTheFeedNeverProduces — the negative half,
// derived from the live vocabulary rather than listed.
//
// Every accepted type that the feed cannot produce is a binding that is created,
// stored, reconciled and grants nothing: Contains() compares the target's dotted
// string to the feed's dotted string, so a re-spelling matches no object ever.
func TestTargetTypeRegistryRefusesTypesTheFeedNeverProduces(t *testing.T) {
	feed := AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() is empty — this gate would assert nothing")

	live := make(map[string]bool, len(feed))
	for _, dotted := range feed {
		live[dotted] = true
	}

	// Twins: same module, resource segment re-spelled in the other convention.
	// Only types whose spelling actually differs produce a twin, so the set
	// shrinks by itself if the vocabulary is ever normalised — an assertion with
	// nothing left to assert must not silently keep passing.
	var twins []string
	for _, dotted := range feed {
		i := strings.IndexByte(dotted, '.')
		require.Greaterf(t, i, 0, "malformed dotted type %q in the materialization feed", dotted)
		module, resource := dotted[:i], dotted[i+1:]
		twin := module + "." + snakeResource(resource)
		if twin == dotted || live[twin] {
			continue
		}
		twins = append(twins, twin)
	}
	require.NotEmptyf(t, twins,
		"no near-miss twin could be derived from %d live types — the vocabulary is single-convention now, so this gate has no subject and must be replaced by whatever guards the new one",
		len(feed))
	t.Logf("scanned: %d derived near-miss twins of %d live types", len(twins), len(feed))

	var accepted []string
	for _, twin := range twins {
		if ValidTargetType(twin) {
			accepted = append(accepted, twin)
		}
	}
	require.Emptyf(t, accepted,
		"%d re-spelled types are accepted as per-object targets although the feed emits the other spelling; a binding naming one is stored and reconciled and matches no object: %v",
		len(accepted), accepted)

	// Control that the predicate is not simply false for everything: the same
	// call on the live spellings must answer true (covered exhaustively by the
	// positive test above; repeated here so THIS test fails on a gutted accessor
	// rather than passing vacuously).
	require.True(t, ValidTargetType(feed[0]), "ValidTargetType(%q) is false — the negative half above proves nothing", feed[0])

	// Malformed and wildcard inputs stay refused.
	for _, bad := range []string{"", "*", "compute", ".instance", "compute.", "unknown.thing"} {
		require.Falsef(t, ValidTargetType(bad), "ValidTargetType(%q) is true", bad)
	}
}

// TestTargetTypeRegistryDoesNotAcceptAnchorVocabularySpellings — the rest of the
// negative half.
//
// The case-convention twins above cannot reach a name that differs by WORD rather
// than by case ("networkLoadBalancers" vs "nlb"). This walks the other vocabulary
// instead: every bare anchor name is un-spelled back into its dotted form, and the
// result must not be an acceptable target unless the feed actually emits it. It
// covers exactly the space a name-derived predicate could reach, so it is the
// regression lock against re-deriving one.
func TestTargetTypeRegistryDoesNotAcceptAnchorVocabularySpellings(t *testing.T) {
	feed := AllMaterializableTypes()
	live := make(map[string]bool, len(feed))
	for _, dotted := range feed {
		live[dotted] = true
	}

	var candidates, accepted []string
	for bare := range validResourceTypes {
		i := strings.IndexByte(string(bare), '_')
		if i <= 0 {
			continue // cluster / account / project / "*" — anchor-only, no dotted form
		}
		dotted := string(bare[:i]) + "." + string(bare[i+1:])
		if live[dotted] {
			continue // the feed does emit this one; the positive half owns it
		}
		candidates = append(candidates, dotted)
		if ValidTargetType(dotted) {
			accepted = append(accepted, dotted)
		}
	}
	require.NotEmptyf(t, candidates,
		"every anchor-vocabulary spelling is also a live feed type — this gate has no subject left and must be replaced by whatever guards the merged vocabulary")
	t.Logf("scanned: %d anchor-vocabulary spellings absent from the %d-type feed", len(candidates), len(feed))

	require.Emptyf(t, accepted,
		"%d anchor-vocabulary spellings are accepted as per-object targets although the feed never emits them; a binding naming one grants nothing and says so to nobody: %v",
		len(accepted), accepted)
}

// TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary — validResourceTypes
// answers a DIFFERENT question (which anchor kind a binding is attached to:
// cluster / account / project and the legacy bare kinds) and must keep answering
// it. This is the control on the fix: the target predicate stops reading that map,
// the anchor predicate must not.
func TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary(t *testing.T) {
	require.NotEmpty(t, validResourceTypes, "validResourceTypes is empty — the anchor vocabulary would assert nothing")
	t.Logf("scanned: validResourceTypes=%d entries", len(validResourceTypes))

	for _, anchor := range []string{"cluster", "account", "project"} {
		require.NoErrorf(t, ResourceType(anchor).Validate(),
			"ResourceType(%q).Validate() rejects a scope anchor — the anchor vocabulary was damaged", anchor)
	}
	// A retired block-storage type is in neither vocabulary. Paired with the
	// anchors above so "absent" is distinguishable from "the map is gone".
	for _, retired := range []string{"compute_disk", "compute_image", "compute_snapshot"} {
		require.Errorf(t, ResourceType(retired).Validate(),
			"ResourceType(%q).Validate() accepts a retired block-storage type", retired)
	}
}

// TestRetiredBlockStorageHasATargetableSuccessor — the lane's own paired
// assertion, on the observable the retire changed.
//
// Before the retire a per-object binding could name compute.disk / compute.image /
// compute.snapshot. Those resources moved to kacho-storage, so the retired names
// must be refused — and the successor names must be accepted, or the retire did
// not move the capability, it removed it.
func TestRetiredBlockStorageHasATargetableSuccessor(t *testing.T) {
	for _, retired := range []string{"compute.disk", "compute.image", "compute.snapshot"} {
		require.Falsef(t, ValidTargetType(retired),
			"ValidTargetType(%q) is true — a binding may still target a resource compute does not serve", retired)
	}
	for _, successor := range []string{"storage.volumes", "storage.snapshots", "storage.images"} {
		require.Truef(t, ValidTargetType(successor),
			"ValidTargetType(%q) is false — block storage lost its per-object grant in the retire instead of moving it to its present owner", successor)
	}
}

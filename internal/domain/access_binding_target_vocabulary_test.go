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

// TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary — две ОСИ, два
// вокабуляра, и путать их нельзя.
//
// `target` (F8) называет ОБЪЕКТ под якорем и судится лентой материализации;
// `ResourceType` называет САМ ЯКОРЬ и судится тремя ярусами иерархии. Наборы не
// пересекаются вовсе, и это утверждается с ОБЕИХ сторон — иначе «раздельны»
// зеленело бы на любом из двух опустевших вокабуляров.
//
// Здесь этот гейт ходил в `validResourceTypes` — рукописную карту, которая была
// вторым, разошедшимся объявлением вокабуляра якоря. Карта снята вместе со своим
// предметом (#1092), и гейт переведён на ЖИВОЙ источник: ленту и сам предикат
// якоря. Словесные же близнецы (`nlb` против `networkLoadBalancers`) переписыванием
// ленты недостижимы — их стережёт гейт у порождённой таблицы
// (authzmap/target_vocabulary_word_twins_test.go), где живёт производитель.
func TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary(t *testing.T) {
	feed := AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() пуста — гейт не утверждал бы ничего")

	anchors := []string{"cluster", "account", "project"}
	for _, anchor := range anchors {
		require.NoErrorf(t, ResourceType(anchor).Validate(),
			"ResourceType(%q).Validate() отвергает ярус — вокабуляр якоря повреждён", anchor)
		require.Falsef(t, ValidTargetType(anchor),
			"ValidTargetType(%q) истинно — ярус принят как ПООБЪЕКТНАЯ цель", anchor)
	}
	for _, dotted := range feed {
		require.Errorf(t, ResourceType(dotted).Validate(),
			"ResourceType(%q).Validate() принимает пообъектный тип как ЯКОРЬ области", dotted)
	}
	t.Logf("перепись: ярусов якоря %d, типов ленты %d, пересечение 0", len(anchors), len(feed))
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

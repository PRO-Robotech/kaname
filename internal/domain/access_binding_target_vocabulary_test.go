// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// access_binding_target_vocabulary_test.go — годность типа пообъектной цели
// выдачи судит ЖИВОЙ каталог платформы, и ничто другое (Р1 приёмки
// `access-target-names-live-catalog-types.md`, kaname#904).
//
// A per-object AccessBinding target is honoured in exactly one place: the
// reconciler calls AccessTarget.Contains(o.ObjectType, o.ObjectID) with
// o.ObjectType taken from the materialization feed (the mirror row / iam-native
// row), and keeps the object only on an exact string match. The mirror admits an
// object only of a type with a LIVE catalog row (`resource_mirror/emitter.go`), so
// the question "may a binding name this target type" has one correct answer —
// "can an object of that type ever reach Contains", i.e. does the type have a live
// catalog row — and any second, separately maintained answer is wrong in both
// directions at once:
//
//	a type the feed produces but the check rejects  → the grant cannot be
//	  expressed per-object at all, so the only way to grant it is the whole-anchor
//	  arm. The check then does not restrict the grant, it WIDENS it. Таким вторым
//	  ответом был закрытый перечень `materializableTypes`: тип модуля, живой в
//	  каталоге, он отвергал (kaname#904);
//	a type the check accepts but the feed never produces → the binding is
//	  created, stored and reconciled, matches nothing, and grants nothing. Accepted
//	  and ignored (api-conventions.md), which is the failure the caller cannot see.
//
// Both halves are asserted here, and the negative half is DERIVED rather than
// listed: for every live type it re-spells the resource segment in the other
// convention and requires the re-spelling to be refused.
//
// Пакет внешний (`domain_test`): живой каталог даёт `catalogfixture`, а `catalog`
// импортирует `domain` — проба внутри пакета замкнула бы кольцо импорта.

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// liveDotted — точечные имена ЖИВЫХ строк каталога, равного посеянному.
func liveDotted(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, r := range catalogfixture.Facts().Resources() {
		out = append(out, r.Module+"."+r.Resource)
	}
	require.NotEmpty(t, out, "живой каталог фикстуры пуст — гейт не утверждал бы ничего")
	return out
}

// TestTargetTypeRegistryIsTheMaterializationFeed — положительная половина: каждый
// тип с живой строкой каталога называется пообъектной целью; и каждый тип,
// который реконсайлер разворачивает подстановкой (`AllMaterializableTypes`),
// живой — иначе перевод на каталог сузил бы прежнюю цель.
func TestTargetTypeRegistryIsTheMaterializationFeed(t *testing.T) {
	cat := catalogfixture.Facts()
	live := liveDotted(t)
	feed := domain.AllMaterializableTypes()
	require.NotEmpty(t, feed, "AllMaterializableTypes() is empty — this gate would assert nothing")
	t.Logf("перепись: живых строк каталога %d, типов ленты %d", len(live), len(feed))

	var rejected []string
	for _, dotted := range append(append([]string{}, live...), feed...) {
		if !domain.ValidTargetType(cat, dotted) {
			rejected = append(rejected, dotted)
		}
	}
	require.Emptyf(t, rejected,
		"%d types cannot be named as a per-object target, so the only expressible grant on them is the whole-anchor arm: %v",
		len(rejected), rejected)
}

// TestTargetTypeRegistryRefusesTypesTheFeedNeverProduces — the negative half,
// derived from the live vocabulary rather than listed.
func TestTargetTypeRegistryRefusesTypesTheFeedNeverProduces(t *testing.T) {
	cat := catalogfixture.Facts()
	live := liveDotted(t)
	isLive := make(map[string]bool, len(live))
	for _, dotted := range live {
		isLive[dotted] = true
	}

	// Twins: same module, resource segment re-spelled in the other convention.
	// Only types whose spelling actually differs produce a twin, so the set
	// shrinks by itself if the vocabulary is ever normalised — an assertion with
	// nothing left to assert must not silently keep passing.
	var twins []string
	for _, dotted := range live {
		i := strings.IndexByte(dotted, '.')
		require.Greaterf(t, i, 0, "malformed dotted type %q in the live catalog", dotted)
		twin := dotted[:i] + "." + domain.SnakeResource(dotted[i+1:])
		if twin == dotted || isLive[twin] {
			continue
		}
		twins = append(twins, twin)
	}
	require.NotEmptyf(t, twins,
		"no near-miss twin could be derived from %d live types — the vocabulary is single-convention now, so this gate has no subject and must be replaced by whatever guards the new one",
		len(live))
	t.Logf("перепись: близнецов %d из живых типов %d", len(twins), len(live))

	var accepted []string
	for _, twin := range twins {
		if domain.ValidTargetType(cat, twin) {
			accepted = append(accepted, twin)
		}
	}
	require.Emptyf(t, accepted,
		"%d re-spelled types are accepted as per-object targets although the catalog carries the other spelling: %v",
		len(accepted), accepted)

	// Control that the predicate is not simply false for everything.
	require.True(t, domain.ValidTargetType(cat, live[0]), "ValidTargetType(%q) is false — the negative half above proves nothing", live[0])

	// Malformed and wildcard inputs stay refused; so does every input without a
	// catalog at all.
	for _, bad := range []string{"", "*", "compute", ".instance", "compute.", "unknown.thing", "compute.*"} {
		require.Falsef(t, domain.ValidTargetType(cat, bad), "ValidTargetType(%q) is true", bad)
	}
	require.False(t, domain.ValidTargetType(nil, live[0]), "ValidTargetType без каталога истинно — отсутствие источника стало всеразрешением")
}

// TestAccessTargetValidateDoesNotJudgeMembership — `AccessTarget.Validate` судит
// ФОРМУ цели, не членство типа: тип модуля, которого нет ни в одном перечне кода,
// проходит домен, а годность спрашивается у каталога (`FirstNonLiveType`).
func TestAccessTargetValidateDoesNotJudgeMembership(t *testing.T) {
	tgt := domain.AccessTarget{Resources: []domain.ResourceRef{
		{Type: "compute.instance", ID: "i1"}, {Type: "probemod.boxes", ID: "b1"},
	}}
	require.NoError(t, tgt.Validate(), "домен отверг тип по перечню в коде")

	typ, bad := tgt.FirstNonLiveType(catalogfixture.Facts())
	require.True(t, bad, "probemod.boxes в каталоге посева нет — ответ «все живые» неверен")
	require.Equal(t, "probemod.boxes", typ)

	empty := domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "", ID: "i1"}}}
	require.Error(t, empty.Validate(), "пустой тип прошёл форму")
	_, bad = domain.AccessTarget{AllInScope: true}.FirstNonLiveType(nil)
	require.False(t, bad, "у цели «вся область» типов нет — неживого быть не может")
}

// TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary — две ОСИ, два
// вокабуляра. `target` называет ОБЪЕКТ под якорем и судится живым каталогом;
// `ResourceType` называет САМ ЯКОРЬ и судится тремя ярусами иерархии.
func TestTargetTypeRegistryIsSeparateFromTheScopeAnchorVocabulary(t *testing.T) {
	cat := catalogfixture.Facts()
	live := liveDotted(t)

	anchors := []string{"cluster", "account", "project"}
	for _, anchor := range anchors {
		require.NoErrorf(t, domain.ResourceType(anchor).Validate(),
			"ResourceType(%q).Validate() отвергает ярус — вокабуляр якоря повреждён", anchor)
		require.Falsef(t, domain.ValidTargetType(cat, anchor),
			"ValidTargetType(%q) истинно — ярус принят как ПООБЪЕКТНАЯ цель", anchor)
	}
	for _, dotted := range live {
		require.Errorf(t, domain.ResourceType(dotted).Validate(),
			"ResourceType(%q).Validate() принимает пообъектный тип как ЯКОРЬ области", dotted)
	}
	t.Logf("перепись: ярусов якоря %d, живых типов %d, пересечение 0", len(anchors), len(live))
}

// TestRetiredBlockStorageHasATargetableSuccessor — строки compute.disk /
// compute.image / compute.snapshot в посеве сняты (`live = false`): цель их не
// называет; преемники в storage живые и называются.
func TestRetiredBlockStorageHasATargetableSuccessor(t *testing.T) {
	cat := catalogfixture.Facts()
	for _, retired := range []string{"compute.disk", "compute.image", "compute.snapshot"} {
		require.Falsef(t, domain.ValidTargetType(cat, retired),
			"ValidTargetType(%q) is true — a binding may still target a resource compute does not serve", retired)
	}
	for _, successor := range []string{"storage.volumes", "storage.snapshots", "storage.images"} {
		require.Truef(t, domain.ValidTargetType(cat, successor),
			"ValidTargetType(%q) is false — block storage lost its per-object grant in the retire instead of moving it to its present owner", successor)
	}
}

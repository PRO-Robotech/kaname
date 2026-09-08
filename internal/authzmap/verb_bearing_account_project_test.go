// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verb_bearing_account_project_test.go — RBAC explicit-model.
//
// Asserts the authzmap-layer contract that makes `account`/`project`
// verb-bearing resource types. The flip is the SINGLE source of truth the FGA
// emitter consults (access_binding/scope_grant_tuples.go gates `v_*` emission on
// authzmap.TypeHasVerbRelations(objType)); once these return true, a grant of
// `iam.account.get` materializes `account:<id> # v_get @ subj` — object-level
// access to the account itself, with NO cascade to its contents.
//
// This is the EXPAND half of expand→contract: the table flip is purely
// additive — it does NOT touch the viewer-tier emission, scope_grant carrier,
// or cascade (those are the contract step). It only marks the two hierarchy
// ancestors as also carrying the closed per-verb relation set, matching the
// canonical fga_model.fga which already defines v_* on both types.
package authzmap_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// account/project are now verb-bearing (TypeHasVerbRelations == true).
func TestVerbBearing_AccountProjectAreVerbBearing(t *testing.T) {
	for _, ft := range []string{"account", "project"} {
		require.Truef(t, authzmap.TypeHasVerbRelations(ft),
			"TypeHasVerbRelations(%q) must be true (account/project are now verb-bearing)", ft)
	}
}

// Regression: every leaf resource type stays verb-bearing — the flip must not
// disturb the existing mappings (no loss of v_* emission anywhere).
//
// The leaf set is DERIVED from authzmap.Catalog() (the grantable closed table)
// minus the two hierarchy ancestors, not hand-listed: a literal list silently
// omits whatever it was not updated for (this one had never learned about
// registry.* or storage.*) and simultaneously keeps asserting types that were
// removed from the table.
func TestVerbBearing_LeafTypesStillVerbBearing(t *testing.T) {
	hierarchy := map[string]bool{"account": true, "project": true}
	var checked int
	for _, e := range authzmap.Catalog() {
		ft, ok := authzmap.ObjectType(e.Module, e.Resource)
		require.Truef(t, ok, "Catalog() yielded %s.%s but ObjectType does not resolve it", e.Module, e.Resource)
		if hierarchy[ft] {
			continue
		}
		require.Truef(t, authzmap.TypeHasVerbRelations(ft),
			"regression: leaf type %q must remain verb-bearing", ft)
		checked++
	}
	require.NotZero(t, checked, "no leaf resource types found in the grantable catalog")
}

// An unknown FGA type must never be reported as verb-bearing (closed set).
func TestVerbBearing_UnknownTypeNotVerbBearing(t *testing.T) {
	require.False(t, authzmap.TypeHasVerbRelations("definitely_not_a_type"))
}

// verb→relation resolution at the authzmap+domain seam:
// a rule on iam.account / iam.project with verbs [get,list] resolves to the
// closed per-verb relation set v_get/v_list, AND the type is verb-bearing so
// the emitter writes those v_* tuples (rather than SKIPping as a tier-only
// ancestor). This mirrors emitNamesRule's emitVerbs gate without coupling the
// test to the emitter package.
func TestVerbBearing_AccountProjectVerbToRelation(t *testing.T) {
	cases := []struct {
		name        string
		module, res string
		verbs       []string
		wantRels    []string // expected v_<verb> relations
	}{
		{"account get/list", "iam", "account", []string{"get", "list"}, []string{"v_get", "v_list"}},
		{"project get/update", "iam", "project", []string{"get", "update"}, []string{"v_get", "v_update"}},
		// Подстановка `*` разворачивается в набор, ОБЪЯВЛЕННЫЙ ТИПОМ, поэтому и
		// ожидание берётся оттуда же. Здесь стоял пятиимённый литерал с `v_create`;
		// он пережил свой предмет, когда отношение сняли со всех типов, кроме
		// `registry_registry`, — и требовал бы от аккаунта глагол, которого у него
		// больше нет. Ожидание, выписанное отдельно от источника, не может следовать
		// за ним; тавтологией это не становится, потому что утверждается ПУТЬ —
		// разворот подстановки `*` доменом и отбор развёрнутых глаголов по набору
		// типа, — а не сама таблица. Обе функции этого пути живут в домене и
		// вызываются телом теста ниже; здесь они намеренно не названы по имени:
		// комментарий, называющий защиту, которую ЭТОТ пакет не применяет, отвечает
		// читателю на вопрос вместо самой защиты (гейт internal/repohygiene
		// TestCommentsNamingAGuardHaveItInScope).
		{"account wildcard verb → the type's declared set", "iam", "account", []string{"*"},
			authzmap.VerbRelationsOfType("account")},
	}
	require.NotEmpty(t, cases[2].wantRels,
		"тип account не объявляет ни одного глагольного отношения — подстановочный случай "+
			"стал бы бессодержательным (ожидание пусто, полученное пусто)")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objType, ok := authzmap.ObjectType(tc.module, tc.res)
			require.True(t, ok, "ObjectType(%q,%q)", tc.module, tc.res)
			require.Truef(t, authzmap.TypeHasVerbRelations(objType),
				"%s must be verb-bearing for v_* emission", objType)

			resolved, _ := domain.ResolveVerbsAndTier(tc.verbs, authzmap.VerbsOfType(objType))
			var got []string
			for _, v := range resolved {
				if domain.IsVerbOfType(v, authzmap.VerbsOfType(objType)) {
					got = append(got, "v_"+v)
				}
			}
			require.ElementsMatch(t, tc.wantRels, got,
				"%s verbs %v should resolve to %v", objType, tc.verbs, tc.wantRels)
		})
	}
}

// Каждое глагольное отношение, объявленное account/project, остаётся в закрытом
// множестве спрашиваемых (ExpandAccess «кто может <глагол> на account:<id>»).
//
// Множество выводится из наборов ВСЕХ типов, поэтому проверять его перечнем от
// имени двух — значит утверждать больше, чем эти два типа знают: прежняя редакция
// называла `v_create`, который аккаунт не объявляет с тех пор, как отношение
// оставили одному `registry_registry`. Отношение осталось спрашиваемым, но уже НЕ
// по этой причине, и утверждать это здесь было бы верным выводом из ложной посылки.
func TestVerbBearing_VRelationsAreExpandable(t *testing.T) {
	for _, ty := range []string{"account", "project"} {
		rels := authzmap.VerbRelationsOfType(ty)
		require.NotEmptyf(t, rels, "тип %q не объявляет глагольных отношений", ty)
		for _, r := range rels {
			require.Truef(t, authzmap.IsExpandableRelation(r),
				"%q объявлено типом %q, но ExpandAccess его не принимает — право энфорсится "+
					"и остаётся неспрашиваемым", r, ty)
		}
	}
}

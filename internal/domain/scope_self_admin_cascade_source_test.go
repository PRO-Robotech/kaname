// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// scope_self_admin_cascade_source_test.go — safety lock for the level-3 cascade
// source (owner directive 2026-07-27, .claude/rules/security.md "Три уровня
// супер-доступа — КАСКАДОМ").
//
// The authorization model now derives `super_admin` on every account-scoped
// resource from `admin from account`. That makes the tuple
//
//	account:<A> # admin @ <subject>
//
// the switch that hands somebody the WHOLE account. It is produced by exactly one
// projection: an account-scoped, all-in-scope binding whose role's rules match the
// scope self (Rules.ScopeSelfVerbs("account")) and whose verbs resolve to tier
// `admin`. So the question that decides whether the cascade is safe is: WHICH role
// shapes reach that tier on the account anchor?
//
// This test pins the answer in both directions. The shapes below are the seeded
// system roles (migrations 0001 §4.1-4.6, rules filled by 0031, `owner` added by
// 0035). What must hold:
//
//   - only a role that is genuinely account-WIDE administrator — the `*.*`
//     superuser shape, or an explicit `iam`/`account` rule with delete authority —
//     becomes a cascade source;
//   - a NARROW per-domain admin role (vpc / compute / nlb / registry / storage, or
//     even iam.project.admin) bound AT ACCOUNT SCOPE must NOT. This is the case
//     that would be a silent disaster: an account owner hands out
//     `vpc.network.admin` across his account, and with a cascade that subject would
//     own every resource of every project in it.
//   - read/write tiers below `admin` must NOT, so `edit` / `view` stay harmless.
//
// anchorTypeVerbs — набор глаголов ТИПА якоря (account/project) на этой стадии.
// Объявлен литералом НАМЕРЕННО: платформенного словаря больше нет, набор есть
// атрибут типа, а внешний тестовый пакет домена таблицу звать не вправе.
var anchorTypeVerbs = []string{"get", "list", "create", "update", "delete"}

func TestScopeSelfAdmin_OnlyAccountWideRolesBecomeCascadeSource(t *testing.T) {
	// tierOnAccountScope reproduces the projection the reconciler performs for an
	// account-scoped, all-in-scope binding: ScopeSelfVerbs over the scope's resource
	// type, then the tier those verbs resolve to. "" == no scope-self tuple at all.
	tierOnAccountScope := func(rs domain.Rules) string {
		verbs := rs.ScopeSelfVerbs("account", anchorTypeVerbs)
		if verbs == nil {
			return ""
		}
		_, tier := domain.ResolveVerbsAndTier(verbs, anchorTypeVerbs)
		return tier
	}

	cases := []struct {
		name     string
		role     string
		rules    domain.Rules
		wantTier string // "" = no scope-self projection at all
	}{
		// ── genuinely account-wide: SOURCE of the cascade, by design ──────────
		{"wildcard superuser", "admin",
			domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}, "admin"},
		{"platform superuser", "kacho-system.admin",
			domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}, "admin"},
		{"account owner role", "owner",
			domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}, "admin"},
		{"explicit account admin", "iam.account.admin",
			domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"*"}}}, "admin"},

		// ── account-wide but below the admin tier: NOT a cascade source ───────
		{"wildcard editor", "edit",
			domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"get", "list", "update"}}}, "editor"},
		{"wildcard viewer", "view",
			domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"get", "list"}}}, "viewer"},
		{"account editor", "iam.account.edit",
			domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list", "update"}}}, "editor"},
		{"account viewer", "iam.account.view",
			domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list"}}}, "viewer"},

		// ── narrow per-domain admin bound AT ACCOUNT SCOPE: no scope-self at all.
		// These are the ones an ordinary tenant hands out freely. If any of them
		// ever returned "admin", the cascade would give its holder the account.
		{"vpc network admin", "vpc.network.admin",
			domain.Rules{{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"*"}}}, ""},
		{"compute instance admin", "compute.instance.admin",
			domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"*"}}}, ""},
		{"storage volume admin", "storage.volume.admin",
			domain.Rules{{Module: "storage", Resources: []string{"volume"}, Verbs: []string{"*"}}}, ""},
		{"registry admin", "registry.registries.admin",
			domain.Rules{{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"*"}}}, ""},
		{"nlb operator", "loadbalancer.operator",
			domain.Rules{{Module: "loadbalancer", Resources: []string{"networkLoadBalancers"}, Verbs: []string{"*"}}}, ""},
		{"iam project admin at ACCOUNT scope", "iam.project.admin",
			domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"*"}}}, ""},
		{"iam user admin at ACCOUNT scope", "iam.user.admin",
			domain.Rules{{Module: "iam", Resources: []string{"user"}, Verbs: []string{"*"}}}, ""},
		{"iam role admin at ACCOUNT scope", "iam.role.admin",
			domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"*"}}}, ""},

		// ── half-wildcards are not a seed shape and must stay fail-closed ──────
		{"half wildcard module", "synthetic.*.account",
			domain.Rules{{Module: "*", Resources: []string{"account"}, Verbs: []string{"*"}}}, ""},
		{"half wildcard resource", "synthetic.iam.*",
			domain.Rules{{Module: "iam", Resources: []string{"*"}, Verbs: []string{"*"}}}, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tierOnAccountScope(c.rules)
			require.Equalf(t, c.wantTier, got,
				"role %q bound at ACCOUNT scope projects tier %q on account:<A>, expected %q — "+
					"tier `admin` here IS the level-3 cascade source and hands over the whole account",
				c.role, got, c.wantTier)
			if c.wantTier != "admin" {
				require.NotEqualf(t, "admin", got,
					"role %q must NEVER become an account-level cascade source", c.role)
			}
		})
	}
}

// TestScopeSelfAdmin_ProjectScopeIsNotACascadeSource — the same projection at
// PROJECT scope produces `project:<P> # admin`, which the model deliberately does
// NOT read as a cascade source (project.super_admin derives from its account and
// the cluster only). This test states the companion fact from the projection side:
// a project-scoped grant, however strong, never yields the ACCOUNT anchor — so it
// can never reach level 3 no matter what the role says.
func TestScopeSelfAdmin_ProjectScopeIsNotACascadeSource(t *testing.T) {
	superuser := domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}

	// At project scope the superuser shape does materialize on the project anchor…
	verbs := superuser.ScopeSelfVerbs("project", anchorTypeVerbs)
	require.NotNil(t, verbs, "the superuser shape projects onto its project anchor")
	_, tier := domain.ResolveVerbsAndTier(verbs, anchorTypeVerbs)
	require.Equal(t, "admin", tier)

	// …and that is exactly why the model must not treat `project#admin` as a
	// cascade source: a project-scoped binding is something an ordinary tenant
	// hands out freely.
	//
	// The substantive companion fact: a role written AGAINST projects reaches the
	// project anchor and nothing else. `iam.project.admin` is admin-tier on
	// project:<P> and projects NOTHING on account:<A> — so no amount of
	// project-directed authority can climb to level 3.
	projectAdmin := domain.Rules{{Module: "iam", Resources: []string{"project"}, Verbs: []string{"*"}}}

	pv := projectAdmin.ScopeSelfVerbs("project", anchorTypeVerbs)
	require.NotNil(t, pv, "iam.project.admin must project onto the project anchor")
	_, pTier := domain.ResolveVerbsAndTier(pv, anchorTypeVerbs)
	require.Equal(t, "admin", pTier, "iam.project.admin is admin-tier on its own project")

	require.Nil(t, projectAdmin.ScopeSelfVerbs("account", anchorTypeVerbs),
		"iam.project.admin must project NOTHING onto the account anchor — otherwise a "+
			"project-directed role would become a level-3 cascade source and hand over the account")
}

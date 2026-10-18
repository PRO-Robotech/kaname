// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// deletion_hold_text_test.go — форма отказа снятия по содержимому у
// `UserService.Delete` и `AccountService.Delete` (kaname#725, приёмка
// `deletion-refusals-name-the-remainder-and-the-step.md`, Р1–Р3, DRS-14).
//
// Утверждается ТЕКСТ ЦЕЛИКОМ и признак первого держащего: текст — контракт
// (§Error-format), поэтому «содержит» здесь не годится — оно зеленело бы на
// хвосте, потерявшем шаг или счёт.

import (
	stderrors "errors"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// TestDeletionHoldRefusalNamesTheFirstHolderAndTheStep — таблица Р1: на каждый
// вид держащего один текст, и он называет первого держащего, шаг и счёт.
func TestDeletionHoldRefusalNamesTheFirstHolderAndTheStep(t *testing.T) {
	cases := []struct {
		name     string
		kind     iamerr.HoldKind
		subject  string
		first    heldBy
		wantText string
		wantType string
	}{
		{"владение аккаунтами (DRS-02, DRS-04)", iamerr.HoldAccountsOwned, "usr_u",
			heldBy{ID: "acc_a", Count: 2},
			"User usr_u owns accounts and cannot be deleted: delete Account acc_a first (accounts owned: 2)", "account"},
		{"выдача на аккаунте (DRS-05)", iamerr.HoldActiveBindings, "usr_u",
			heldBy{ID: "acb_b", ScopeType: "account", ScopeID: "acc_f", Count: 1},
			"User usr_u has active access bindings and cannot be deleted: AccessBinding acb_b on account acc_f is revoked by an administrator of that account (active bindings: 1)", "access_binding"},
		{"выдача на проекте (DRS-07)", iamerr.HoldActiveBindings, "usr_u",
			heldBy{ID: "acb_b2", ScopeType: "project", ScopeID: "prj_q", Count: 2},
			"User usr_u has active access bindings and cannot be deleted: AccessBinding acb_b2 on project prj_q is revoked by an administrator of that project (active bindings: 2)", "access_binding"},
		{"членство в группе (DRS-08)", iamerr.HoldGroupMembership, "usr_u",
			heldBy{ID: "grp_g", Count: 1},
			"User usr_u is a member of one or more groups and cannot be deleted: Group grp_g removes the member by its administrator (groups: 1)", "group"},
		{"проекты аккаунта (DRS-10)", iamerr.HoldProjects, "acc_a",
			heldBy{ID: "prj_p", Count: 1},
			"Account acc_a contains projects and cannot be deleted: delete Project prj_p first (projects: 1)", "project"},
		{"сервисные аккаунты (DRS-11)", iamerr.HoldServiceAccounts, "acc_a",
			heldBy{ID: "sva_s", Count: 1},
			"Account acc_a contains service accounts and cannot be deleted: delete ServiceAccount sva_s first (service accounts: 1)", "service_account"},
		{"группы аккаунта (DRS-11)", iamerr.HoldGroups, "acc_a",
			heldBy{ID: "grp_g", Count: 1},
			"Account acc_a contains groups and cannot be deleted: delete Group grp_g first (groups: 1)", "group"},
		{"свои роли (DRS-11)", iamerr.HoldCustomRoles, "acc_a",
			heldBy{ID: "rol_r", Count: 3},
			"Account acc_a contains custom roles and cannot be deleted: delete Role rol_r first (custom roles: 3)", "role"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			first := c.first
			err := holdRefusal(c.kind, c.subject, &first)
			if got := iamerr.StripSentinel(err); got != c.wantText {
				t.Fatalf("текст отказа\n got: %q\nwant: %q", got, c.wantText)
			}
			if !stderrors.Is(err, iamerr.ErrReferenceInUse) {
				t.Fatalf("полоса обязана быть «ещё ссылаются» (REFERENCE_IN_USE), получено %v", err)
			}
			h, ok := iamerr.HolderOf(err)
			if !ok {
				t.Fatalf("отказ обязан нести первого держащего для metadata (Р3), получено %v", err)
			}
			if h.ResourceType != c.wantType || h.ResourceID != first.ID || h.Remaining != first.Count {
				t.Fatalf("держащий = %+v; ожидалось {%s %s %d}", h, c.wantType, first.ID, first.Count)
			}
		})
	}
}

// TestDeletionHoldRefusalWithNothingLeftSaysRetry — DRS-14 (Р2): держащих
// этого вида к моменту чтения уже нет — текст «повторите», без ресурса и счёта,
// и держащего у отказа нет (metadata пуст отсутствием ключей).
func TestDeletionHoldRefusalWithNothingLeftSaysRetry(t *testing.T) {
	err := holdRefusal(iamerr.HoldActiveBindings, "usr_u", nil)
	const want = "User usr_u has active access bindings and cannot be deleted: nothing holds it now, retry the deletion"
	if got := iamerr.StripSentinel(err); got != want {
		t.Fatalf("текст отказа\n got: %q\nwant: %q", got, want)
	}
	if !stderrors.Is(err, iamerr.ErrReferenceInUse) {
		t.Fatalf("полоса обязана остаться REFERENCE_IN_USE, получено %v", err)
	}
	if h, ok := iamerr.HolderOf(err); ok {
		t.Fatalf("держащего нет — отказ не вправе его называть, получено %+v", h)
	}
}

// TestDeletionRaceRubezhCarriesTheHoldKind — Р2: отказ рубежа гонки (ключ либо
// триггер схемы на операторе снятия) несёт ВИД держащего, по которому
// репозиторий дочитывает остаток. Близнец — та же связь на стороне ВСТАВКИ и
// снятие соседнего вида: вида держащего у них нет.
func TestDeletionRaceRubezhCarriesTheHoldKind(t *testing.T) {
	cases := []struct {
		constraint, kindHint string
		want                 iamerr.HoldKind
	}{
		{"accounts_owner_fk", "User.Delete", iamerr.HoldAccountsOwned},
		{"access_binding_subjects_subject_ref", "User.Delete", iamerr.HoldActiveBindings},
		{"projects_account_fk", "Account.Delete", iamerr.HoldProjects},
		{"service_accounts_account_fk", "Account.Delete", iamerr.HoldServiceAccounts},
		{"groups_account_fk", "Account.Delete", iamerr.HoldGroups},
		{"roles_account_fk", "Account.Delete", iamerr.HoldCustomRoles},
	}
	for _, c := range cases {
		err := wrapPgErr(mkPgErr("23503", c.constraint), c.kindHint, "x_1")
		got, ok := iamerr.HoldKindOf(err)
		if !ok || got != c.want {
			t.Errorf("%s/%s: вид держащего = %q (%v); ожидался %q", c.constraint, c.kindHint, got, ok, c.want)
		}
	}
	twins := []struct{ constraint, kindHint string }{
		{"accounts_owner_fk", ""},
		{"projects_account_fk", ""},
		{"access_binding_subjects_subject_ref", "Group.Delete"},
		{"access_binding_subjects_subject_ref", "ServiceAccount.Delete"},
	}
	for _, c := range twins {
		err := wrapPgErr(mkPgErr("23503", c.constraint), c.kindHint, "x_1")
		if k, ok := iamerr.HoldKindOf(err); ok {
			t.Errorf("близнец %s/%q: вида держащего быть не должно, получено %q", c.constraint, c.kindHint, k)
		}
	}
}

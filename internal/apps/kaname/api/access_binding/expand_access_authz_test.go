// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// expand_access_authz_test.go — per-object authz on ExpandAccess (B3) +
// relation closed-set validation (B2).
//
// B3: ExpandAccess used to gate only the authenticated-floor (anti-anon),
// so ANY authenticated principal could expand "who can do X" on ANY object —
// including a foreign account / instance they have no authority over. That leaks
// the authz topology + group membership to an unauthorized caller (an
// under-authorized method). ExpandAccess MUST require grant-authority/admin on the
// target object's scope BEFORE walking the userset — the SAME requireGrantAuthority
// gate ListByResource/ListByRole already enforce (read==enforce).
//
// B2: the `relation` field was forwarded verbatim into the FGA Read.
// It MUST be validated against the closed known-relation set (per-verb v_* + tier
// viewer/editor/admin + member); an unknown relation → INVALID_ARGUMENT (no probing
// of arbitrary strings).

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// foreignCtx returns a context for an authenticated, NON-owner, NON-admin
// principal (passes RequireAuthenticated but fails requireGrantAuthority unless
// FGA grants admin on the object).
func foreignCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{ID: "usr_foreign", Type: "user"})
}

// ── B3: per-object authz ──────────────────────────────────────────────────────

// TestExpandAccess_B3_ForeignObject_Denied — an authenticated caller WITHOUT
// grant-authority on the target object's scope must be DENIED before the userset is
// expanded (no leak of effective principals). FGA Check denies (no admin); the
// owner-account lookup returns a DIFFERENT owner (the caller is not the owner).
func TestExpandAccess_B3_ForeignObject_Denied(t *testing.T) {
	// Owner of acc_foreign is usr_owner; caller is usr_foreign (not the owner).
	repo := newABFakeRepo("usr_owner", "acc_foreign", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{
		"account:acc_foreign#viewer": {"user:usr_secret_member"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, &denyingFGA{}, nil)

	res, _, err := uc.Execute(foreignCtx(), "account", "acc_foreign", "viewer", 0)
	require.Error(t, err, "ExpandAccess on a foreign object MUST be denied (B3)")
	assert.Equal(t, codes.PermissionDenied, status.Code(err),
		"unauthorized expand → PERMISSION_DENIED (parity with ListByResource)")
	assert.Empty(t, res, "no principals leaked when denied")
	assert.Equal(t, 0, exp.calls, "the userset must NOT be walked before authority is verified")
}

// TestExpandAccess_B3_OwnObject_Allowed — the account OWNER (grant-authority via the
// owner path) may expand their own object's userset.
func TestExpandAccess_B3_OwnObject_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{
		"account:acc_mine#viewer": {"user:usr_a", "user:usr_b"},
	}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, &denyingFGA{}, nil)

	ctx := newOwnerContext("usr_owner")
	res, _, err := uc.Execute(ctx, "account", "acc_mine", "viewer", 0)
	require.NoError(t, err, "the owner has grant-authority on their own object")
	require.Len(t, res, 2)
}

// TestExpandAccess_B3_DelegatedAdmin_Allowed — a non-owner who holds FGA `admin`
// on the object (delegated administration, Path 2) may expand it.
func TestExpandAccess_B3_DelegatedAdmin_Allowed(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_x", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	// Тип назван так, как его знает МОДЕЛЬ (`compute_instance`). Точечная форма
	// каталога (`compute.instance`), стоявшая здесь прежде, моделью не объявлена:
	// проба была снисходительнее продукта — источник подставной, поэтому она
	// зеленела на паре, по которой настоящая форма не собрала бы плана (#1290).
	exp := &fakeLister{byNode: map[string][]string{
		"compute_instance:inst_x#v_delete": {"user:usr_a"},
	}}
	// recordingFGA.Check returns true → delegated admin path passes.
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)

	res, _, err := uc.Execute(foreignCtx(), "compute_instance", "inst_x", "v_delete", 0)
	require.NoError(t, err, "a delegated FGA admin may expand the object")
	require.Len(t, res, 1)
}

// ── B2: relation closed-set ───────────────────────────────────────────────────

// TestExpandAccess_B2_UnknownRelation_Rejected — an unknown relation string must be
// rejected with INVALID_ARGUMENT, before any FGA probe.
func TestExpandAccess_B2_UnknownRelation_Rejected(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	exp := &fakeLister{byNode: map[string][]string{}}
	uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)

	ctx := newOwnerContext("usr_owner")
	for _, rel := range []string{"sg_compute_instance", "owner", "g_admin_compute_instance", "totally_bogus", "v_teleport"} {
		_, _, err := uc.Execute(ctx, "account", "acc_mine", rel, 0)
		require.Error(t, err, "unknown relation %q must be rejected", rel)
		assert.Equal(t, codes.InvalidArgument, status.Code(err),
			"unknown relation %q → INVALID_ARGUMENT", rel)
	}
	assert.Equal(t, 0, exp.calls, "no FGA Read probe for an invalid relation")
}

// TestExpandAccess_B2_KnownRelations_Accepted — каждое отношение закрытой
// поверхности проходит вход НА ТИПЕ, КОТОРЫЙ ЕГО ОБЪЯВЛЯЕТ.
//
// Прежняя редакция спрашивала ВЕСЬ набор у ОДНОГО типа (`account`) и тем
// закрепляла дефект: приём судил ОБЪЕДИНЕНИЕ наборов всех типов, поэтому
// `v_create` и `member` у аккаунта вход проходили, а план по ним не собирался —
// корректный запрос возвращал вызывающему внутреннюю ошибку (#1290). Проба была
// зелёной ровно на сломанном.
//
// Единица утверждения теперь ПАРА, а не отношение: у каждой строки свой тип, и
// именно он это отношение объявляет.
func TestExpandAccess_B2_KnownRelations_Accepted(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	ctx := newOwnerContext("usr_owner")
	known := []struct {
		objectType string
		objectID   string
		relation   string
	}{
		{"account", "acc_mine", "v_get"},
		{"account", "acc_mine", "v_list"},
		{"account", "acc_mine", "v_update"},
		{"account", "acc_mine", "v_delete"},
		{"account", "acc_mine", "viewer"},
		{"account", "acc_mine", "editor"},
		{"account", "acc_mine", "admin"},
		// `v_create` объявляет ровно один тип — реестр: «создать репозиторий в
		// этом пространстве имён» действительно операция над ним.
		{"registry_registry", "reg_x", "v_create"},
		// Состав группы целей отделён от изменения самой группы (NLB-TGT-1).
		{"nlb_target_group", "tg_x", "v_addtargets"},
		{"nlb_target_group", "tg_x", "v_removetargets"},
		// Членство бывает только у группы.
		{"iam_group", "grp_x", "member"},
	}
	for _, c := range known {
		exp := &fakeLister{byNode: map[string][]string{
			c.objectType + ":" + c.objectID + "#" + c.relation: {"user:usr_a"},
		}}
		uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)
		_, _, err := uc.Execute(ctx, c.objectType, c.objectID, c.relation, 0)
		require.NoError(t, err, "объявленная пара %s.%s обязана проходить вход", c.objectType, c.relation)
		assert.Equal(t, 1, exp.calls, "объявленная пара %s.%s обязана доходить до источника",
			c.objectType, c.relation)
	}
}

// TestExpandAccess_B2_SurfaceRelationOnAForeignType_Rejected — ЗЕРКАЛО к
// предыдущему: то же отношение поверхности у типа, который его НЕ объявляет,
// отвергается терминально и до источника не доходит.
//
// Без этого зеркала положительная проба выше зеленела бы и на приёме, который
// берёт всё подряд, — то есть ровно на дефекте, который она заводится ловить.
func TestExpandAccess_B2_SurfaceRelationOnAForeignType_Rejected(t *testing.T) {
	repo := newABFakeRepo("usr_owner", "acc_mine", "", "rol_x", "viewer", domain.Permissions{"iam.access_bindings.get"})
	ctx := newOwnerContext("usr_owner")
	foreign := []struct {
		objectType string
		objectID   string
		relation   string
	}{
		{"account", "acc_mine", "v_create"},
		{"account", "acc_mine", "member"},
		{"account", "acc_mine", "v_addtargets"},
		{"vpc_network", "vpcn_x", "v_removetargets"},
		{"iam_user", "usr_x", "v_delete"},
	}
	for _, c := range foreign {
		exp := &fakeLister{byNode: map[string][]string{}}
		uc := NewExpandAccessUseCase(exp).WithGrantAuthority(repo, newRecordingFGA(), nil)
		_, _, err := uc.Execute(ctx, c.objectType, c.objectID, c.relation, 0)
		require.Error(t, err, "пара %s.%s не объявлена — вход обязан её отвергнуть", c.objectType, c.relation)
		assert.Equal(t, codes.InvalidArgument, status.Code(err),
			"отказ по паре %s.%s обязан быть терминальным", c.objectType, c.relation)
		assert.Equal(t, 0, exp.calls, "до источника такой запрос доходить не должен")
	}
}

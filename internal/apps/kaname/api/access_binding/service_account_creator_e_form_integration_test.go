// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_e_form_integration_test.go — группа E приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// форма права, роль создателя только системная (SAC-40, SAC-41). SAC-42 —
// модульная проба пакета `internal/manifest`.
//
// Тела ролей пишутся JSON края дословно из приёмки и разбираются `protojson` в
// сообщение входа: ключа `createdBySubject` в контракте до изменения нет, и проба
// обязана исполниться на стволе — неизвестный ключ отбрасывается разбором, и
// роль заводится; это и есть красное SAC-40 d, e до изменения.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	sac40VerbsText    = "Illegal argument verbs (create on serviceAccount is system-only)"
	sac40SelectorText = "Illegal argument createdBySubject (creator-scoped rules are declared by a module manifest)"
)

// SAC-40 — роль аккаунта не называет `create` на учётках и не несёт селектора создателя.
//
// Имена ролей — с подчёркиванием (`r_40a`), а не с дефисом, как в теле приёмки
// (`r-40a`): имя роли аккаунта судит `roles_custom_name_check`
// (`^[a-z][a-z0-9_]{0,40}$`), и дефис отвергся бы ДО предмета — отказом имени, а не
// отказом права. Остальное тело — дословно.
func TestServiceAccountCreator_SAC40_TenantRoleNamesNoCreateAndNoCreatorSelector(t *testing.T) {
	w := newSACWorld(t)
	owner := asUser(w.ctx, w.usrA)
	ownRules := w.roleRules(w.rolOwn)
	ruleA := `{"module":"iam","resources":["serviceAccount"],"verbs":["create"]}`
	ruleD := `{"module":"iam","resources":["serviceAccount"],"verbs":["get"],"createdBySubject":true}`

	create := func(name, rule string) sacOp {
		var req iamv1.CreateRoleRequest
		roleFromJSON(t, fmt.Sprintf(`{"accountId":%q,"name":%q,"rules":[%s]}`, string(w.accA), name, rule), &req)
		return w.mutate(owner, sacMethodRolCreate, &req, func(ctx context.Context) (*operationpb.Operation, error) {
			return w.rolex.Create(ctx, &req)
		})
	}
	update := func(rule string) sacOp {
		var req iamv1.UpdateRoleRequest
		roleFromJSON(t, fmt.Sprintf(`{"roleId":%q,"updateMask":"rules","rules":[%s]}`, string(w.rolOwn), rule), &req)
		return w.mutate(owner, sacMethodRolUpdate, &req, func(ctx context.Context) (*operationpb.Operation, error) {
			return w.rolex.Update(ctx, &req)
		})
	}
	requireRefused := func(o sacOp, text, field, why string) {
		t.Helper()
		require.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция (ошибка %v)", why, o.opErr)
		st := requireRefusal(t, o.syncErr, codes.InvalidArgument, text, why)
		if field != "" {
			require.Containsf(t, fieldViolations(st), field, "%s: поле отказа", why)
		}
	}

	requireRefused(create("r_40a", ruleA), sac40VerbsText, "", "SAC-40 a: Create с create на serviceAccount")
	requireRefused(update(ruleA), sac40VerbsText, "", "SAC-40 b: Update rol-own тем же правилом")
	require.Equal(t, ownRules, w.roleRules(w.rolOwn), "SAC-40 b: правила rol-own прежние")
	requireSACDone(t, create("r_40c", `{"module":"iam","resources":["serviceAccount"],"verbs":["get"]}`),
		"SAC-40 c (близнец): Create с get")
	requireRefused(create("r_40d", ruleD), sac40SelectorText, "rules[0].createdBySubject",
		"SAC-40 d: Create с createdBySubject")
	requireRefused(update(ruleD), sac40SelectorText, "rules[0].createdBySubject",
		"SAC-40 e: Update rol-own правилом d")
	require.Equal(t, ownRules, w.roleRules(w.rolOwn), "SAC-40 e: правила rol-own прежние")
}

// SAC-41 — роль создателя видна в каталоге ролей целиком.
func TestServiceAccountCreator_SAC41_CreatorRoleIsVisibleWhole(t *testing.T) {
	w := newSACWorld(t)
	owner := asUser(w.ctx, w.usrA)
	c := w.listRoleByName(owner, sacCreatorRoleName)
	if c == nil {
		t.Fatalf("SAC-41: роли %s нет в RoleService.List от usr-A (ПРЕДМЕТА НЕТ — Р2)", sacCreatorRoleName)
	}
	require.True(t, c.GetIsSystem(), "SAC-41: isSystem")
	require.Equal(t, "iam.cluster", c.GetDefinitionTier().GetTierType(), "SAC-41: definitionTier.tierType")
	require.Equal(t, "cluster_root", c.GetDefinitionTier().GetTierId(), "SAC-41: definitionTier.tierId")
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_HEALTHY, c.GetHealth(), "SAC-41: health")
	rules := roleRulesJSON(t, c)
	require.Len(t, rules, 2, "SAC-41: правил у роли C")
	require.Equal(t, "iam", rules[0]["module"], "SAC-41: правило 1, module")
	require.Equal(t, []any{"serviceAccount"}, rules[0]["resources"], "SAC-41: правило 1, resources")
	require.Equal(t, []any{"create"}, rules[0]["verbs"], "SAC-41: правило 1, verbs")
	require.NotContains(t, rules[0], sacCreatedByJSON, "SAC-41: правило 1 без ключа createdBySubject")
	require.Equal(t, "iam", rules[1]["module"], "SAC-41: правило 2, module")
	require.Equal(t, []any{"serviceAccount"}, rules[1]["resources"], "SAC-41: правило 2, resources")
	require.ElementsMatch(t, []any{"get", "list", "update", "delete"}, rules[1]["verbs"], "SAC-41: правило 2, verbs (как множество)")
	require.Equal(t, true, rules[1][sacCreatedByJSON], "SAC-41: правило 2, createdBySubject")

	saa := w.listRoleByName(owner, sacAdminRoleName)
	require.NotNil(t, saa, "SAC-41: роль SAA в каталоге")
	for i, r := range roleRulesJSON(t, saa) {
		require.NotContainsf(t, r, sacCreatedByJSON, "SAC-41: правило %d роли SAA без ключа createdBySubject", i)
	}
}

// fieldViolations — поля, названные отказом (`errdetails.BadRequest`).
func fieldViolations(st *status.Status) []string {
	var out []string
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			for _, v := range br.GetFieldViolations() {
				out = append(out, v.GetField())
			}
		}
	}
	return out
}

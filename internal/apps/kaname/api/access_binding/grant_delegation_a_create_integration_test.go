// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_a_create_integration_test.go — группа A приёмки делегированных
// выдач (PRO-Robotech/kaname#986): заведение делегирования, GD-01…GD-07. Мир —
// `newGDWorld`; порядок каждой пробы — мир → близнец вне предмета → проба
// возможностей → тело сценария (шапка `grant_delegation_world_integration_test.go`).

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// sortedStrings — значения JSON-массива строк.
func sortedStrings(t *testing.T, v any, field string) []string {
	t.Helper()
	arr, ok := v.([]any)
	require.Truef(t, ok, "поле %s — не массив: %v", field, v)
	out := make([]string, 0, len(arr))
	for _, it := range arr {
		s, ok := it.(string)
		require.Truef(t, ok, "элемент %s — не строка: %v", field, it)
		out = append(out, s)
	}
	return out
}

// requireAscending — порядок набора — по возрастанию строки (Р1, `api-repeated-order`).
func requireAscending(t *testing.T, got []string, field string) {
	t.Helper()
	for i := 1; i < len(got); i++ {
		require.Truef(t, got[i-1] < got[i], "%s не по возрастанию строки: %v", field, got)
	}
}

// requireSecondTruncated — момент усечён до секунды.
func requireSecondTruncated(t *testing.T, v any, field string) {
	t.Helper()
	s, ok := v.(string)
	require.Truef(t, ok, "поле %s — не строка момента: %v", field, v)
	ts, err := time.Parse(time.RFC3339Nano, s)
	require.NoErrorf(t, err, "поле %s не разбирается: %q", field, s)
	require.Zerof(t, ts.Nanosecond(), "%s не усечён до секунды: %q", field, s)
}

// requireD1Body — тело делегирования D1 (GD-01) полем за полем.
func (w *gdWorld) requireD1Body(body map[string]any, id string, delegatedBy domain.UserID, sc string) {
	w.t.Helper()
	t := w.t
	assert.Equalf(t, id, body["id"], "%s: id", sc)
	assert.Truef(t, strings.HasPrefix(fmt.Sprint(body["id"]), "gdl"), "%s: префикс id gdl", sc)
	assert.Equalf(t, string(w.accA), body["accountId"], "%s: accountId", sc)
	assert.Equalf(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": w.svaIss}, body["delegate"], "%s: delegate", sc)
	roles := sortedStrings(t, body["roleIds"], "roleIds")
	requireAscending(t, roles, "roleIds")
	want := []string{string(w.rolPuller), string(w.rolPusher), string(w.rolRegAdmin)}
	assert.ElementsMatchf(t, want, roles, "%s: roleIds", sc)
	types := sortedStrings(t, body["targetTypes"], "targetTypes")
	requireAscending(t, types, "targetTypes")
	assert.Equalf(t, []string{"registry.registries", "registry.repositories"}, types, "%s: targetTypes", sc)
	subs := sortedStrings(t, body["subjectTypes"], "subjectTypes")
	requireAscending(t, subs, "subjectTypes")
	assert.Equalf(t, []string{"SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS"}, subs, "%s: subjectTypes", sc)
	assert.Equalf(t, "registry", body["module"], "%s: module", sc)
	assert.Equalf(t, "ACTIVE", body["status"], "%s: status", sc)
	assert.Equalf(t, map[string]any{"type": "user", "id": string(delegatedBy)}, body["delegatedBy"], "%s: delegatedBy", sc)
	requireSecondTruncated(t, body["createdAt"], "createdAt")
	assert.NotContainsf(t, body, "revokedAt", "%s: ключ revokedAt у действующего", sc)
	assert.NotContainsf(t, body, "revokedBy", "%s: ключ revokedBy у действующего", sc)
}

// GD-01 — владелец аккаунта заводит делегирование.
func TestGrantDelegation_GD01_AccountOwnerCreatesADelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-01")

	id := w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "GD-01")
	body, err := w.getDelegation(asUser(w.ctx, w.usrA), id)
	require.NoError(t, err, "GD-01: Get делегирования от usr-A")
	w.requireD1Body(body, id, w.usrA, "GD-01")

	// Перечень выдач учётки читает держатель права на ЕЁ аккаунт — владелец acc-S
	// usr-S: sva-iss живёт в acc-S, и у владельца acc-A права читать выдачи чужой
	// учётки нет (прогон: PERMISSION_DENIED). Вызывающего приёмка не называет.
	resp, err := w.abx.ListBySubject(asUser(w.ctx, w.usrS), &iamv1.ListAccessBindingsBySubjectRequest{
		SubjectType: "service_account", SubjectId: w.svaIss})
	require.NoError(t, err, "GD-01: ListBySubject sva-iss")
	assert.Empty(t, resp.GetAccessBindings(), "GD-01: у sva-iss новых выдач нет")
	w.requireRelation("service_account:"+w.svaIss, "admin", "account:"+string(w.accA), false,
		"GD-01: делегирование не даёт admin на acc-A")
}

// GD-02 — администратор аккаунта заводит делегирование; близнец GD-03 — вызывающий.
func TestGrantDelegation_GD02_AccountAdminCreatesADelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-02")

	body := w.delegationBody(w.accA, w.svaIss2,
		[]domain.RoleID{w.rolPuller, w.rolPusher, w.rolRegAdmin},
		[]string{"registry.registries", "registry.repositories"},
		[]string{"SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_SYSTEM_CLASS"})
	id := w.createDelegation(asUser(w.ctx, w.usrE), body, "GD-02: D-E от usr-E")
	got, err := w.getDelegation(asUser(w.ctx, w.usrA), id)
	require.NoError(t, err, "GD-02: Get делегирования")
	assert.Equal(t, map[string]any{"type": "user", "id": string(w.usrE)}, got["delegatedBy"], "GD-02: delegatedBy")
}

// GD-03 — без права выдавать делегирование не заводится; близнец — GD-01.
func TestGrantDelegation_GD03_NoGrantAuthorityNoDelegation(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-03")

	for _, caller := range []struct {
		name string
		user domain.UserID
		sva  string
	}{
		{name: "usr-B", user: w.usrB},
		{name: "usr-C (владелец acc-B)", user: w.usrC},
		{name: "sva-iss", sva: w.svaIss},
	} {
		ctx := asUser(w.ctx, caller.user)
		if caller.sva != "" {
			ctx = asSA(w.ctx, caller.sva)
		}
		o := w.gdMutate(ctx, "Create", w.d1Body(w.svaIss))
		require.Emptyf(t, o.opID, "GD-03 (%s): синхронного отказа нет, заведена операция", caller.name)
		requireRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", "GD-03 ("+caller.name+")")
	}
	assert.Zero(t, len(w.listAllDelegations(asUser(w.ctx, w.usrA), w.accA)), "GD-03: делегирований в acc-A нет")

	// Близнец — GD-01: тот же запрос от владельца проходит.
	w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "GD-03 близнец (GD-01)")
}

// gd04Row — строка таблицы GD-04: отличие от D1 и ожидаемый отказ.
type gd04Row struct {
	name  string
	patch func(m map[string]any)
	text  string
	field string // "" — `field_violations` нет
}

// requireFieldViolationExact — `field_violations[0]` = {field, description: text};
// пустое поле — деталей BadRequest нет вовсе.
func requireFieldViolationExact(t *testing.T, err error, field, text, why string) {
	t.Helper()
	var fvs []*errdetails.BadRequest_FieldViolation
	for _, d := range status.Convert(err).Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			fvs = append(fvs, br.GetFieldViolations()...)
		}
	}
	if field == "" {
		require.Emptyf(t, fvs, "%s: field_violations есть, а их не должно быть: %v", why, fvs)
		return
	}
	require.NotEmptyf(t, fvs, "%s: field_violations нет", why)
	assert.Equalf(t, field, fvs[0].GetField(), "%s: field_violations[0].field", why)
	assert.Equalf(t, text, fvs[0].GetDescription(), "%s: field_violations[0].description", why)
}

// d1Map — тело D1 в виде объекта (для одно-фактных правок строк таблиц).
func (w *gdWorld) d1Map(delegate string) map[string]any {
	w.t.Helper()
	var m map[string]any
	require.NoError(w.t, json.Unmarshal([]byte(w.d1Body(delegate)), &m))
	return m
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return string(b)
}

// GD-04 — форма запроса проверяется синхронно; близнец каждой строки — GD-01.
func TestGrantDelegation_GD04_RequestFormIsCheckedSynchronously(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-04")

	pullerTwice := []any{string(w.rolPuller), string(w.rolPuller)}
	seventeen := make([]any, 17)
	for i := range seventeen {
		seventeen[i] = fmt.Sprintf("rol%017d", i+1)
	}
	rows := []gd04Row{
		{"a", func(m map[string]any) { m["accountId"] = "" }, "account_id: required", "account_id"},
		{"b", func(m map[string]any) { m["accountId"] = "acc!!" }, "invalid account id 'acc!!'", ""},
		{"c", func(m map[string]any) {
			m["delegate"] = map[string]any{"type": "SUBJECT_TYPE_USER", "id": string(w.usrB)}
		}, "delegate.type: only SUBJECT_TYPE_SERVICE_ACCOUNT can hold a grant delegation", "delegate.type"},
		{"d", func(m map[string]any) {
			m["delegate"] = map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": "sva!!"}
		}, "invalid service account id 'sva!!'", ""},
		{"e", func(m map[string]any) { m["roleIds"] = []any{} }, "role_ids: required", "role_ids"},
		{"f", func(m map[string]any) { m["roleIds"] = pullerTwice },
			fmt.Sprintf("role_ids: role %s is listed twice", w.rolPuller), "role_ids"},
		{"g", func(m map[string]any) { m["roleIds"] = seventeen }, "role_ids: at most 16 roles", "role_ids"},
		{"h", func(m map[string]any) { m["targetTypes"] = []any{} }, "target_types: required", "target_types"},
		// Строка i — форма отказа цели выдачи (`create.go`, `targetTypeNotLiveSyncMsg`)
		// с именем поля делегирования (Р6).
		{"i", func(m map[string]any) { m["targetTypes"] = []any{"registry.nope"} },
			`Illegal argument target_types[] "registry.nope" (not a live entry of the platform resource catalog; ` +
				"grantable types are published by " + domain.CatalogEndpoint + ")", "target_types"},
		{"j", func(m map[string]any) { m["subjectTypes"] = []any{} }, "subject_types: required", "subject_types"},
		{"k", func(m map[string]any) { m["subjectTypes"] = []any{"SUBJECT_TYPE_UNSPECIFIED"} },
			"subject_types: SUBJECT_TYPE_UNSPECIFIED is not a subject type", "subject_types"},
	}
	for _, r := range rows {
		m := w.d1Map(w.svaIss)
		r.patch(m)
		o := w.gdMutate(asUser(w.ctx, w.usrA), "Create", mustJSON(t, m))
		why := "GD-04 " + r.name
		require.Emptyf(t, o.opID, "%s: синхронного отказа нет, заведена операция", why)
		st := status.Convert(o.syncErr)
		require.Equalf(t, codes.InvalidArgument, st.Code(), "%s: код (текст %q)", why, st.Message())
		require.Equalf(t, r.text, st.Message(), "%s: текст отказа", why)
		requireFieldViolationExact(t, o.syncErr, r.field, r.text, why)
	}
	assert.Zero(t, len(w.listAllDelegations(asUser(w.ctx, w.usrA), w.accA)), "GD-04: делегирований в acc-A нет")
	w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "GD-04 близнец (GD-01)")
}

// GD-05 — форма проверяется до права, состав — после.
func TestGrantDelegation_GD05_FormBeforeAuthorityCompositionAfter(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-05")

	m := w.d1Map(w.svaIss)
	m["accountId"] = "acc!!"
	o := w.gdMutate(asUser(w.ctx, w.usrB), "Create", mustJSON(t, m))
	requireRefusal(t, o.syncErr, codes.InvalidArgument, "invalid account id 'acc!!'", "GD-05 a")

	vpcBody := w.withRole(w.d1Map(w.svaIss), w.rolVPCPool)
	o = w.gdMutate(asUser(w.ctx, w.usrB), "Create", vpcBody)
	requireRefusal(t, o.syncErr, codes.PermissionDenied, "permission denied", "GD-05 b")

	// Близнец b — GD-06 a: тот же запрос от usr-A даёт текст о составе.
	o = w.gdMutate(asUser(w.ctx, w.usrA), "Create", vpcBody)
	requireRefusal(t, o.syncErr, codes.FailedPrecondition,
		"role_ids and target_types must belong to one module; found registry, vpc", "GD-05 близнец (GD-06 a)")
}

// withRole — тело с одной ролью сверх D1.
func (w *gdWorld) withRole(m map[string]any, extra domain.RoleID) string {
	w.t.Helper()
	roles := append([]any{}, m["roleIds"].([]any)...)
	m["roleIds"] = append(roles, string(extra))
	return mustJSON(w.t, m)
}

// GD-06 — состав делегирования: роли и типы одного модуля, не iam; близнец — GD-01.
func TestGrantDelegation_GD06_RolesAndTypesOfOneModuleNotIAM(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-06")

	const nope = "rol00000000000000099"
	const noSA = "sva00000000000000099"
	rows := []struct {
		name string
		body string
		text string
	}{
		{"a", w.withRole(w.d1Map(w.svaIss), w.rolVPCPool),
			"role_ids and target_types must belong to one module; found registry, vpc"},
		{"b", w.withRole(w.d1Map(w.svaIss), gdAdminRID),
			fmt.Sprintf("role %s is not declared by a module manifest", gdAdminRID)},
		{"c", func() string {
			m := w.d1Map(w.svaIss)
			m["roleIds"] = []any{gdIAMRole}
			m["targetTypes"] = []any{"iam.project"}
			return mustJSON(t, m)
		}(), "module iam cannot be delegated"},
		{"d", func() string {
			m := w.d1Map(w.svaIss)
			m["targetTypes"] = append(append([]any{}, m["targetTypes"].([]any)...), "vpc.addressPool")
			return mustJSON(t, m)
		}(), "role_ids and target_types must belong to one module; found registry, vpc"},
		{"e", w.withRole(w.d1Map(w.svaIss), nope), "Role " + nope + " not found"},
		{"f", w.withRole(w.d1Map(w.svaIss), w.rolRegGet),
			fmt.Sprintf("role %s is not declared by a module manifest", w.rolRegGet)},
		{"g", func() string {
			m := w.d1Map(noSA)
			return mustJSON(t, m)
		}(), "ServiceAccount " + noSA + " not found"},
	}
	for _, r := range rows {
		o := w.gdMutate(asUser(w.ctx, w.usrA), "Create", r.body)
		require.Emptyf(t, o.opID, "GD-06 %s: синхронного отказа нет, заведена операция", r.name)
		requireRefusal(t, o.syncErr, codes.FailedPrecondition, r.text, "GD-06 "+r.name)
	}
	assert.Zero(t, len(w.listAllDelegations(asUser(w.ctx, w.usrA), w.accA)), "GD-06: делегирований в acc-A нет")
	w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "GD-06 близнец (GD-01)")
}

// GD-07 — одно действующее делегирование на пару «аккаунт, делегат».
func TestGrantDelegation_GD07_OneActiveDelegationPerAccountAndDelegate(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-07")

	d1 := w.d1()
	// a — второе заведение той же пары.
	o := w.gdMutate(asUser(w.ctx, w.usrA), "Create", w.d1Body(w.svaIss))
	require.NoError(t, o.syncErr, "GD-07 a: отказ уникальности — в операции, не синхронно")
	require.NotNil(t, o.opErr, "GD-07 a: второе действующее делегирование пары принято")
	assert.Equal(t, codes.AlreadyExists, o.opErr.Code(), "GD-07 a: код (текст %q)", o.opErr.Message())
	assert.Equal(t, fmt.Sprintf("an active grant delegation to service account %s in account %s already exists",
		w.svaIss, w.accA), o.opErr.Message(), "GD-07 a: текст")
	assert.Equal(t, 1, w.activeDelegationsOfPair(w.accA, w.svaIss), "GD-07 a: действующих делегирований пары")

	// b — после отзыва новое заводится (близнец a: прежнее отозвано).
	w.revokeDelegation(asUser(w.ctx, w.usrA), d1, "GD-07 b: отзыв D1")
	d1b := w.createDelegation(asUser(w.ctx, w.usrA), w.d1Body(w.svaIss), "GD-07 b")
	assert.NotEqual(t, d1, d1b, "GD-07 b: новый id")
	old, err := w.getDelegation(asUser(w.ctx, w.usrA), d1)
	require.NoError(t, err)
	assert.Equal(t, "REVOKED", old["status"], "GD-07 b: D1 отозвано")
	assert.Equal(t, 1, w.activeDelegationsOfPair(w.accA, w.svaIss), "GD-07 b: действующих делегирований пары")
}

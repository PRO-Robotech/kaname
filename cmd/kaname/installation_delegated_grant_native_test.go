// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func rid03BothModes(t *testing.T, systemClass bool, run func(*testing.T, *ridLifecycleWorld)) {
	t.Helper()
	for _, mode := range []string{"S1", "S2"} {
		t.Run(mode, func(t *testing.T) { run(t, newRIDLifecycleWorld(t, mode, systemClass)) })
	}
}
func ridNativeDelegatedGrant(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		u := w.f.ridSA(t, w.f.tenantID, "rid-grantee")
		g := w.grant(t, w.bindingInput("service_account", u, w.pull, "registry.registries", w.object))
		require.Equal(t, w.gd.Id, g.DelegationId)
		require.NotEqual(t, w.issuer.ID, w.f.creator.ID)
		rid03PublicDelegatedGrant(t, w)
	})
}
func ridNativeDelegatedAxes(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		// Обе роли законно поставлены и покрывают оба целевых типа. Единственное
		// изменение роли между отрицательным/положительным запросами — роль вне оси.
		u := w.f.ridSA(t, w.f.tenantID, "rid-role-twin")
		body := w.bindingInput("service_account", u, w.push, "registry.registries", w.object)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		body["roleId"] = w.pull
		w.grant(t, body)
		// Зарегистрированный допустимый репозиторий с покрывающей ролью; отличается только целевая ось.
		u = w.f.ridSA(t, w.f.tenantID, "rid-target-twin")
		body = w.bindingInput("service_account", u, w.pull, "registry.repositories", w.repository)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		body["target"] = w.bindingInput("service_account", u, w.pull, "registry.registries", w.object)["target"]
		w.grant(t, body)
		// Настоящий существующий пользователь — допустимый вид субъекта, но вне этого делегирования.
		u = w.f.ridSA(t, w.f.tenantID, "rid-subject-twin")
		body = w.bindingInput("user", w.f.operator.UserID(), w.pull, "registry.registries", w.object)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		body["subjectType"] = "service_account"
		body["subjectId"] = u
		w.grant(t, body)
		rid03PublicDelegatedAxes(t, w)
	})
}
func ridNativeIssuerCannotDelegate(t *testing.T) {
	rid03BothModes(t, false, func(t *testing.T, w *ridLifecycleWorld) {
		f := w.f
		other := ""
		if len(w.accounts) > 1 {
			other = w.accounts[1]
		} else {
			other = ridResponseID(t, f.ridOperation(t, "POST", "/iam/v1/accounts", f.operator.Bearer(), map[string]any{"name": "rid-other-account"}, 0))
		}
		require.NotEqual(t, f.tenantID, other)
		// Свежая штатная SA делает пару отсутствующей даже в S2, где уже
		// установлена собственная пара I во всех учётных записях снимка. Полезная нагрузка побайтно одинакова.
		delegate := f.ridSA(t, other, "rid-explicit-delegate")
		body := w.gdCreateBody(other, delegate)
		w.denied(t, "/iam/v1/grantDelegations", w.issuerToken, body)
		token := f.ridToken(t, f.creator)
		op := f.ridOperation(t, "POST", "/iam/v1/grantDelegations", token, body, 0)
		id := ridResponseID(t, op)
		found := false
		for _, gd := range w.delegations(t, other) {
			if gd.Id == id {
				found = true
				require.Equal(t, delegate, gd.Delegate.Id)
				require.Equal(t, f.creator.ID, gd.DelegatedBy.Id)
			}
		}
		require.True(t, found)
		rid03PublicIssuerCannotDelegate(t, w, other)
	})
}
func ridNativeAnonymousClass(t *testing.T) {
	rid03BothModes(t, true, func(t *testing.T, w *ridLifecycleWorld) {
		// Та же допустимая ось SYSTEM_CLASS, цель, роль, область и вызывающий. Меняется только
		// имя существующего класса. Издатель аутентифицирован в обоих запросах.
		body := w.bindingInput("system_class", "authenticated", w.pull, "registry.registries", w.object)
		w.denied(t, "/iam/v1/accessBindings", w.issuerToken, body)
		body["subjectId"] = "anonymous"
		w.grant(t, body)
		rid03PublicAnonymousClass(t, w)
	})
}

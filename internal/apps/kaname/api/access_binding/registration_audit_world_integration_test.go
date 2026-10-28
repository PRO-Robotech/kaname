// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// registration_audit_world_integration_test.go — регистрация и снятие объектов
// модулем попадают в журнал аудита (PRO-Robotech/kaname#1005).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Регистрация и снятие объекта модулем меняют модель прав: кладут и снимают
// владельца, указатель области, цепь предков. Действия людей над выдачами и
// учётками журнал аудита пишет, а регистрацию модулем — нет, и кто и когда завёл
// или снял объект, после события восстановить нельзя. Событие пишется той же
// транзакцией, что изменение: действие, объект, личность модуля-актора, исход.
//
// Модуль-актор — машинная личность, которой обработчик пропускает запись
// (`service_account:<учётка службы>` по сертификату вызывающего): контекст пробы
// несёт подтверждённую личность службы реестра.
//
// Близнец: повтор регистрации без изменения (та же версия) не плодит ложного
// события изменения.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Ключ реестра, которого мир П6 не регистрирует.
const auditK = "reg00000000000000008"

const (
	auditRegistered   = "iam.resource_registration.registered"
	auditUnregistered = "iam.resource_registration.unregistered"
)

// registryModuleCtx — контекст вызова службой реестра: подтверждённая личность
// по сертификату.
func registryModuleCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kacho.cloud"),
		"spiffe://kacho.cloud/ns/kacho/sa/kacho-registry", true)
}

// auditRows — число строк аудита данного типа по объекту.
func (w *urxWorld) auditRows(eventType string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.audit_outbox
		  WHERE event_type = $1 AND event_payload #>> '{object,id}' = $2`,
		eventType, auditK).Scan(&n))
	return n
}

// registerAuditK — регистрация указателя области K службой реестра.
func (w *urxWorld) registerAuditK(req *iamv1.RegisterResourceRequest) {
	w.t.Helper()
	require.NoError(w.t, w.reg.Register(registryModuleCtx(), req), "регистрация K")
}

func auditKRequest(w *urxWorld) *iamv1.RegisterResourceRequest {
	return &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + auditK,
		ParentProjectId: string(w.prjA), ParentAccountId: string(w.accA),
		ParentChain:   []string{"project:" + string(w.prjA), "account:" + string(w.accA)},
		SourceVersion: w.nextVersion(),
	}
}

// assertAuditEvent — строка аудита несёт актора-модуля, объект и исход.
func (w *urxWorld) assertAuditEvent(eventType, outcome, why string) {
	w.t.Helper()
	p := w.auditPayload(eventType, "actor", "service_account:"+authzguard.ServiceAccountIDForAccount(moduleroster.NameForm().Account("registry")))
	obj, _ := p["object"].(map[string]any)
	assert.Equalf(w.t, pcrRegTgt, obj["type"], "%s: тип объекта в событии", why)
	assert.Equalf(w.t, auditK, obj["id"], "%s: id объекта в событии", why)
	assert.Equalf(w.t, "registry", p["module"], "%s: модуль-актор в событии", why)
	assert.Equalf(w.t, outcome, p["outcome"], "%s: исход в событии", why)
}

// TestRegistrationAudit_RegisterAndUnregisterAreAudited — регистрация K модулем
// пишет событие регистрации, снятие — событие снятия; оба с актором-модулем,
// объектом и исходом.
func TestRegistrationAudit_RegisterAndUnregisterAreAudited(t *testing.T) {
	w := newURXWorld(t)

	w.registerAuditK(auditKRequest(w))
	require.Equal(t, 1, w.auditRows(auditRegistered), "kaname#1005: регистрация K не попала в аудит")
	w.assertAuditEvent(auditRegistered, "registered", "kaname#1005 регистрация")

	require.NoError(t, w.reg.Unregister(registryModuleCtx(), &iamv1.UnregisterResourceRequest{
		SubjectId: "project:" + string(w.prjA), Relation: "project", Object: pcrRegType + ":" + auditK,
		SourceVersion: w.nextVersion(),
	}), "снятие K")
	require.Equal(t, 1, w.auditRows(auditUnregistered), "kaname#1005: снятие K не попало в аудит")
	w.assertAuditEvent(auditUnregistered, "unregistered", "kaname#1005 снятие")
}

// TestRegistrationAudit_RepeatWithoutChangeIsNotAudited — близнец: повтор той же
// регистрации (та же версия) события не добавляет.
func TestRegistrationAudit_RepeatWithoutChangeIsNotAudited(t *testing.T) {
	w := newURXWorld(t)
	req := auditKRequest(w)
	w.registerAuditK(req)
	require.Equal(t, 1, w.auditRows(auditRegistered), "kaname#1005 близнец предусловие: регистрация K не в аудите")

	w.registerAuditK(req)

	assert.Equal(t, 1, w.auditRows(auditRegistered), "kaname#1005 близнец: повтор без изменения дал второе событие")
}

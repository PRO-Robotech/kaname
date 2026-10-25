// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// ModuleActor — машинная личность модуля-вызывающего по ПОДТВЕРЖДЁННОМУ
// сертификату: субъект `service_account:<учётка службы>` и имя службы
// (kaname#1005, аудит регистрации объектов модулем).
//
// Личность выводится тем же разбором, которым ворота записи регистрации
// (`RelationWriteGate.Authorize`) пропускают модуль: SAN сертификата → служба
// (`SANToServiceDomain`) → учётка службы (`ServiceAccountIDForService`). Поэтому
// актор события аудита — ровно тот субъект, чьё право на запись проверено, а не
// слово вызывающего. ok=false — подтверждённой личности по сертификату нет
// (вызов не по mTLS либо SAN не называет службу продукта).
func ModuleActor(ctx context.Context) (subject, module string, ok bool) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return "", "", false
	}
	svc, ok := SANToServiceDomain(grpcsrv.CertIdentityDomainFromContext(ctx), san)
	if !ok {
		return "", "", false
	}
	return "service_account:" + ServiceAccountIDForService(svc), svc, true
}

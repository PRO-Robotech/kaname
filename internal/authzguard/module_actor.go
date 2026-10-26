// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

import (
	"context"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// ModuleActor — машинная личность модуля-вызывающего по ПОДТВЕРЖДЁННОМУ
// сертификату: субъект `service_account:<учётка службы>` и имя службы
// (kaname#1005, аудит регистрации объектов модулем).
//
// Личность выводится тем же разбором, которым ворота записи регистрации
// (`RelationWriteGate.Authorize`) узнают модуль: единственный разбор SAN
// (`moduleidentity.ParseSAN`, kaname#984) → учётка → служба
// (`moduleidentity.ServiceFromAccount`, та же функция, которой перечень
// личностей выводит `Identity.Service`) → учётка службы
// (`ServiceAccountIDForService`). Поэтому для вызова, пропущенного воротами, актор
// события аудита — ровно тот субъект, чьё право на запись проверено, а не слово
// вызывающего. Признание по перечню и привязку к выпустившему центру (kaname#984,
// kaname#988) судят ворота до use-case; здесь личность только называется.
// ok=false — подтверждённой личности по сертификату нет (вызов не по mTLS либо
// SAN не называет службу продукта).
func ModuleActor(ctx context.Context) (subject, module string, ok bool) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return "", "", false
	}
	_, account, ok := moduleidentity.ParseSAN(grpcsrv.CertIdentityDomainFromContext(ctx), san)
	if !ok {
		return "", "", false
	}
	svc, ok := moduleidentity.ServiceFromAccount(account)
	if !ok {
		return "", "", false
	}
	return "service_account:" + ServiceAccountIDForService(svc), svc, true
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// check_module_domain.go — внутренний Check плоскости данных ограничен доменом
// её модуля (kaname#987).
//
// # Предмет
//
// Внутренний Check освобождён от проверки отношений вызывающего: модуль
// спрашивает о праве конечного субъекта, и вопроса к модели о самом модуле здесь
// нет. Перечень методов профиля (kaname#984) открывает плоскости данных ровно
// этот глагол — и до сих пор он отвечал ей об объектах ЛЮБОГО модуля: плоскость
// данных реестра узнавала права на сети, машины и проекты, хотя ей нужен только
// свой реестр.
//
// Теперь личность профиля `data-plane` спрашивает только о типах объектов
// своего модуля; вопрос о чужом типе — отказ до решателя.
//
// # Чей тип — тем же словарём, что у посредника записи отношений
//
// Владение типом решает ПОРОЖДЁННАЯ таблица типов модели (`catalogTypeOwner`) и
// словарь «служба ↔ модуль каталога» фундамента (`platformmodules`): тот же
// словарь, которым посредник записи отношений ограничивает регистрацию
// объекта доменом модуля. Тип, которого таблица не знает, судится приставкой
// домена — как там же.
//
// # Граница
//
// Привязка стоит у плоскости данных. Модуль-владелец ресурсов спрашивает и о
// контейнерах платформы (проект, аккаунт), и в известных случаях — о чужих
// объектах, которые его ресурс использует; сужать его без переписи таких
// вопросов по дереву платформы значило бы оборвать живые пути. Край — парадная
// дверь и спрашивает за любого.

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/platformmodules"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// objectTypeInDomain — принадлежит ли тип объекта objType модулю службы
// service.
func objectTypeInDomain(service, objType string) bool {
	if objType == "" {
		return false
	}
	if module, known := (catalogTypeOwner{}).CatalogModuleOfObjectType(objType); known {
		mine, ok := platformmodules.CatalogModuleOfService(service)
		return ok && module == mine
	}
	domain, ok := platformmodules.ObjectDomainOfService(service)
	return ok && domain != "" && strings.HasPrefix(objType, domain+"_")
}

// requireCheckInCallerDomain — отказ, если признанная плоскость данных спрашивает о
// объекте чужого домена. Прочие вызывающие проходят без суда здесь: их судит
// политика вызывающего внутреннего слушателя.
func (h *Handler) requireCheckInCallerDomain(module moduleidentity.Identity, object string) error {
	if module.Profile != moduleidentity.ProfileDataPlane {
		return nil
	}
	objType, _, found := strings.Cut(object, ":")
	if !found || !objectTypeInDomain(module.Service, objType) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

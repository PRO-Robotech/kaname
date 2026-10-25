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
// Теперь личность профиля `data-plane` спрашивает только об объектах своего
// модуля; вопрос о чужом объекте — отказ до решателя.
//
// # «Свой объект» — ТЕМ ЖЕ правилом, что у посредника записи отношений
//
// Своим считается объект, который модуль вправе регистрировать: правило
// проксируемой записи фундамента (`proxytuple.ValidateTuple`) с отношением
// иерархии и тем же словарём владения типом (`catalogTypeOwner`), что у
// `RegisterResource`. Второго изложения «чей это тип» здесь нет — оно
// разошлось бы с первым молча, — и словаря имён модулей на пути запроса тоже
// нет: членство модуля решает порождённая таблица типов, а запретные типы
// (кластер, свои типы службы доступа) отвергаются тем же правилом.
//
// # Граница
//
// Привязка стоит у плоскости данных. Модуль-владелец ресурсов спрашивает и о
// контейнерах платформы (проект, аккаунт), и в известных случаях — о чужих
// объектах, которые его ресурс использует; сужать его без переписи таких
// вопросов по дереву платформы значило бы оборвать живые пути. Край — парадная
// дверь и спрашивает за любого.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// objectInModuleDomain — объект того вида, который модуль службы service
// вправе регистрировать через посредника записи отношений.
//
// Субъект пуст намеренно: правило судит субъекта только по его типу, а здесь
// вопрос — о владении ОБЪЕКТОМ, и подставленный субъект был бы утверждением,
// которого вызывающий не делал.
func objectInModuleDomain(service, object string) bool {
	return proxytuple.ValidateTuple(service, "", string(proxytuple.RelationParent), object,
		proxytuple.WithTypeOwner(catalogTypeOwner{})) == nil
}

// requireCheckInCallerDomain — отказ, если признанная плоскость данных спрашивает
// об объекте чужого домена. Прочие вызывающие проходят без суда здесь: их судит
// политика вызывающего внутреннего слушателя.
func (h *Handler) requireCheckInCallerDomain(module moduleidentity.Identity, object string) error {
	if module.Profile != moduleidentity.ProfileDataPlane {
		return nil
	}
	if module.Service == "" || !objectInModuleDomain(module.Service, object) {
		return status.Error(codes.PermissionDenied, "permission denied")
	}
	return nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// service_subject.go — тенантская поверхность выдачи служебного субъекта не
// производит (приёмка NTF-1, NTF1-M10 (а); замысел З17).
//
// Субъект `service:<имя>` заводит ТОЛЬКО строка `notifications` манифеста через
// применитель посева; гейт дерева `internal/check/servicesubjectwriter_test.go`
// держит, что второго производителя нет. Здесь — наблюдаемая половина: привязка
// с субъектом типа `service` отвергается с именем поля, а не общим текстом
// закрытого перечня типов, — вызывающий узнаёт, что тип существует и выдаче
// недоступен, а не что он опечатался.
//
// Отказ стоит ДО разрешения набора субъектов: разрешение отвергло бы тот же тип
// текстом перечня, и поле, которое править, осталось бы неназванным.

import (
	"fmt"

	"github.com/PRO-Robotech/corelib/authz"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// refuseServiceSubjects — `INVALID_ARGUMENT` на первом субъекте типа `service`.
// Единственная форма (`subject_type`) — проекция `subjects[0]`, и называется
// тем же полем.
func refuseServiceSubjects(subjects []domain.Subject, legacyType domain.SubjectType) error {
	types := make([]domain.SubjectType, 0, len(subjects)+1)
	for _, s := range subjects {
		types = append(types, s.Type)
	}
	if len(types) == 0 {
		types = append(types, legacyType)
	}
	for i, t := range types {
		if string(t) != authz.ServiceSubjectType {
			continue
		}
		field := fmt.Sprintf("subjects[%d].type", i)
		return shared.InvalidArg(field,
			fmt.Sprintf("%s: '%s' is not a grantable subject type", field, authz.ServiceSubjectType))
	}
	return nil
}

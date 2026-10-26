// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// permanent_project.go — проверка ключа `permanentProject` ресурса (kaname#983,
// приёмка docs/engineering/acceptance/object-keeps-its-project-after-unregistration.md,
// Р7, PB-22 a–c).
//
// Ключ объявляет автор (порождающий раздел его не выводит, как
// `publicReadToChildren`). Загрузка отвергает документ, ни одной строки каталога
// не применяя, и называет координату `resources[i].permanentProject`.

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// permanentProjectKey — ключ ресурса в документе (тег поля
// [Resource.PermanentProject]).
const permanentProjectKey = "permanentProject"

// validateResourcePermanentProject — ключ `permanentProject` ресурса resources[i].
//
// Путь к проекту у типа есть, если среди его указателей стоит якорь `project`
// либо указатель на тип ТОГО ЖЕ документа (контейнер, сам привязанный к
// проекту). Указатель на тип того же документа обязан вести к типу, тоже
// объявившему ключ: иначе контейнер мог бы сменить проект, а его ребёнок — нет.
func validateResourcePermanentProject(m *Manifest, r *Resource, doc *yaml.Node, i int,
	ownTypes map[string]struct{},
) []error {
	if r.PermanentProject == nil {
		return nil
	}
	coord := locate(doc, "resources", i, permanentProjectKey)
	if !*r.PermanentProject {
		return []error{linkFault{
			kind:  ErrPermanentProjectFalse,
			coord: coord,
			detail: fmt.Sprintf("resources[%d].permanentProject: значение false не принимается — "+
				"ключ либо отсутствует, либо равен true", i),
		}}
	}

	declared := make(map[string]bool, len(m.Resources))
	for k := range m.Resources {
		declared[m.Resources[k].ObjectType] = m.Resources[k].HoldsPermanentProject()
	}
	var faults []error
	pathToProject := false
	for _, p := range r.Parents {
		if p.Type == anchorProjectType {
			pathToProject = true
			continue
		}
		if _, own := ownTypes[p.Type]; !own {
			continue
		}
		pathToProject = true
		if !declared[p.Type] {
			faults = append(faults, linkFault{
				kind:  ErrPermanentProjectParentUnbound,
				coord: coord,
				detail: fmt.Sprintf("resources[%d].permanentProject: указатель %q ведёт к типу %s того же "+
					"модуля, который ключа не объявляет — контейнер мог бы сменить проект, а ребёнок нет",
					i, p.Name, p.Type),
			})
		}
	}
	if !pathToProject {
		faults = append(faults, linkFault{
			kind:  ErrPermanentProjectWithoutProject,
			coord: coord,
			detail: fmt.Sprintf("resources[%d].permanentProject: у типа %s нет пути к проекту — среди "+
				"указателей нет ни якоря %s, ни указателя на тип того же модуля", i, r.ObjectType, anchorProjectType),
		})
	}
	return faults
}

// anchorProjectType — тип якоря области «проект».
const anchorProjectType = "project"

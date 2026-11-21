// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"errors"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	childRegistrationKey         = "childRegistration"
	childRegistrationSubjectKind = "user"
)

// ErrChildRegistrationDeclaration обозначает неполное или неверно связанное
// объявление пользовательской регистрации потомка.
var ErrChildRegistrationDeclaration = errors.New("manifest: invalid child registration declaration")

type ChildRegistration struct {
	// Verb называет контейнерное действие этого типа. Указатель и отношение
	// берутся из действия, поэтому второй записи координаты права нет.
	Verb           string `yaml:"verb"`
	ParentSegments int32  `yaml:"parentSegments"`
	MaxChildren    int32  `yaml:"maxChildren"`
	MaxCreates     int32  `yaml:"maxCreates"`
	WindowSeconds  int32  `yaml:"windowSeconds"`
}

// UserChildPathPolicy возвращает модельные координаты объявления. Связность
// и допуск человека проверяет загрузчик манифеста.
func (r Resource) UserChildPathPolicy() (domain.UserChildPathPolicy, bool) {
	if r.ChildRegistration == nil {
		return domain.UserChildPathPolicy{}, false
	}
	action, ok := r.ContainerVerbNamed(r.ChildRegistration.Verb)
	if !ok || action.Parent != "parent" {
		return domain.UserChildPathPolicy{}, false
	}
	parentType := r.ParentTypeOf(action)
	if parentType == "" {
		return domain.UserChildPathPolicy{}, false
	}
	return domain.UserChildPathPolicy{
		ChildType:      r.ObjectType,
		ParentType:     parentType,
		ParentAction:   action.Relation,
		ParentSegments: int(r.ChildRegistration.ParentSegments),
	}, true
}

func validateChildRegistration(m *Manifest, doc *yaml.Node) []error {
	var faults []error
	for i, resource := range m.Resources {
		node := mapValue(seqItem(mapValue(doc, "resources"), i), childRegistrationKey)
		if node == nil {
			continue
		}
		coord := locate(doc, "resources", i, childRegistrationKey)
		if node.Kind != yaml.MappingNode || resource.ChildRegistration == nil {
			faults = append(faults, linkFault{kind: ErrChildRegistrationDeclaration, coord: coord,
				detail: "пользовательская регистрация требует непустого объявления"})
			continue
		}
		path, ok := resource.UserChildPathPolicy()
		verb := mapValue(node, "verb")
		if !ok || verb == nil || verb.ShortTag() != "!!str" {
			faults = append(faults, linkFault{kind: ErrChildRegistrationDeclaration,
				coord:  locate(doc, "resources", i, childRegistrationKey, "verb"),
				detail: "нужно именованное контейнерное действие на указателе parent"})
		} else if segments := mapValue(node, "parentSegments"); segments != nil && segments.ShortTag() == "!!int" {
			// Минимальный ключ родителя занимает один байт на каждый сегмент
			// и разделитель между ними. У потомка есть ещё свой сегмент.
			minParentID := 2*int64(path.ParentSegments) - 1
			limit := int64(domain.MaxUserChildObjectKeyBytes)
			if path.ParentSegments <= 0 || int64(len(path.ParentType)+1)+minParentID > limit ||
				int64(len(path.ChildType)+3)+minParentID > limit {
				faults = append(faults, linkFault{kind: ErrChildRegistrationDeclaration,
					coord:  locate(doc, "resources", i, childRegistrationKey, "parentSegments"),
					detail: "граница родителя должна быть положительной и позволять записать полный ключ"})
			}
		} else {
			faults = append(faults, linkFault{kind: ErrChildRegistrationDeclaration,
				coord:  locate(doc, "resources", i, childRegistrationKey, "parentSegments"),
				detail: "граница родителя требует положительного целого значения"})
		}
		value := resource.ChildRegistration
		for _, bound := range []struct {
			name  string
			value int32
		}{{"maxChildren", value.MaxChildren}, {"maxCreates", value.MaxCreates}, {"windowSeconds", value.WindowSeconds}} {
			field := mapValue(node, bound.name)
			if field == nil || field.ShortTag() != "!!int" || bound.value <= 0 {
				faults = append(faults, linkFault{kind: ErrChildRegistrationDeclaration,
					coord:  locate(doc, "resources", i, childRegistrationKey, bound.name),
					detail: "поле требует положительного целого значения"})
			}
		}
	}
	return faults
}

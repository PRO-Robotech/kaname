// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// MetadataObject задаёт существующий объект, чьи метки меняются. CatalogType
// обязательно для внешней координаты и берётся из удержанного каталога.
// Писатель подтверждает OLD, точную правку, область и полноту источников.
type MetadataObject struct {
	registration bool
	Type, ID     string
	CatalogType  string `json:",omitempty"`
	Labels       domain.Labels
	AccessLabels domain.Labels `json:",omitempty"`
	// CreatorKnown отделяет подтверждённый NULL legacy creator от отсутствующего источника.
	CreatorKnown bool           `json:",omitempty"`
	Creator      domain.Subject `json:",omitzero"`
}

// MetadataDelta содержит только эффекты привязки, зависящие от метаданных узла.
// Производители legacy, explicit meta, scope-self и container-action неизменны
// и исключены с ОБЕИХ сторон. Обычные выводы кортежей, включая наследуемые права,
// сохраняют полные символические пути. Компиляция выполняется для каждого
// получателя с полным Subjects; OLD разных получателей объединять нельзя.
// Полная пустая сторона означает отсутствие затронутого эффекта, а не успех Prove.
type MetadataDelta struct {
	Before Set
	After  Set
}

// CompileMetadataDelta специализирует прямых кандидатов и вложенные контейнеры.
// Потомки не перечисляются, авторские правила и отпечатки не переписываются.
// OLD и NEW обязаны называть один поддержанный объект. Неподдержанные случаи несут
// обязательства; неполный NEW нельзя считать пустым изменением эффекта.
func (b *Bundle) CompileMetadataDelta(binding Binding, old, next MetadataObject) MetadataDelta {
	if b.Validate() != nil {
		return MetadataDelta{}
	}
	return b.compiler.compileMetadataDelta(binding, old, next)
}

var (
	metadataUserID           = regexp.MustCompile(`^usr[a-zA-Z0-9_-]{1,61}$`)
	metadataGroupID          = regexp.MustCompile(`^grp[a-zA-Z0-9_-]{1,61}$`)
	metadataServiceAccountID = regexp.MustCompile(`^sva[a-zA-Z0-9_-]{1,61}$`)
)

func (c *Compiler) compileMetadataDelta(binding Binding, old, next MetadataObject) MetadataDelta {
	return c.compileMetadataImages(binding, binding, old, next)
}

func (c *Compiler) compileMetadataImages(beforeBinding, afterBinding Binding, old, next MetadataObject) MetadataDelta {
	fail := func(detail string) MetadataDelta {
		s := Set{identity: c.identity, obligations: []Obligation{{Code: "metadata_input", Detail: detail,
			Provenance: Provenance{SourceID: beforeBinding.SourceID, RoleID: beforeBinding.Role.ID}}}}
		return MetadataDelta{Before: s, After: s}
	}

	if old.Type != next.Type || old.CatalogType != next.CatalogType || old.ID != next.ID ||
		old.CreatorKnown != next.CreatorKnown || old.Creator != next.Creator {
		return fail("same existing metadata coordinate and creator required")
	}
	dotted := ""
	switch old.Type {
	case "account", "project":
		if old.CreatorKnown || old.Creator != (domain.Subject{}) {
			return fail("creator is not supported for this metadata coordinate")
		}
		if domain.DeriveFromResourceType(old.Type).ValidateAgainst(old.Type, old.ID) != nil {
			return fail("invalid metadata coordinate")
		}
		dotted = "iam." + old.Type
	case "iam_user":
		if !metadataUserID.MatchString(old.ID) || old.CreatorKnown || old.Creator != (domain.Subject{}) {
			return fail("invalid user metadata coordinate")
		}
		// Позицию User подтверждает удержанное множество membership в writer.
		// Здесь проверяется только точная координата уже выбранного объекта.
		dotted = "iam.user"
	case "iam_group":
		if !metadataGroupID.MatchString(old.ID) || old.CreatorKnown || old.Creator != (domain.Subject{}) {
			return fail("invalid group metadata coordinate")
		}
		// Объект IAM и userset участников группы — разные типы модели.
		dotted = "iam.group"
	case "iam_service_account":
		if !metadataServiceAccountID.MatchString(old.ID) || !old.CreatorKnown {
			return fail("service account identity or creator is not established")
		}
		if old.Creator != (domain.Subject{}) && ((old.Creator.Type != domain.SubjectTypeUser && old.Creator.Type != domain.SubjectTypeServiceAccount) || old.Creator.Validate() != nil || strings.ContainsAny(string(old.Creator.ID), ":#* \t\r\n")) {
			return fail("invalid service account creator")
		}
		dotted = "iam.serviceAccount"
	default:
		dotted = old.CatalogType
		if dotted == "" || domain.FeedSourceForType(dotted) != domain.FeedMirror || grantcapability.IsInternalObjectType(old.Type) ||
			old.CreatorKnown || old.Creator != (domain.Subject{}) {
			return fail("unsupported metadata coordinate")
		}
		if old.ID == "" || old.ID == "*" || len(old.ID) > grantcoverage.MaxStringBytes || !utf8.ValidString(old.ID) ||
			strings.TrimSpace(old.ID) != old.ID || strings.ContainsAny(old.ID, "\x00\r\n\t") {
			return fail("invalid mirror object identifier")
		}
	}
	if typ, ok := c.facts.FGAObjectType(dotted); !ok || typ != old.Type || (old.CatalogType != "" && old.CatalogType != dotted) {
		return fail("focal model/catalog mapping is not established")
	}
	if old.Labels.Validate() != nil || next.Labels.Validate() != nil ||
		old.AccessLabels.Validate() != nil || next.AccessLabels.Validate() != nil {
		return fail("invalid focal labels")
	}
	raw, err := json.Marshal([]MetadataObject{old, next})
	if err != nil || len(raw) > MaxInputBytes {
		return fail("metadata input limit")
	}
	before, after := c.compileBinding(beforeBinding, &old), c.compileBinding(afterBinding, &next)
	return MetadataDelta{Before: before, After: after}
}

func (c *Compiler) bindingSelectorRegions(sel domain.RuleSelector, dotted, typ string, b Binding, focal *MetadataObject) ([][]Constraint, error) {
	regions, err := c.selectorRegions(sel, dotted, typ, b)
	if err != nil || focal == nil {
		return regions, err
	}
	direct := typ == focal.Type
	container := false
	if sel.Container != nil {
		containerType, known := c.facts.FGAObjectType(sel.Container.Type)
		if !known {
			return nil, fmt.Errorf("unknown metadata container type")
		}
		container = containerType == focal.Type
	}
	if !direct && !container {
		return nil, nil
	}
	if direct && container {
		// Рекурсивный путь одного типа требует различать несколько его узлов.
		// Одна изменяемая строка не определяет, какое вхождение имеется в виду.
		return nil, fmt.Errorf("metadata focal occurs as both object and container")
	}
	index := 0
	if container {
		index = 1
	}
	var out [][]Constraint
	for _, region := range regions {
		if len(region) <= index || region[index].Type != focal.Type {
			return nil, fmt.Errorf("metadata focal constraint is missing")
		}
		constraint := region[index]
		switch constraint.Region.Creator.Kind {
		case grantcoverage.AnyCreator:
		case grantcoverage.ExactCreator:
			if !focal.CreatorKnown {
				return nil, fmt.Errorf("metadata focal creator is not established")
			}
			if focal.Creator != constraint.Region.Creator.Subject {
				continue
			}
		default:
			return nil, fmt.Errorf("metadata focal creator is invalid")
		}
		selected := constraint.Region.Objects.Kind == grantcoverage.AllObjects
		if constraint.Region.Objects.Kind == grantcoverage.ObjectIDs {
			selected = contains(constraint.Region.Objects.IDs, focal.ID)
		} else if !selected {
			return nil, fmt.Errorf("unsupported metadata object selector")
		}
		for key, value := range constraint.Region.Labels {
			actual, present := focal.Labels[domain.LabelKey(key)]
			selected = selected && present && string(actual) == value
		}
		for key, value := range constraint.Region.AccessLabels {
			actual, present := focal.AccessLabels[domain.LabelKey(key)]
			selected = selected && present && string(actual) == value
		}
		if !selected {
			continue
		}
		copy := cloneConstraints(region)
		// Метки уже проверены на удержанной строке OLD/NEW. Символическая
		// формула ошибочно представила бы новый выбранный объект покрытым
		// той же неизменной формулой меток со стороны OLD.
		// Создатель неизменен и уже проверен на точном OLD, как обе карты меток.
		copy[index].Region.Creator = grantcoverage.Creator{Kind: grantcoverage.AnyCreator}
		copy[index].Region.Labels = nil
		copy[index].Region.AccessLabels = nil
		copy[index].Region.Objects = grantcoverage.Objects{Kind: grantcoverage.ObjectIDs, IDs: []string{focal.ID}}
		// Предикаты ребёнка, полные пути родителей, Within и происхождение
		// неизменны. В частности, binding.Target по-прежнему выбирает контейнер.
		out = append(out, copy)
	}
	return out, nil
}

// Метаданные не подтверждают новое условие или членство в группе. Сохраняем
// типизированный кортеж group#member производителя, но не создаём безусловный
// факт, если модель принимает этого субъекта только с условием.
func (c *Compiler) metadataDeclaration(s *Set, subject domain.Subject, typ, relation string, provenance Provenance) bool {
	userset := ""
	if subject.Type == domain.SubjectTypeGroup {
		userset = "member"
	}
	if c.plans.EffectDirectAccepts(typ, relation, string(subject.Type), userset, "") {
		return true
	}
	s.obligations = append(s.obligations, Obligation{Code: "metadata_declaration", Detail: typ + "." + relation, Provenance: provenance})
	return false
}

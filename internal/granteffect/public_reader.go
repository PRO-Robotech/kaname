// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func validateBindingSubjects(b Binding) error {
	if len(b.Subjects) > domain.MaxSubjectsPerBinding {
		return fmt.Errorf("too many binding subjects")
	}
	if len(b.Subjects) == 0 {
		if b.Recipient.IsSystemClass() {
			return fmt.Errorf("class requires the complete binding subjects")
		}
		return nil
	}
	seen := map[domain.Subject]bool{}
	for _, subject := range b.Subjects {
		if subject.Validate() != nil || seen[subject] {
			return fmt.Errorf("invalid or duplicate binding subject")
		}
		seen[subject] = true
	}
	if !seen[b.Recipient] {
		return fmt.Errorf("recipient absent from binding subjects")
	}
	return nil
}

// Класс не подменяется пользователем даже при совпадении строкового ID.
// Отсутствующее разрешённое объявление не превращает эмиссию в пустой успех.
func (c *Compiler) classDeclaration(s *Set, subject domain.Subject, typ, rel string, p Provenance) bool {
	if !subject.IsSystemClass() || c.plans.EffectDirectAccepts(typ, rel, string(subject.Type), "", "") {
		return true
	}
	s.obligations = append(s.obligations, Obligation{"recipient_declaration", typ + "." + rel, p})
	return false
}

// compilePublicReaders сначала доказывает отбор контейнера по owner-правилу,
// цели и области. В модель передаётся отношение НА всём выбранном контейнере:
// ограничение по запускающему ребёнку потеряло бы права других и будущих детей.
func (c *Compiler) compilePublicReaders(s *Set, b Binding, selectors []domain.RuleSelector, origins map[string]string, p Provenance) {
	type selected struct {
		region    []Constraint
		owners    map[string]bool
		authored  map[string]bool
		ambiguous bool
	}
	byType := map[string]*selected{}
	var order []string
	ownerFPs := domain.PublicReaderOwnerRuleFPs(selectors)
	for _, sel := range selectors {
		if sel.Container != nil || !ownerFPs[sel.RuleFP] {
			continue
		}
		for _, dotted := range sel.ObjectTypes {
			typ, ok := c.facts.FGAObjectType(dotted)
			if !ok {
				s.obligations = append(s.obligations, Obligation{"catalog_type", dotted, p})
				continue
			}
			regions, err := c.selectorRegions(sel, dotted, typ, b)
			if err != nil {
				s.obligations = append(s.obligations, Obligation{"public_reader_selector", err.Error(), p})
				continue
			}
			for _, region := range regions {
				entry := byType[dotted]
				if entry == nil {
					entry = &selected{region: region, owners: map[string]bool{}, authored: map[string]bool{}}
					byType[dotted] = entry
					order = append(order, dotted)
				} else if !reflect.DeepEqual(entry.region, region) {
					// Разные области owner требуют точного разбиения, включая
					// пересечения: общий fingerprint зависит от всех выбранных
					// оснований на КАЖДОМ контейнере. Не угадываем этот набор.
					entry.ambiguous = true
				}
				entry.owners[sel.RuleFP] = true
				entry.authored[origins[sel.RuleFP]] = true
			}
		}
	}
	for _, dotted := range order {
		entry := byType[dotted]
		grant, ok := c.facts.PublicReaderEffect(selectors, b.Subjects, dotted, entry.owners)
		if !ok {
			// Тип был проверен выше. Здесь отсутствие эффекта означает
			// отсутствие объявленного публичного producer, не unknown catalog.
			continue
		}
		ep := p
		ep.Primitive = "public_reader"
		ep.ProjectedRuleFP = grant.RuleFP
		var authored []string
		for fp := range entry.authored {
			authored = append(authored, fp)
		}
		sort.Strings(authored)
		ep.AuthoredRuleFP = strings.Join(authored, ",")
		if entry.ambiguous {
			s.obligations = append(s.obligations, Obligation{"public_reader_owners", "distinct owner regions require exact partition: " + dotted, ep})
			continue
		}
		if !c.classDeclaration(s, b.Recipient, grant.FGAType, grant.Relation, ep) {
			continue
		}
		c.derive(s, grant.FGAType, grant.Relation, entry.region, Condition{}, ep)
	}
}

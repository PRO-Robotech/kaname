// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// rolechildren.go — судья формы вложенного правила роли (kaname#874, приёмка
// docs/engineering/acceptance/nested-rule-reaches-descendants-of-a-named-container.md,
// редакция 2, Р1, ND-04 (а)–(е)).
//
// Правило над типом-контейнером несёт `children` — правила над типами, лежащими
// под ним по указателям `parents`, на любой глубине. Указатели типа берутся из
// раздела `resources` ЭТОГО манифеста, а для типа, которого манифест не объявил,
// — из канона модели прав, внесённого вызывающим ([WithTypeCanon], kaname#951):
// модулю не нужно копировать раздел `resources` канона ради суда своих ролей.
// Загрузчик принимает ключ, только если:
//
//  1. правило-владелец называет РОВНО ОДИН ресурс, и это не `*`;
//  2. ресурс владельца — не ярус иерархии: под ярусом выбирает ОБЛАСТЬ выдачи;
//  3. тип каждого вложенного правила — потомок типа владельца по `parents`;
//     сам себе тип потомком не является;
//  4. у вложенного правила нет `module` (оно берёт модуль владельца) и своих
//     `children` — глубину выражает тип, а не структура роли;
//  5. `children` либо отсутствует, либо непуст.
//
// # Почему пункт 4 судится по СЫРОМУ узлу
//
// Вложенное правило — свой тип [ChildRule] без полей `module` и `children`:
// рекурсивный тип сделал бы бесконечным обход полей структур, на котором стоит
// согласие схемы и структур (MOD-MF-21), а схема у вложенного правила этих
// ключей не объявляет. Строгий разбор (`KnownFields`) отверг бы такой ключ
// общим «неизвестное поле», не назвав, ЧТО не так с вложенностью. Поэтому оба
// ключа ищутся в узле документа ДО типизированного разбора, и находка несёт
// координату и причину.

import (
	"errors"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ErrRoleRuleNestingMalformed — вложенность правила роли не той формы.
var ErrRoleRuleNestingMalformed = errors.New("manifest: role rule nesting is malformed")

// ChildRule — вложенное правило роли манифеста (kaname#874). Те же ключи права,
// что у [Rule], без `module` (берётся у владельца) и без `children` (глубину
// выражает тип).
type ChildRule struct {
	Resources     []string          `yaml:"resources"`
	Classes       []string          `yaml:"classes"`
	Verbs         []string          `yaml:"verbs"`
	ResourceNames []string          `yaml:"resourceNames"`
	MatchLabels   map[string]string `yaml:"matchLabels"`
}

// Right — запись права вложенного правила и её форма (см. [Rule.Right]).
func (c ChildRule) Right() (values []string, named bool) {
	if len(c.Verbs) > 0 {
		return c.Verbs, true
	}
	return c.Classes, false
}

// DomainRule — вложенное правило в форме домена: модуль пуст, `classes` — глаголы
// (как у [Rule.DomainRule]).
func (c ChildRule) DomainRule() domain.Rule {
	return domain.Rule{
		Resources:     c.Resources,
		Verbs:         c.Classes,
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

// formRule — вложенное правило с записью права любой из двух форм (для судьи
// домена).
func (c ChildRule) formRule() domain.Rule {
	values, _ := c.Right()
	return domain.Rule{
		Resources:     c.Resources,
		Verbs:         values,
		ResourceNames: c.ResourceNames,
		MatchLabels:   c.MatchLabels,
	}
}

// domainChildren — вложенные правила в форме домена; nil — ключа нет.
func domainChildren(children []ChildRule, form bool) []domain.Rule {
	if children == nil {
		return nil
	}
	out := make([]domain.Rule, 0, len(children))
	for _, c := range children {
		if form {
			out = append(out, c.formRule())
		} else {
			out = append(out, c.DomainRule())
		}
	}
	return out
}

// refuseNestedChildKeys — пункт 4: `module` и `children` у вложенного правила,
// по сырому узлу документа (почему не по разобранному — шапка файла).
func refuseNestedChildKeys(doc *yaml.Node) error {
	var faults []error
	roles := mapValue(doc, "roles")
	if roles == nil || roles.Kind != yaml.SequenceNode {
		return nil
	}
	for i, role := range roles.Content {
		rules := mapValue(role, "rules")
		if rules == nil || rules.Kind != yaml.SequenceNode {
			continue
		}
		for j, rule := range rules.Content {
			children := mapValue(rule, "children")
			if children == nil || children.Kind != yaml.SequenceNode {
				continue
			}
			for k, child := range children.Content {
				if mapValue(child, "module") != nil {
					faults = append(faults, linkFault{
						kind:  ErrRoleRuleNestingMalformed,
						coord: locate(doc, "roles", i, "rules", j, "children", k, "module"),
						detail: fmt.Sprintf("roles[%d].rules[%d].children[%d].module: "+
							"вложенное правило берёт модуль правила-владельца", i, j, k),
					})
				}
				if mapValue(child, "children") != nil {
					faults = append(faults, linkFault{
						kind:  ErrRoleRuleNestingMalformed,
						coord: locate(doc, "roles", i, "rules", j, "children", k, "children"),
						detail: fmt.Sprintf("roles[%d].rules[%d].children[%d].children: "+
							"у вложенного правила своих children нет; более глубокий тип "+
							"называется прямо под правилом-владельцем", i, j, k),
					})
				}
			}
		}
	}
	if len(faults) > 0 {
		return errors.Join(faults...)
	}
	return nil
}

// validateRuleChildren — пункты 1, 2, 3 и 5 по разобранному правилу.
//
// Родство типов — [typeGraph]: объявленное этим манифестом, а для типов, которых
// манифест не объявил, — каноном модели прав, если вызывающий его внёс
// ([WithTypeCanon], kaname#951). `canon == nil` — судья видит только раздел
// `resources` документа, как до kaname#951.
func validateRuleChildren(m *Manifest, rule Rule, doc *yaml.Node, i, j int, canon TypeCanon) []error {
	if rule.Children == nil {
		return nil
	}
	fault := func(detail string, steps ...any) linkFault {
		return linkFault{
			kind:   ErrRoleRuleNestingMalformed,
			coord:  locate(doc, append([]any{"roles", i, "rules", j}, steps...)...),
			detail: detail,
		}
	}
	if len(rule.Children) == 0 {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].children: пустой перечень; "+
			"правило без вложенных пишется без ключа", i, j), "children")}
	}
	if len(rule.Resources) != 1 {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: правило с children "+
			"называет ровно один ресурс, получено %d", i, j, len(rule.Resources)), "resources")}
	}
	owner := rule.Resources[0]
	if owner == "*" {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: правило с children "+
			"называет ресурс, а не «*»", i, j), "resources")}
	}
	graph := newTypeGraph(m, canon)
	// Ярус иерархии — из ОДНОГО закрытого словаря якорей области (`scopeAnchors`):
	// своя копия здесь разошлась бы с ним молча, и ярус, добавленный туда, судья
	// вложенности не узнал бы.
	if t, ok := graph.objectTypeOf(owner); ok && contains(scopeAnchors, t) {
		return []error{fault(fmt.Sprintf("roles[%d].rules[%d].resources: %q — ярус иерархии; "+
			"под ярусом выбирает область выдачи, children у него нет", i, j, owner), "resources")}
	}

	var faults []error
	for k, child := range rule.Children {
		if formFaults := validateChildRightForm(child, doc, i, j, k); len(formFaults) > 0 {
			faults = append(faults, formFaults...)
			continue
		}
		for _, res := range child.Resources {
			if graph.unknown(res) {
				faults = append(faults, fault(fmt.Sprintf("roles[%d].rules[%d].children[%d].resources: "+
					"тип %q не объявлен ни разделом resources этого манифеста, ни каноном модели прав; "+
					"указателей parents у него нет, и потомком типа правила-владельца он не бывает",
					i, j, k, rule.Module+"."+res), "children", k, "resources"))
				continue
			}
			if res == "*" || !graph.descendsFrom(res, owner) {
				faults = append(faults, fault(fmt.Sprintf("roles[%d].rules[%d].children[%d].resources: "+
					"тип %q не лежит под %q ни по одному объявленному указателю parents; "+
					"вложенное правило действует только на потомков типа правила-владельца",
					i, j, k, rule.Module+"."+res, rule.Module+"."+owner), "children", k, "resources"))
			}
		}
	}
	return faults
}

// validateChildRightForm — две записи права у вложенного правила рядом не
// стоят (то же, что [validateRuleRightForm] у правила верхнего уровня).
func validateChildRightForm(child ChildRule, doc *yaml.Node, i, j, k int) []error {
	if len(child.Classes) == 0 || len(child.Verbs) == 0 {
		return nil
	}
	return []error{linkFault{
		kind:  ErrRoleRuleRightFormsCollide,
		coord: locate(doc, "roles", i, "rules", j, "children", k),
		detail: fmt.Sprintf("roles[%d].rules[%d].children[%d]: право записано ОБЕИМИ формами "+
			"сразу — и `classes`, и `verbs`. Формы взаимоисключающи: оставьте ОДНУ", i, j, k),
	}}
}

// TypeCanon — родство типов, объявленное КАНОНОМ модели прав образа (kaname#951).
//
// Вносится вызывающим через [WithTypeCanon] — тот же довод «порт, а не импорт
// владельца модели», что у [RelationOracle]: загрузчик не знает, кто держит
// модель, и не отмечает модель процесса прочитанной.
//
// Спрашивается ТОЛЬКО о типах, которых документ не объявил: объявленный тип
// судится своим разделом `resources`, и канон его не перекрывает. Поэтому у
// внесения нет того отказа, из-за которого канон не вносится оракулом на пути
// старта: тип нового модуля объявлен его же манифестом, и канон о нём не
// спрашивают вовсе.
type TypeCanon interface {
	// ParentTypes — типы модели, на которые ведут указатели типа objectType в
	// каноне, отсортированно и без повторов. Второе значение `false` — тип
	// каноном НЕ объявлен; `true` с пустым перечнем — объявлен и указателей не
	// несёт. Различие несущее: «типа нет» и «тип есть, предков нет» дают разные
	// отказы.
	ParentTypes(objectType string) ([]string, bool)
}

// WithTypeCanon вносит родство типов канона, которым судья вложенных правил
// судит типы, не объявленные документом (kaname#951). `nil` оставляет загрузку
// такой же, какой она была бы без опции.
func WithTypeCanon(c TypeCanon) LoadOption {
	return func(opts *loadOptions) {
		if c == nil {
			return
		}
		opts.canon = c
	}
}

// typeGraph — родство типов для судьи вложенности: объявленное ЭТИМ манифестом,
// а для необъявленных им типов — каноном (если внесён).
//
// Имя ресурса в правило роли пишется именем КАТАЛОГА (`repositories`), а канон
// ключуется типом модели (`registry_repository`). Тип необъявленного имени
// берётся у таблицы типов образа (`authzmap.ObjectType`) — той же, которую
// загрузчик уже спрашивает о владении типом (objecttype.go); второго словаря
// имён здесь не заводится.
type typeGraph struct {
	module string
	byName map[string]Resource
	byType map[string]Resource
	canon  TypeCanon
}

func newTypeGraph(m *Manifest, canon TypeCanon) typeGraph {
	byName := resourcesByName(m)
	byType := make(map[string]Resource, len(byName))
	for _, r := range byName {
		byType[r.ObjectType] = r
	}
	return typeGraph{module: m.Module, byName: byName, byType: byType, canon: canon}
}

// objectTypeOf — тип модели ресурса name: из раздела `resources` документа, иначе
// — из таблицы типов образа, если канон внесён и тип в нём объявлен.
func (g typeGraph) objectTypeOf(name string) (string, bool) {
	if r, ok := g.byName[name]; ok {
		return r.ObjectType, true
	}
	if g.canon == nil {
		return "", false
	}
	t, ok := authzmap.ObjectType(g.module, name)
	if !ok {
		return "", false
	}
	if _, declared := g.canon.ParentTypes(t); !declared {
		return "", false
	}
	return t, true
}

// unknown — имя не называет тип ни в документе, ни в каноне. Без внесённого
// канона судья об этом не утверждает ничего (`false`): отказ тогда даёт прежняя
// находка «не лежит под», как до kaname#951.
func (g typeGraph) unknown(name string) bool {
	if g.canon == nil || name == "*" {
		return false
	}
	_, ok := g.objectTypeOf(name)
	return !ok
}

// parentsOf — типы, на которые указывает тип objectType: по `parents` документа,
// если тип объявлен им, иначе — по канону.
func (g typeGraph) parentsOf(objectType string) []string {
	if r, ok := g.byType[objectType]; ok {
		out := make([]string, 0, len(r.Parents))
		for _, p := range r.Parents {
			out = append(out, p.Type)
		}
		return out
	}
	if g.canon == nil {
		return nil
	}
	parents, _ := g.canon.ParentTypes(objectType)
	return parents
}

// descendsFrom — ресурс child лежит под ресурсом owner по указателям parents на
// любой глубине. Сам себе ресурс потомком не является. Обход — по типам модели;
// цикл указателей (его судит раздел `resources` и допуск модели) обход не
// зацикливает.
func (g typeGraph) descendsFrom(child, owner string) bool {
	if child == owner {
		return false
	}
	ownerType, ok := g.objectTypeOf(owner)
	if !ok {
		return false
	}
	start, ok := g.objectTypeOf(child)
	if !ok {
		return false
	}
	seen := map[string]bool{start: true}
	queue := []string{start}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, p := range g.parentsOf(cur) {
			if p == ownerType {
				return true
			}
			if seen[p] {
				continue
			}
			seen[p] = true
			queue = append(queue, p)
		}
	}
	return false
}

// resourcesByName — ресурсы манифеста по имени.
func resourcesByName(m *Manifest) map[string]Resource {
	out := make(map[string]Resource, len(m.Resources))
	for _, r := range m.Resources {
		out[r.Name] = r
	}
	return out
}

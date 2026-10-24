// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmodel

// parenttypes.go — на какие типы ведут указатели типа (kaname#951).
//
// Вызывающий — судья вложенных правил роли манифеста: тип, который манифест
// модуля не объявил своим разделом `resources`, судится родством канона, и
// модулю не нужно копировать раздел канона ради суда своих ролей.
//
// Указатель — отношение, через которое хоть одно объявление ходит формой
// `X from <указатель>` (`authzplan.Model.Pointers`); его цели —
// `authzplan.Model.PointerTargets`. Своего определения указателя здесь не
// заводится: второе разошлось бы с разбором молча, ровно на той форме, которой
// не знает.

import "sort"

// ParentTypes — типы, на которые ведут указатели типа objectType, по
// возрастанию и без повторов.
//
// ok=false — тип моделью не объявлен; пустой перечень у объявленного типа
// законен и означает «указателей нет» (ярус вершины цепи), а не «типа нет».
func (p *Plans) ParentTypes(objectType string) ([]string, bool) {
	t := p.model.Type(objectType)
	if t == nil {
		return nil, false
	}
	seen := map[string]bool{}
	out := []string{}
	for rel := range p.model.Pointers[objectType] {
		for _, target := range p.model.PointerTargets(t.Rel(rel)) {
			if seen[target] {
				continue
			}
			seen[target] = true
			out = append(out, target)
		}
	}
	sort.Strings(out)
	return out, true
}

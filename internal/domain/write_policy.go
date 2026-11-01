// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// write_policy.go — ЗАКРЫТАЯ ПОЛИТИКА ЗАПИСИ модуля на тип объекта (kaname#982,
// приёмка `kaname-derives-the-parent-of-a-registered-object.md`, Р1).
//
// Что модуль вправе записать на объект своего типа, объявляет манифест модуля —
// тройками «тип объекта · отношение · тип субъекта»:
//
//	политика(T) = { (T, p.name, p.type) : p — указатель T из parents }
//	            ∪ { (T, w.relation, s)  : w — запись T из writes, s ∈ w.subjects }
//
// Политика СУЖАЕТ правило проксируемой записи (`corelib/authz/proxytuple`) и не
// расширяет его: регистрация обязана пройти оба. Источник — живая строка каталога
// (указатели и записи доезжают туда из доставленного манифеста либо из посева в
// паритете с манифестами), а не литерал этого пакета.

import "strings"

// writeSubjectTypes — ЗАКРЫТЫЙ перечень типов субъекта записи `writes`. Сверх
// указателя модуль пишет создателя, а создатель — человек или учётка; класс или
// группа в отношении иерархии раздали бы доступ мимо выдачи.
var writeSubjectTypes = []string{"user", "service_account"}

// WriteSubjectTypes — копия закрытого перечня типов субъекта записи.
func WriteSubjectTypes() []string { return append([]string(nil), writeSubjectTypes...) }

// IsWriteSubjectType — тип входит в закрытый перечень субъектов записи.
func IsWriteSubjectType(typ string) bool {
	for _, s := range writeSubjectTypes {
		if s == typ {
			return true
		}
	}
	return false
}

// ParentPointer — указатель типа: ИМЯ отношения и ТИП объекта, на который оно
// указывает (`{name: parent, type: registry_registry}` у репозитория).
type ParentPointer struct {
	Name string
	Type string
}

// WriteGrant — одна пара записи `writes`: отношение и тип субъекта.
type WriteGrant struct {
	Relation    string
	SubjectType string
}

// writeTokenSep — разделитель отношения и типа субъекта в форме хранения. Ни в
// имени отношения, ни в имени типа его нет: оба — строчная латиница, цифры и `_`.
const writeTokenSep = ":"

// Token — форма хранения пары в строке каталога: `<отношение>:<тип субъекта>`.
func (g WriteGrant) Token() string { return g.Relation + writeTokenSep + g.SubjectType }

// ParseWriteGrant — пара из формы хранения. ok=false — строка не той формы:
// разделителя нет, одна из половин пуста либо разделителей больше одного.
func ParseWriteGrant(token string) (WriteGrant, bool) {
	rel, sub, found := strings.Cut(token, writeTokenSep)
	if !found || rel == "" || sub == "" || strings.Contains(sub, writeTokenSep) {
		return WriteGrant{}, false
	}
	return WriteGrant{Relation: rel, SubjectType: sub}, true
}

// WriteTriple — тройка политики: тип объекта, отношение, тип субъекта.
type WriteTriple struct {
	ObjectType  string
	Relation    string
	SubjectType string
}

// WritePolicy — политика записи одного типа объекта (тип назван словарём
// модели прав).
type WritePolicy struct {
	ObjectType string
	Pointers   []ParentPointer
	Writes     []WriteGrant
	// PermanentProject — тип объявил неизменность проекта своих объектов
	// (kaname#983): регистрация обязана нести проект и полем, и звеном `project`
	// цепи, и сверяется с привязкой объекта к проекту.
	PermanentProject bool
}

// Admits — кортеж с отношением relation и субъектом типа subjectType проходит
// политику: тройка (тип, отношение, тип субъекта) в ней есть.
func (p WritePolicy) Admits(relation, subjectType string) bool {
	if ptr, ok := p.Pointer(relation); ok {
		return ptr.Type == subjectType
	}
	for _, w := range p.Writes {
		if w.Relation == relation && w.SubjectType == subjectType {
			return true
		}
	}
	return false
}

// Pointer — указатель с именем relation; ok=false — relation не указатель типа.
func (p WritePolicy) Pointer(relation string) (ParentPointer, bool) {
	for _, ptr := range p.Pointers {
		if ptr.Name == relation {
			return ptr, true
		}
	}
	return ParentPointer{}, false
}

// PointerNames — имена указателей типа в порядке манифеста.
func (p WritePolicy) PointerNames() []string {
	out := make([]string, 0, len(p.Pointers))
	for _, ptr := range p.Pointers {
		out = append(out, ptr.Name)
	}
	return out
}

// Triples — все тройки политики: указатели, затем записи, в порядке манифеста.
func (p WritePolicy) Triples() []WriteTriple {
	out := make([]WriteTriple, 0, len(p.Pointers)+len(p.Writes))
	for _, ptr := range p.Pointers {
		out = append(out, WriteTriple{ObjectType: p.ObjectType, Relation: ptr.Name, SubjectType: ptr.Type})
	}
	for _, w := range p.Writes {
		out = append(out, WriteTriple{ObjectType: p.ObjectType, Relation: w.Relation, SubjectType: w.SubjectType})
	}
	return out
}

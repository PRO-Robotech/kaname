// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// system_class.go — системный класс субъекта: «аноним» и «вошедший»
// (приёмка anonymous-and-authenticated-are-subject-classes.md, kaname#829).
//
// Класс — именованный субъект ЗАКРЫТОГО словаря, а не подстановка: арендатор
// выдаёт и отзывает его поимённо теми же глаголами, что выдачу человеку (Р1).
// Здесь живут ТРИ правила, и у каждого ровно одно написание в дереве:
//
//   - словарь имён класса (Р1, SC-02);
//   - классификация говорящего — какие классы получает вопрос от имени
//     данного субъекта (Р2, SC-10, SC-11). Её читают все три формы вопроса к
//     модели (прямой, страничный, перечень) и эталон формы; три независимых
//     написания разошлись бы молча — перечень отдал бы то, что вопрос
//     отвергает;
//   - кто говорящим НЕ бывает (Р3, SC-14, SC-15).

import (
	"fmt"
	"strings"
)

// SubjectTypeSystemClass — вид субъекта «системный класс» (Р1).
const SubjectTypeSystemClass SubjectType = "system_class"

// Имена классов закрытого словаря.
const (
	// ClassAnonymous — любой вызывающий, в том числе без личности.
	ClassAnonymous SubjectID = "anonymous"
	// ClassAuthenticated — любой принципал кластера с личностью, из любого
	// аккаунта: выдача этому классу видна за границей арендатора (Р5).
	ClassAuthenticated SubjectID = "authenticated"
)

// Субъекты классов в записи модели прав (`тип:идентификатор`).
const (
	SpeakerAnonymous     = string(SubjectTypeSystemClass) + ":" + string(ClassAnonymous)
	SpeakerAuthenticated = string(SubjectTypeSystemClass) + ":" + string(ClassAuthenticated)
)

// classReadVerbs — единственные глаголы, которые класс получает (Р4).
var classReadVerbs = map[string]bool{"get": true, "list": true}

// IsClassReadVerb — глагол чтения, допустимый у выдачи классу (Р4, SC-23).
func IsClassReadVerb(verb string) bool { return classReadVerbs[NormalizeVerb(verb)] }

// LegacyPublicWildcardWord — прежнее слово публичного чтения в составе субъектов
// манифеста. Рендер блока переводит его в класс (`modelrender.subjectWords`), и
// поэтому оно — одно из написаний класса ([IsClassSubjectWord]).
const LegacyPublicWildcardWord = "user:*"

// IsClassSubjectWord — слово состава субъектов называет системный класс:
// `system_class`, `system_class:<класс>` либо прежнее слово
// [LegacyPublicWildcardWord], которое рендер переводит в класс.
//
// Единственное написание правила (kaname#866, CE-03): его читают загрузчик
// манифеста (Р2 — класс в действии чтения ресурса с ключом) и допуск собранной
// модели (Д3 — запись класса в блоке нового типа). Узнаётся по ВИДУ слова, а не
// по имени класса: имена — закрытый словарь, и запись с незнакомым именем
// обязана дойти до отказа, а не проскочить мимо него.
func IsClassSubjectWord(word string) bool {
	if word == LegacyPublicWildcardWord {
		return true
	}
	kind, _, _ := strings.Cut(word, ":")
	return SubjectType(kind) == SubjectTypeSystemClass
}

// IsSystemClassName — имя из закрытого словаря классов.
func IsSystemClassName(id SubjectID) bool {
	return id == ClassAnonymous || id == ClassAuthenticated
}

// validateSystemClassName — отказ формы имени класса (SC-02). Пустое имя
// отвергается раньше, общим для всех видов текстом (SC-03).
func validateSystemClassName(id SubjectID) error {
	if IsSystemClassName(id) {
		return nil
	}
	return fmt.Errorf("Illegal argument subject id %q for subject type %s (allowed: %s|%s)",
		string(id), SubjectTypeSystemClass, ClassAnonymous, ClassAuthenticated)
}

// IsSystemClass — субъект есть системный класс.
func (s Subject) IsSystemClass() bool { return s.Type == SubjectTypeSystemClass }

// HasSystemClass — среди субъектов выдачи есть системный класс.
func HasSystemClass(subjects []Subject) bool {
	for _, s := range subjects {
		if s.IsSystemClass() {
			return true
		}
	}
	return false
}

// SpeakerClasses — классы, которые получает вопрос от имени `speaker`, СВЕРХ
// самого говорящего (Р2).
//
// Правило перечисляет виды, которым классы положены, а ветви «все прочие» у
// него нет:
//
//   - человек и сервисная учётка (`user:<id>`, `service_account:<id>`) —
//     вошедший: оба класса. Вход не отнимает прав, поэтому выданное анониму
//     читает и вошедший;
//   - `system_class:anonymous` — вызывающий без личности: классов сверх себя у
//     него нет. Обратного вывода нет никогда: у анонима нет `authenticated`
//     (SC-10);
//   - группа (`group:<id>`, `group:<id>#member`), подстановка любого вида
//     (`user:*`, SC-15) и всё прочее — ничего: группа говорящим-личностью не
//     является (SC-11), подстановка говорящим не бывает вовсе. Вопрос о
//     вызывающем без личности задаётся классом `system_class:anonymous`, а не
//     подстановкой: плоскость данных реестра kacho переведена на класс
//     (SC-39), и переходного отображения подстановки в аноним нет.
//
// Безымянность — значение входа (`system_class:anonymous`), а не вывод из
// формы строки: пустой и нераспознанный говорящий отвергаются раньше, разбором
// [SpeakerRefusal].
func SpeakerClasses(speaker string) []string {
	kind, id, ok := strings.Cut(speaker, ":")
	if !ok || id == "" || strings.ContainsAny(id, "#*") {
		return []string{}
	}
	switch SubjectType(kind) {
	case SubjectTypeUser, SubjectTypeServiceAccount:
		return []string{SpeakerAuthenticated, SpeakerAnonymous}
	default:
		return []string{}
	}
}

// SpeakerRefusal — отказ говорящему, который говорящим не бывает (Р3).
//
// Один разборщик на все методы, принимающие говорящего (`Check`, `BatchCheck`,
// `CheckRelation`): отказ в одном из них оставил бы соседний спрашивающим от
// имени «вошедшего без личности».
//
//   - `system_class:authenticated` — «вошедший» без названной личности есть
//     противоречие (SC-14); любое имя класса, кроме `anonymous`, — тем же
//     отказом;
//   - подстановка любого вида, `user:*` в том числе, — не говорящий (SC-15):
//     она называет множество, а не того, кто спрашивает.
//
// nil — говорящий допустим.
func SpeakerRefusal(speaker string) error {
	kind, id, ok := strings.Cut(speaker, ":")
	if !ok {
		return nil
	}
	if SubjectType(kind) == SubjectTypeSystemClass {
		if SubjectID(id) == ClassAnonymous {
			return nil
		}
		return fmt.Errorf("Illegal argument subject: system class %s is not a speaker", id)
	}
	if id == "*" {
		return fmt.Errorf("Illegal argument subject: wildcard is not a speaker")
	}
	return nil
}

// PublicationSubject — ХРАНИМЫЙ субъект публикации объекта для чтения без
// входа (Р8, SC-12).
//
// Входное слово соседа не меняется: владелец ресурса публикует парой `user:*`
// + `v_get` (`register-resource-checks-the-module-vocabulary.md`). Здесь —
// ЕДИНСТВЕННЫЙ перевод этого слова в субъекта, которого хранит служба. Его
// зовут запись и снятие публикации, разбор остаточных фактов и миграция
// переезда: снятие, назвавшее другое написание, удалило бы несуществующий факт,
// и чтение анонимом устояло бы (SC-13).
const PublicationSubject = SpeakerAnonymous

// PublicationRelation — отношение хранимой публикации.
const PublicationRelation = "v_get"

// IsStoredPublication — хранимый факт есть публикация для чтения без входа.
// Узнаётся по идентичности хранимой пары, а не по входному слову: после
// переезда входное слово (`user:*`) в фактах не встречается.
func IsStoredPublication(subject, relation string) bool {
	return subject == PublicationSubject && relation == PublicationRelation
}

// GrantsReadsOnly — каждый глагол роли — `get` либо `list` (Р4, SC-21).
//
// Судится АВТОРСКОЕ написание, а не раскрытый набор: глагол `*` раскрывается
// в набор ТИПА, который растёт вместе с каталогом, и роль, читающая сегодня,
// завтра писала бы — поэтому `*` пишущим считается всегда. Роль без правил
// судится по своей хранимой проекции прав (`<модуль>.<ресурс>.<…>.<глагол>`),
// и в ней действует то же правило.
//
// То же правило держит база (`kaname.role_grants_reads_only`) — на пути
// записи, где у выдачи и правки роли последнее слово (ban #10); здесь оно
// ради синхронного отказа до заведения операции.
func (r Role) GrantsReadsOnly() bool {
	if len(r.Rules) > 0 {
		// Вложенные правила читаются наравне с верхним уровнем (kaname#874, M1):
		// пишущий глагол во вложенном — пишущий глагол роли.
		for _, rule := range withEffectiveChildren(r.Rules) {
			for _, v := range rule.Verbs {
				if !IsClassReadVerb(v) {
					return false
				}
			}
		}
		return true
	}
	for _, p := range r.Permissions {
		s := string(p)
		i := strings.LastIndexByte(s, '.')
		if i < 0 || !IsClassReadVerb(s[i+1:]) {
			return false
		}
	}
	return true
}

// RoleBoundToSystemClassText — текст отказа правке роли, выданной классу
// (SC-22). Один производитель на синхронный отказ и на отказ записи.
func RoleBoundToSystemClassText(id RoleID) string {
	return "Role " + string(id) + " is bound to a system class subject; it accepts read verbs only"
}

// RoleNotReadOnlyForClassText — текст отказа выдаче классу роли с пишущим
// глаголом (SC-21). Один производитель на синхронный отказ и на отказ записи.
func RoleNotReadOnlyForClassText(id RoleID) string {
	return "Role " + string(id) + " grants verbs beyond get and list; a system class subject accepts read-only roles"
}

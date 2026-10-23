// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// subjects.go — разворачивание выдачи судит КАЖДОГО её субъекта (kaname#880).
//
// # Почему не «субъект выдачи», а перечень
//
// Выдача называет перечень субъектов (`access_binding_subjects`), и класс с
// людьми в одной выдаче разрешён (SC-04 приёмки
// anonymous-and-authenticated-are-subject-classes.md). Решение судит ветвь
// выдач по строке КАЖДОГО субъекта (`relverdict`: фильтр глаголов класса,
// запрет вложенного правила классу — оба по `bs.subject_type` строки
// субъекта). Материализатор, читавший одну пару «вид, идентификатор»
// (проекцию первого субъекта), разворачивал выдачу только первому: класс на
// втором месте получал сам контейнер ветвью выдач и ни одного его потомка —
// исход зависел от порядка субъектов.
//
// Поэтому одиночной пары у [BindingScope] нет вовсе: читать «первого» здесь
// нечем by construction. Кортежи члена — объединение по субъектам, каждому со
// своими глаголами:
//   - классу — только чтение (Р4, SC-23), человеку, учётке, группе — глаголы
//     правила как есть; та же граница, что `relverdict.classVerbFilterSQL`;
//   - вложенное правило классу не применяется (Р5, ND-10) — у класса одна
//     дорога к потомкам, `public_reader`; остальным субъектам той же выдачи
//     применяется;
//   - `public_reader` пишется каждому классу выдачи и никому, кроме классов.

import "github.com/PRO-Robotech/kaname/internal/domain"

// grantee — субъект выдачи в форме кортежа и глаголы, которые выдача ему даёт.
type grantee struct {
	subject string
	verbs   []string
}

// isClassSubject — субъект — системный класс.
func isClassSubject(s domain.Subject) bool {
	return s.Type == domain.SubjectTypeSystemClass
}

// subjectRef — субъект в форме кортежа.
func subjectRef(s domain.Subject) string {
	return domain.FGASubjectRef(string(s.Type), string(s.ID))
}

// classReadVerbs — только глаголы чтения (Р4); `*` чтением не считается: он
// раскрывается в набор типа, а набор растёт.
func classReadVerbs(verbs []string) []string {
	out := make([]string, 0, len(verbs))
	for _, v := range verbs {
		if domain.IsClassReadVerb(v) {
			out = append(out, v)
		}
	}
	return out
}

// subjectVerbs — глаголы из `verbs`, которые выдача даёт субъекту `s`: классу —
// только чтение, какими бы ни были правила роли СЕЙЧАС (роль может получить
// пишущий глагол поставкой модуля, мимо стража правки).
func subjectVerbs(s domain.Subject, verbs []string) []string {
	if isClassSubject(s) {
		return classReadVerbs(verbs)
	}
	return verbs
}

// grantees — субъекты выдачи, которым набор `verbs` даёт хоть один глагол,
// каждый со своими глаголами. `nested` — набор принадлежит вложенному правилу:
// классу оно не применяется (Р5, ND-10).
func grantees(bs BindingScope, verbs []string, nested bool) []grantee {
	out := make([]grantee, 0, len(bs.Subjects))
	for _, s := range bs.Subjects {
		if nested && isClassSubject(s) {
			continue
		}
		v := subjectVerbs(s, verbs)
		if len(v) == 0 {
			continue
		}
		out = append(out, grantee{subject: subjectRef(s), verbs: v})
	}
	return out
}

// selectorGrantees — субъекты, которым селектор `sel` выдачи что-то даёт.
func selectorGrantees(bs BindingScope, sel domain.RuleSelector) []grantee {
	return grantees(bs, sel.Verbs, sel.Container != nil)
}

// classSubjects — классы выдачи в форме кортежа, в порядке перечня.
func classSubjects(bs BindingScope) []string {
	var out []string
	for _, s := range bs.Subjects {
		if isClassSubject(s) {
			out = append(out, subjectRef(s))
		}
	}
	return out
}

// hasNonClassSubject — среди субъектов выдачи есть не-класс: вложенное правило
// ей применяется.
func hasNonClassSubject(bs BindingScope) bool {
	for _, s := range bs.Subjects {
		if !isClassSubject(s) {
			return true
		}
	}
	return false
}

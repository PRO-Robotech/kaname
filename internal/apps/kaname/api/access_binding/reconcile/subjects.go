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

// grantees — субъекты выдачи, которым набор `verbs` даёт хоть один глагол,
// каждый со своими глаголами. `nested` — набор принадлежит вложенному правилу:
// классу оно не применяется (Р5, ND-10).
func grantees(bs BindingScope, verbs []string, nested bool) []grantee {
	recipients := domain.GrantRecipients(bs.Subjects, verbs, nested)
	out := make([]grantee, 0, len(recipients))
	for _, recipient := range recipients {
		out = append(out, grantee{
			subject: domain.FGASubjectRef(string(recipient.Subject.Type), string(recipient.Subject.ID)),
			verbs:   recipient.Verbs,
		})
	}
	return out
}

// selectorGrantees — субъекты, которым селектор `sel` выдачи что-то даёт.
func selectorGrantees(bs BindingScope, sel domain.RuleSelector) []grantee {
	return grantees(bs, sel.Verbs, sel.Container != nil)
}

// hasNonClassSubject — среди субъектов выдачи есть не-класс: вложенное правило
// ей применяется.
func hasNonClassSubject(bs BindingScope) bool {
	return domain.HasNonClassSubject(bs.Subjects)
}

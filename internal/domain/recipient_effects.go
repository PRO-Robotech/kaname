// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// GrantRecipient — типизированный получатель и его глаголы одной ветви выдачи.
// Класс остаётся классом; превращение его в человека изменило бы охват выдачи.
type GrantRecipient struct {
	Subject Subject
	Verbs   []string
}

// ClassReadVerbs оставляет авторские глаголы чтения в исходном порядке.
// Звёздочка чтением не считается: множество её глаголов может расти (SC-23).
func ClassReadVerbs(verbs []string) []string {
	out := make([]string, 0, len(verbs))
	for _, v := range verbs {
		if IsClassReadVerb(v) {
			out = append(out, v)
		}
	}
	return out
}

// RecipientVerbs — общая граница материализации и анализа эффекта: классу
// доступно только чтение верхнего уровня (SC-04, SC-23); вложенная ветвь ему
// ничего не даёт (ND-10). Публичное чтение потомков — отдельное отношение.
// Субъект уже проверен границей входа; функция не заменяет Subject.Validate.
func RecipientVerbs(subject Subject, verbs []string, nested bool) []string {
	if subject.IsSystemClass() {
		if nested {
			return nil
		}
		return ClassReadVerbs(verbs)
	}
	return verbs
}

// GrantRecipients разворачивает ветвь по ВСЕМ субъектам без перестановки и
// пропуска соседей класса. Получатели без глаголов в результат не входят.
func GrantRecipients(subjects []Subject, verbs []string, nested bool) []GrantRecipient {
	out := make([]GrantRecipient, 0, len(subjects))
	for _, subject := range subjects {
		v := RecipientVerbs(subject, verbs, nested)
		if len(v) != 0 {
			out = append(out, GrantRecipient{Subject: subject, Verbs: v})
		}
	}
	return out
}

// SystemClassSubjects сохраняет классы полного перечня в исходном порядке.
func SystemClassSubjects(subjects []Subject) []Subject {
	var out []Subject
	for _, subject := range subjects {
		if subject.IsSystemClass() {
			out = append(out, subject)
		}
	}
	return out
}

// HasNonClassSubject сообщает, есть ли получатель обычной вложенной ветви.
func HasNonClassSubject(subjects []Subject) bool {
	for _, subject := range subjects {
		if !subject.IsSystemClass() {
			return true
		}
	}
	return false
}

// PublicReaderOwnerRuleFPs — правила, чьи выбранные контейнеры могут дать
// классу публичное чтение потомков. Наличие отпечатка ещё не доказывает отбор
// конкретного контейнера, его принадлежность цели или области выдачи.
func PublicReaderOwnerRuleFPs(selectors []RuleSelector) map[string]bool {
	out := map[string]bool{}
	for _, sel := range selectors {
		if sel.Container == nil && len(ClassReadVerbs(sel.Verbs)) > 0 {
			out[sel.RuleFP] = true
		}
	}
	return out
}

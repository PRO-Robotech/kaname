// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// notification_recipient.go — получатель письма в справочнике адресов (приёмка
// NTF-3 Р7, kacho#2918): исход `Resolve` и запись получателя, по которой он
// выводится.

// RecipientOutcome — исход справочника. Условия проверяются в порядке
// значений таблицы Р7; первое невыполненное даёт исход.
type RecipientOutcome int

const (
	// RecipientOutcomeUnspecified — нулевое значение; справочник его не отдаёт.
	RecipientOutcomeUnspecified RecipientOutcome = iota
	// RecipientAddress — всё выполнено: адрес и видимые ссылки.
	RecipientAddress
	// RecipientSubjectNotFound — субъекта нет.
	RecipientSubjectNotFound
	// RecipientSubjectInactive — пользователь не в состоянии ACTIVE.
	RecipientSubjectInactive
	// RecipientAudienceDenied — ни одна ссылка не видна либо у аккаунта нет
	// владельца-пользователя.
	RecipientAudienceDenied
	// RecipientNoConfirmedAddress — субъект — учётная запись службы, либо
	// адрес не подтверждён.
	RecipientNoConfirmedAddress
)

// RecipientKind — вид субъекта-получателя.
type RecipientKind int

const (
	// RecipientKindUser — пользователь: у него есть адрес.
	RecipientKindUser RecipientKind = iota + 1
	// RecipientKindServiceAccount — учётная запись службы: адреса нет никогда.
	RecipientKindServiceAccount
)

// RecipientRecord — запись получателя, прочитанная одним оператором.
type RecipientRecord struct {
	// Active — пользователь в состоянии ACTIVE. У учётной записи службы не
	// заполняется и не читается.
	Active bool
	// Email — адрес пользователя; пуст у учётной записи службы.
	Email string
	// EmailVerified — адрес подтверждён.
	EmailVerified bool
}

// HasConfirmedAddress — у получателя вида kind есть подтверждённый адрес.
func (r RecipientRecord) HasConfirmedAddress(kind RecipientKind) bool {
	return kind == RecipientKindUser && r.EmailVerified && r.Email != ""
}

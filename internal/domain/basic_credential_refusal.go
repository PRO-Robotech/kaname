// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import "errors"

// BasicCredentialRefusalReason — ПРИЧИНА единого отказа полосы базового
// секрета (задача kaname#379). Закрытый словарь.
//
// # Почему причина есть, а отказ всё равно один
//
// Наружу полоса отвечает ОДНИМ отказом — [ErrBasicCredentialRefused]:
// различимый исход был бы оракулом. Но отказ, неотличимый и внутри, делает
// каждый контроль полосы ненаблюдаемым: отсечка отзыва-всех, сработавшая
// тысячу раз, выглядит так же, как перебор секрета, и так же, как контроль, не
// сработавший ни разу.
//
// Поэтому причина едет ВНУТРЬ — значением ошибки ([RefuseBasicCredential]) — и
// читается только [BasicCredentialRefusalReasonOf]. Текст ошибки остаётся
// дословно текстом единого отказа: вызывающий, напечатавший её, различия не
// увидит, а на провод полоса отдаёт свой фиксированный текст и вовсе не
// значение ошибки.
type BasicCredentialRefusalReason string

const (
	// BasicRefusalMalformed — предъявленное не называет удостоверения, которое
	// у нас может быть: пусто, форма или контрольная сумма не сходятся, вид по
	// приставке идентификатора не наш. База не спрашивалась.
	BasicRefusalMalformed BasicCredentialRefusalReason = "malformed"
	// BasicRefusalNotFound — живой строки нет: отозвано, истекло, владелец
	// неактивен либо её не было никогда. Внутри эти случаи тоже неразличимы, и
	// это не упущение: их отсекает один предикат одного оператора, а не
	// развилка, и развести их значило бы завести второй запрос.
	BasicRefusalNotFound BasicCredentialRefusalReason = "not-found"
	// BasicRefusalSecretMismatch — строка есть, секрет не тот.
	BasicRefusalSecretMismatch BasicCredentialRefusalReason = "secret-mismatch"
	// BasicRefusalOwnerRevoked — удостоверение выдано не позже отсечки
	// отзыва-всех его владельца-человека. Имя то же, что у исхода полосы ключа
	// токен-эндпоинта: один контроль — одно имя на всех полосах, которые его
	// исполняют.
	BasicRefusalOwnerRevoked BasicCredentialRefusalReason = "owner-revoked"
)

// BasicCredentialRefusalReasons — закрытый словарь целиком, в объявленном
// порядке. Читатели словаря (перепись исходов, витрина) выводят свои клетки
// отсюда, а не выписывают их второй копией.
func BasicCredentialRefusalReasons() []BasicCredentialRefusalReason {
	return []BasicCredentialRefusalReason{
		BasicRefusalMalformed,
		BasicRefusalNotFound,
		BasicRefusalSecretMismatch,
		BasicRefusalOwnerRevoked,
	}
}

// basicCredentialRefusal — единый отказ, несущий причину внутрь.
type basicCredentialRefusal struct {
	reason BasicCredentialRefusalReason
}

// Error — ДОСЛОВНО текст единого отказа: по тексту причину не узнать.
func (e basicCredentialRefusal) Error() string { return ErrBasicCredentialRefused.Error() }

// Unwrap — `errors.Is(err, ErrBasicCredentialRefused)` истинно при любой
// причине: для всякого, кто различает «отказ» и «авторитет не ответил», отказ с
// причиной остаётся тем же отказом.
func (e basicCredentialRefusal) Unwrap() error { return ErrBasicCredentialRefused }

// RefuseBasicCredential — единый отказ полосы с названной причиной.
func RefuseBasicCredential(reason BasicCredentialRefusalReason) error {
	return basicCredentialRefusal{reason: reason}
}

// BasicCredentialRefusalReasonOf — причина отказа полосы.
//
// false — причина не названа: ошибка не отказ полосы либо отказ отдан голым
// сторожевым. Это отдельный исход, а не причина по умолчанию: подставленная
// причина выглядела бы фактом и легла бы в чужую клетку.
func BasicCredentialRefusalReasonOf(err error) (BasicCredentialRefusalReason, bool) {
	var refusal basicCredentialRefusal
	if !errors.As(err, &refusal) {
		return "", false
	}
	return refusal.reason, true
}

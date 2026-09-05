// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"fmt"
	"time"
)

// CredentialKind — ЧЕМ УДОСТОВЕРЕНИЕ СЕБЯ ПРЕДЪЯВЛЯЕТ (задача #1142, приёмка
// BAT-1 §2.5, §4.1).
//
// Значение — то же, что лежит в колонке `credential_kind` обеих таблиц
// удостоверений: второго написания не заводится. Вид ЗАПИСЫВАЕТСЯ при вставке и
// читателем НЕ вычисляется — правило вывода по содержимому живёт ровно на одном
// пути (обратное заполнение существующих строк) и после него не применяется
// никогда.
type CredentialKind string

const (
	// CredentialKindUnspecified — вид не назван вызывающим. Встречается ТОЛЬКО
	// во входе выдачи и разрешается сохранённым поведением; в строке
	// удостоверения не бывает.
	CredentialKindUnspecified CredentialKind = ""

	// CredentialKindKeypair — ключевая пара ES256: вызывающий сам собирает и
	// подписывает `client_assertion` и обменивает его.
	CredentialKindKeypair CredentialKind = "KEYPAIR"

	// CredentialKindSecret — однострочный непрозрачный секрет, предъявляемый
	// как есть.
	CredentialKindSecret CredentialKind = "SECRET"

	// CredentialKindFederated — удостоверение предъявляет ВНЕШНИЙ издатель по
	// перечню доверенных субъектов; ни материала, ни секрета у нас нет.
	CredentialKindFederated CredentialKind = "FEDERATED"

	// CredentialKindLegacy — строка прежнего потока. НЕ ВЫДАЁТСЯ ни одним
	// глаголом; появляется только обратным заполнением.
	CredentialKindLegacy CredentialKind = "LEGACY"
)

// String — значение как оно лежит в колонке.
func (k CredentialKind) String() string { return string(k) }

// IsIssuable отвечает, производит ли этот вид хоть один глагол выдачи.
// LEGACY не производит НИКТО — и это свойство самого вида, а не проверки в
// конкретном глаголе: иначе следующий глагол завёл бы под него выдачу.
func (k CredentialKind) IsIssuable() bool {
	switch k {
	case CredentialKindKeypair, CredentialKindSecret, CredentialKindFederated:
		return true
	default:
		return false
	}
}

// ErrCredentialKindField — имя поля, которое обязан называть отказ. Объявлено
// одним местом, чтобы тон отказа не разошёлся между двумя глаголами выдачи.
// #nosec G101 -- это ИМЯ ПОЛЯ запроса, которое обязан назвать текст отказа
// (конвенция отказов Kachō), а не значение удостоверения.
const ErrCredentialKindField = "credential_kind"

// ResolveIssuedKind — КЛАССИФИКАТОР НАД ЗАПРОСОМ ВЫДАЧИ. Ветвей ТРИ, и дыры у
// него нет by construction: «ни материала, ни перечня» здесь означает KEYPAIR,
// потому что материал чеканим МЫ — строка получает его при выпуске.
//
// Это НЕ тот классификатор, что работает над содержимым уже лежащих строк: тот
// четырёхветвевой, живёт в обратном заполнении и обязан иметь ветвь LEGACY,
// потому что материал чеканили не всегда мы. Спутать их значило бы получить
// «корзину прочее» наоборот — вход без вида не отвергается, а получает
// ближайший.
//
// asked — вид, названный вызывающим (пустой = не назван).
// hasTrustedSubjects — непуст ли перечень доверенных субъектов запроса.
// federationSupported — есть ли у этого глагола поле, которым задаётся
// федеративный вид (у личности его нет, и вид недостижим by construction).
func ResolveIssuedKind(asked CredentialKind, hasTrustedSubjects, federationSupported bool) (CredentialKind, error) {
	switch asked {
	case CredentialKindUnspecified:
		// Сохранённое ДОСЛОВНО прежнее поведение: вид выводится из перечня.
		if hasTrustedSubjects {
			return CredentialKindFederated, nil
		}
		return CredentialKindKeypair, nil

	case CredentialKindLegacy:
		return "", fmt.Errorf(
			"%s: LEGACY is not issued by any verb — it describes rows of the previous flow",
			ErrCredentialKindField)

	case CredentialKindFederated:
		if !federationSupported {
			return "", fmt.Errorf(
				"%s: FEDERATED is not available for this credential — it has no trusted_subjects field",
				ErrCredentialKindField)
		}
		if !hasTrustedSubjects {
			return "", fmt.Errorf(
				"%s: FEDERATED requires a non-empty trusted_subjects", ErrCredentialKindField)
		}
		return CredentialKindFederated, nil

	case CredentialKindKeypair, CredentialKindSecret:
		// Непустой перечень доверенных субъектов И ЕСТЬ то, чем FEDERATED
		// отличается от прочих видов: названный вид авторитетен, а несогласие
		// с перечнем отвергается с именем поля.
		if hasTrustedSubjects {
			return "", fmt.Errorf(
				"%s: %s conflicts with a non-empty trusted_subjects (that names FEDERATED)",
				ErrCredentialKindField, asked)
		}
		return asked, nil

	default:
		return "", fmt.Errorf("%s: unknown credential kind %q", ErrCredentialKindField, asked)
	}
}

// ErrBasicCredentialRefused — ЕДИНСТВЕННЫЙ отказ полосы базового секрета.
//
// Неизвестный идентификатор, неверный секрет, истёкший срок, отозванное
// удостоверение, неактивный владелец, вид, не принимаемый этой поверхностью, —
// ОДНА И ТА ЖЕ ошибка. Различимый исход есть ОРАКУЛ: по нему отличают «нет
// такого» от «есть, но не ваш», то есть ровно то, что скрытие и должно
// закрыть.
//
// Различимость живёт ВНУТРЬ — в счётчиках по причинам, не в значении ошибки.
// Отдельным исходом остаётся только НЕДОСТУПНОСТЬ АВТОРИТЕТА: это не отказ в
// удостоверении, а неспособность установить его состояние, и предлагать
// вызывающему переаутентифицироваться на неисправность, которую не исправит ни
// одно его удостоверение, значило бы вводить его в заблуждение.
var ErrBasicCredentialRefused = errors.New("credential refused")

// BasicCredential — вердикт авторитета о годном предъявленном удостоверении.
type BasicCredential struct {
	// PrincipalType — "user" | "service_account".
	PrincipalType string
	PrincipalID   string
	DisplayName   string
	// CredentialID — идентификатор СТРОКИ; им адресуется отзыв.
	CredentialID string
	ExpiresAt    time.Time
}

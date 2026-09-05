// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"fmt"
	"regexp"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// SigningAlgorithm — алгоритм подписи токена. Словарь ЗАКРЫТ: значение вне
// него отвергается разбором конфигурации и стражем старта (приёмка F1 §3
// строка 1, F1-03). Открытый словарь означал бы «принимаем любой» — тот же
// класс, что пустой перечень.
type SigningAlgorithm string

// Закрытый словарь алгоритмов подписи. Значения ВЫВЕДЕНЫ из платформенного
// объявления (pkg/tokenpolicy), а не выписаны здесь второй раз: приёмная
// сторона живёт в другом сервисе, и две копии словаря разошлись бы молча — в
// сторону «принимаем больше», потому что расширять проще.
const (
	SigningAlgRS256 SigningAlgorithm = tokenpolicy.AlgRS256
	SigningAlgES256 SigningAlgorithm = tokenpolicy.AlgES256
	SigningAlgEdDSA SigningAlgorithm = tokenpolicy.AlgEdDSA
)

// SigningAlgorithms возвращает закрытый словарь целиком. Перечень ВЫВОДИТСЯ
// отсюда всеми, кому он нужен (страж старта, текст отказа, проверка ключа), а
// не выписывается по месту.
func SigningAlgorithms() []SigningAlgorithm {
	raw := tokenpolicy.Algorithms()
	out := make([]SigningAlgorithm, 0, len(raw))
	for _, a := range raw {
		out = append(out, SigningAlgorithm(a))
	}
	return out
}

// ParseSigningAlgorithm разбирает значение конфигурации. Пустое значение —
// НЕ «умолчание»: у алгоритма подписи умолчания нет, потому что подпись
// умолчанием — решение, принятое за оператора.
func ParseSigningAlgorithm(raw string) (SigningAlgorithm, error) {
	for _, a := range SigningAlgorithms() {
		if string(a) == raw {
			return a, nil
		}
	}
	return "", fmt.Errorf("signing algorithm %q is not one of %v", raw, SigningAlgorithms())
}

// MinBits — нижний порог стойкости ключа, объявленный ЧИСЛОМ и ровно в одном
// месте дерева (F1-02). Для RSA это длина модуля; для кривых и Ed25519 длина
// задана самой кривой, поэтому порог у них выражен размером, который эта
// кривая даёт.
func (a SigningAlgorithm) MinBits() int {
	switch a {
	case SigningAlgRS256:
		return 2048
	case SigningAlgES256:
		return 256
	case SigningAlgEdDSA:
		return 256
	default:
		return 0
	}
}

// SigningKeyState — состояние ключа в ключнице.
//
// Состояний ПЯТЬ, и «скомпрометирован» существует отдельно от «выведен»
// (приёмка §2.1): первое снимает ключ из набора немедленно, принимая отказ
// живых токенов, второе — нет. Глагол, делающий и то и другое, лишил бы второе
// решение его цены.
type SigningKeyState string

// Состояния ключа.
const (
	// SigningKeyPublished — ключ в наборе, но ещё не подписывает. Этап
	// существует ровно ради порядка «в наборе → подписывает» (§6.1).
	SigningKeyPublished SigningKeyState = "PUBLISHED"
	// SigningKeyActive — ключ подписывает. Такой РОВНО ОДИН, и это держит
	// частичный уникальный индекс, а не проверка в коде (§6.2).
	SigningKeyActive SigningKeyState = "ACTIVE"
	// SigningKeyRetired — выведен из подписи, остаётся в наборе всю отсрочку:
	// подписанные им токены доживают свой срок (§6.4).
	SigningKeyRetired SigningKeyState = "RETIRED"
	// SigningKeyRemoved — отсрочка истекла, ключа в наборе нет.
	SigningKeyRemoved SigningKeyState = "REMOVED"
	// SigningKeyCompromised — покидает набор НЕМЕДЛЕННО; живые токены
	// отвергаются, и это принятая цена, а не дефект.
	SigningKeyCompromised SigningKeyState = "COMPROMISED"
)

// InKeySet отвечает, попадает ли ключ в публикуемый набор.
//
// Ответ следует СОСТОЯНИЮ, а не факту существования строки: набор, отдающий
// все строки подряд, отдал бы и снятый, и скомпрометированный.
func (s SigningKeyState) InKeySet() bool {
	switch s {
	case SigningKeyPublished, SigningKeyActive, SigningKeyRetired:
		return true
	default:
		return false
	}
}

// CanActivate отвечает, допускает ли машина состояний переход в ACTIVE.
//
// Переход из REMOVED и COMPROMISED НЕ ВЫРАЖАЕТСЯ (F1-29): скомпрометированный
// ключ, вернувшийся в подпись, — не «редкий случай», а конструкция, которая
// получается сама, если её не запретить.
func (s SigningKeyState) CanActivate() bool {
	return s == SigningKeyPublished || s == SigningKeyActive
}

// kidPattern — форма идентификатора ключа. Значение попадает в заголовок
// токена и приходит обратно ОТ ПРЕДЪЯВИТЕЛЯ, поэтому форма ограничена
// до всякого использования (§6.8).
//
// Потолок длины ВЫВОДИТСЯ из политики платформы, а не выписан здесь числом:
// мест исполнения этой формы три — чеканка и две конфигурации приёма, — и
// разойтись им можно только молча (Ф1б, задача #926).
var kidPattern = regexp.MustCompile(
	fmt.Sprintf(`^[A-Za-z0-9._:-]{1,%d}$`, tokenpolicy.KeyIDMaxLen))

// KeyID — идентификатор ключа (`kid`).
type KeyID string

// Validate проверяет форму идентификатора ключа.
func (k KeyID) Validate() error {
	if !kidPattern.MatchString(string(k)) {
		return fmt.Errorf("key id has illegal form")
	}
	return nil
}

// ValidKeyIDForm — форма идентификатора ключа как предикат для приёмной
// стороны. Отдельная функция, а не экспортированная регулярка: регулярку
// вызывающий скопировал бы, и две копии разошлись бы молча.
func ValidKeyIDForm(raw string) bool { return kidPattern.MatchString(raw) }

// SigningKeyRecord — ХРАНИМАЯ форма ключа: несёт обёрнутую приватную половину.
//
// Пара к PublishedKey. Разделение типов держит §6.10 КОМПИЛЯТОРОМ: форма
// «поле есть, но мы его не заполняем» держалась бы вниманием.
type SigningKeyRecord struct {
	KID               KeyID
	Algorithm         SigningAlgorithm
	State             SigningKeyState
	PublicKeyPEM      string
	PrivateKeyWrapped []byte
	CreatedAt         time.Time
	NotAfter          time.Time
	ActivatedAt       *time.Time
	RetiredAt         *time.Time
	RemovedAt         *time.Time
	CompromisedAt     *time.Time
}

// Published — проекция строки в ПУБЛИКУЕМУЮ форму. Единственный переход между
// двумя типами, и он односторонний: обратного конструктора нет.
func (r SigningKeyRecord) Published() PublishedKey {
	return PublishedKey{KID: r.KID, Algorithm: r.Algorithm, PublicKeyPEM: r.PublicKeyPEM}
}

// PublishedKey — ПУБЛИКУЕМАЯ форма ключа.
//
// Поля приватной половины у этого типа НЕТ и быть не может (F1-05): положить
// её сюда не выражается, а не «запрещено правилом».
type PublishedKey struct {
	KID          KeyID
	Algorithm    SigningAlgorithm
	PublicKeyPEM string
}

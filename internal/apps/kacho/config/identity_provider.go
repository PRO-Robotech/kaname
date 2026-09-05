// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_provider.go — посадка личности со стороны настройки службы прав
// (задача #1125, подфаза Ф4д эпика #896).
//
// Сам СЛОВАРЬ значений здесь НЕ объявляется: он живёт в общем фундаменте
// (pkg/identityposture), потому что читают его ДВА процесса — служба прав и
// край, — а импортировать внутренности друг друга они не вправе. Второе
// объявление словаря разошлось бы с первым на первом же новом значении, и
// разошлось бы молча.
//
// Здесь живёт только то, что принадлежит ЭТОМУ процессу: имя его ручки и
// псевдонимы типа, чтобы настройка читалась без чужого префикса в каждой
// строке.
package config

import "github.com/PRO-Robotech/kacho/pkg/identityposture"

// IdentityProvider — посадка личности. Псевдоним общего типа, не второй тип.
type IdentityProvider = identityposture.Provider

// Значения — те же, что в общем фундаменте. Псевдонимы констант, а не вторая
// их нумерация: собственная нумерация разъехалась бы с общей молча.
const (
	IdentityProviderUnset    = identityposture.Unset
	IdentityProviderExternal = identityposture.External
	IdentityProviderOwn      = identityposture.Own
)

// IdentityProviderSetting — имя ЭТОЙ ручки: путь в настройке службы прав.
//
// Имя ручки у каждого процесса своё (на крае это переменная окружения), и
// называет его тот, кто отказывает: отказ, назвавший чужую ручку, посылает
// оператора править не тот профиль.
const IdentityProviderSetting = "authn." + identityposture.FieldName

// IdentityProviderValues / IdentityProviderNames — законные значения и их
// канонические имена, ВЫВЕДЕННЫЕ из словаря общего фундамента.
func IdentityProviderValues() []IdentityProvider { return identityposture.Values() }

// IdentityProviderNames возвращает канонические имена законных значений.
func IdentityProviderNames() []string { return identityposture.Names() }

// ParseIdentityProvider разбирает значение ручки службы прав тем же
// разборщиком, что и край. Второго разборщика не заводится.
func ParseIdentityProvider(s string) (IdentityProvider, error) {
	return identityposture.Parse(IdentityProviderSetting, s)
}

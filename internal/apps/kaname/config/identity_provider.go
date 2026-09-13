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

import "github.com/PRO-Robotech/corelib/identityposture"

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

// HasExternalIdentityProvider — существует ли у ЭТОЙ посадки внешний поставщик
// личности вообще (задача kaname#21).
//
// ЕДИНСТВЕННОЕ место, где вопрос решается. Читают его и композиционный корень
// (строить ли административную дорогу, публиковать ли запись зеркала чужих
// ключей), и наблюдатель провязки, который об этом отчитывается стражу посадки.
// Один предикат, два читателя — доложенное и сделанное разойтись не могут by
// construction; два предиката разошлись бы молча, и разошлись бы ровно на той
// посадке, ради которой служба выносится отдельным продуктом.
//
// ПОЧЕМУ «НЕ own», А НЕ «== external». Незаявленная посадка дорогу СОХРАНЯЕТ, и
// это решение, а не недосмотр: в боевом режиме незаявленное поле отвергается
// первым и в одиночку (validateIdentityProviderLane), а в непроизводственном
// требований полосы нет вовсе — in-process фикстура поставщика не имеет и
// стендом не является. То есть дорогу снимает ровно ОДНО объявленное значение,
// а не отсутствие объявления: умолчание, меняющее поведение молча, и есть тот
// класс, который эта задача закрывает.
func (c AuthNConfig) HasExternalIdentityProvider() bool {
	return c.IdentityProvider != IdentityProviderOwn
}

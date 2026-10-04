// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// service_identity.go — ключ `authn.service-identity` (приёмка NTF-1 Р2 п.2,
// NTF1-M09; замысел З13 «Ручка kaname», CX1-105).
//
// Значение — перечень методов и таблица пар `{san, name}`: форма списка пар,
// поэтому единственная её форма — файл настроек. Закрытый перечень ключей
// «только файл» (`fileOnlyKeys`, strict_env.go) снимает выведенные из ключа
// имена окружения с законных: таблица SAN служебного субъекта не задаётся
// окружением пода мимо рендера.
//
// Здесь только форма. Согласность (перечень непуст ⇔ таблица непуста, перечень
// закрыт `{ResolveSend}`, SAN канонический, без повторов SAN и имени) судит
// корень при сборке звена — отказ старта называет ручку и значение, а файл с
// несогласной ручкой декодером принимается.

// ServiceIdentityKey — путь ключа; его называют отказы корня и перечень
// «только файл».
const ServiceIdentityKey = "authn.service-identity"

// ServiceIdentityMethodsKey / ServiceIdentityServicesKey — пути частей ключа.
const (
	ServiceIdentityMethodsKey  = ServiceIdentityKey + ".methods"
	ServiceIdentityServicesKey = ServiceIdentityKey + ".services"
)

// ServiceIdentityConfig — секция `authn.service-identity`.
type ServiceIdentityConfig struct {
	// Methods — перечень полных имён методов без ведущей косой
	// (`kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend`).
	Methods []string `mapstructure:"methods"`
	// Services — таблица `{точный SAN → имя службы}`, по строке на службу.
	Services []ServiceIdentityEntry `mapstructure:"services"`
}

// ServiceIdentityEntry — строка таблицы звена.
type ServiceIdentityEntry struct {
	// SAN — точный SPIFFE-идентификатор службы в канонической форме.
	SAN string `mapstructure:"san"`
	// Name — имя службы в субъекте `service:<имя>` (DNS label).
	Name string `mapstructure:"name"`
}

// IsEmpty — ключ не задан либо обе части пусты: звена нет.
func (s ServiceIdentityConfig) IsEmpty() bool {
	return len(s.Methods) == 0 && len(s.Services) == 0
}

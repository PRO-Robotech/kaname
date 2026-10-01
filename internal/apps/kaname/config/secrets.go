// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// secrets.go — ФАЙЛЫ КЛЮЧЕЙ ПОЧТОВОЙ ПОЛОСЫ (замысел NTF-2 З18, CX2-13).
//
// Два ключа — два удостоверения профиля, файлом каждый:
//
//	mail-window-key-file   k_window: свёртка ключа окна адресата и адресов
//	                       ожидающих регистраций (З11, З14);
//	device-label-key-file  k_device: подпись метки доверенного устройства (З18).
//
// Поддерево `authn.secrets.*` стоит ВНЕ `authn.login.*` намеренно: под
// `authn.login.*` живут 32 ручки лимитов таблицы Р8, и путь файла секрета не
// должен смешиваться с ними ни в переписи, ни в документе установки.
//
// Вывода из другого секрета нет: незаданный путь — отказ старта с именем ручки
// (строка таблицы границ вида «обязателен», `mail_bounds.go`). Чтение файла и
// его длину (не короче 32 байт) судит потребитель ключа в композиционном
// корне — там, где ключ становится материалом; настройка видит только путь.
//
// Смена k_window обнуляет окна адресатов и ожидающие регистрации (прежние
// свёртки не совпадут); смена k_device делает недействительными все метки.

// SecretsConfig — секция `authn.secrets`.
type SecretsConfig struct {
	// MailWindowKeyFile — путь к файлу ключа k_window.
	MailWindowKeyFile string `mapstructure:"mail-window-key-file"`
	// DeviceLabelKeyFile — путь к файлу ключа k_device.
	DeviceLabelKeyFile string `mapstructure:"device-label-key-file"`
}

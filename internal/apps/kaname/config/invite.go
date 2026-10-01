// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite.go — величины ПРИГЛАШЕНИЯ как нашей сущности (приёмка ID-MAIL-1,
// §10 пп. 10 и 22; приёмка NTF-2 Р8, замысел NTF-2 З23, З24).
//
// # СРОК И ПОТОЛКИ — РУЧКИ ТАБЛИЦЫ ГРАНИЦ, БЕЗ УМОЛЧАНИЯ
//
// Срок строки приглашения и семь потолков приглашений — строки таблицы Р8
// (`mail_bounds.go`): величину объявляет посадка, незаданная — отказ старта с
// именем ключа, величина за границей — отказ с названной границей (NTF2-71).
// Прежнее умолчание срока (неделя у ручки) снято: величина, которую подставляет
// построение, предметом стража быть не может — незаданной она не бывает.
// Ориентир базового профиля — те же семь суток, но живёт он в профиле.
//
// # ОТЛИЧИЕ ОТ ОГРАНИЧЕНИЯ ЧАСТОТЫ ПИСЕМ (`mail-rate-limit`)
//
// Ограничение частоты писем на адрес — величина прежнего собственного
// отправителя. Оно снимается вместе со своим читателем (замысел NTF-2 З6) и до
// того сохраняет прежнюю форму: умолчание объявлено загрузчику, явный ноль —
// отказ старта.
package config

import (
	"fmt"
	"time"
)

// Умолчание ограничения частоты писем НА АДРЕС за окно (Р14, MAIL-42).
//
// ВЕЛИЧИНА НАЗНАЧЕНА РЕШЕНИЕМ, А НЕ ЗАМЕРОМ, и это сказано прямо: замера нет
// и не будет до эксплуатации — сегодня писем не уходит ни одного. Три письма в
// час одному адресу покрывают штатный ход администратора («не дошло —
// отправлю ещё раз, и ещё раз через десять минут») и не дают обладателю права
// приглашать сделать из продукта средство рассылки (§4.6 приёмки).
//
// ПРЕДИКАТ ПЕРЕСМОТРА: доля исходов `rate_limited` счётчика намерений отправки
// среди законных обращений выше доли, объявленной профилем, ⇒ величина мала;
// ноль таких исходов за квартал при живой доставке ⇒ ограничение не сужает
// ничего и может быть тесней.
//
// УМОЛЧАНИЕ ОБЪЯВЛЕНО ЗАГРУЗЧИКУ (`defaults.go`), а не подставлено у ручки — в
// отличие от срока выше. Различие несущее: у срока ноль читается как «не
// объявлено», потому что умолчание живёт у ручки и загрузчик отдаёт ноль и
// молчащему профилю, и написавшему ноль. Здесь молчащий профиль получает
// умолчание от загрузчика, а ноль до поля доезжает ТОЛЬКО написанным рукой —
// и это попытка снять ограничение, которую страж обязан отвергнуть (MAIL-43).
const (
	DefaultInviteMailPerWindow = 3
	DefaultInviteMailWindow    = time.Hour
)

// InviteMailRateLimitConfig — секция `invite.mail-rate-limit`.
//
//	MaxPerWindow — сколько писем одному адресу за окно; положительное.
//	Window       — длина окна; положительная.
//
// Ограничение действует на КАЖДЫЙ наш глагол, отправляющий письмо (Р22):
// его списывает писатель очереди перед постановкой намерения, поэтому глагол,
// минующий ограничитель, невыразим — у него нет другого пути к письму.
type InviteMailRateLimitConfig struct {
	MaxPerWindow int           `mapstructure:"max-per-window"`
	Window       time.Duration `mapstructure:"window"`
}

// InviteConfig — секция `invite`. Указатель — ручка таблицы границ Р8: nil
// означает «ключ не объявлен».
type InviteConfig struct {
	// TTL — срок строки приглашения: после него активация отвергается.
	TTL *time.Duration `mapstructure:"ttl"`
	// AccountPerDay — приглашений одного аккаунта в сутки.
	AccountPerDay *int `mapstructure:"account-per-day"`
	// YoungAccountPerDay — то же для аккаунта моложе YoungAccountAge.
	YoungAccountPerDay *int `mapstructure:"young-account-per-day"`
	// YoungAccountAge — возраст, до которого аккаунт считается молодым.
	YoungAccountAge *time.Duration `mapstructure:"young-account-age"`
	// PendingMax — висящих приглашений одного аккаунта.
	PendingMax *int `mapstructure:"pending-max"`
	// RecipientPerHour, RecipientPerDay — писем приглашения одному адресату от
	// одного аккаунта в час и в сутки.
	RecipientPerHour *int `mapstructure:"recipient-per-hour"`
	RecipientPerDay  *int `mapstructure:"recipient-per-day"`
	// RecipientPerDayAll — писем приглашения одному адресату в сутки поперёк
	// аккаунтов.
	RecipientPerDayAll *int `mapstructure:"recipient-per-day-all"`
	// MailRateLimit — ограничение частоты писем на адрес прежнего отправителя.
	MailRateLimit InviteMailRateLimitConfig `mapstructure:"mail-rate-limit"`
}

// Validate — страж ограничения частоты писем прежнего отправителя. Срок и
// потолки приглашений судит страж таблицы границ (`Config.ValidateMailBounds`).
func (c InviteConfig) Validate() error {
	// ОГРАНИЧЕНИЕ ЧАСТОТЫ: НЕПОЗИТИВНОЕ — ОТКАЗ, включая явный ноль (MAIL-43).
	// Значения «без ограничения» в словаре ручки не существует; умолчание
	// объявлено загрузчику, поэтому ноль здесь всегда написан рукой.
	if c.MailRateLimit.MaxPerWindow <= 0 {
		return fmt.Errorf(
			"invite.mail-rate-limit.max-per-window must be positive (got %d) — it caps the "+
				"letters one address receives per window, and there is no value meaning "+
				"«unlimited»: the profile may change the cap, never remove it",
			c.MailRateLimit.MaxPerWindow)
	}
	if c.MailRateLimit.Window <= 0 {
		return fmt.Errorf(
			"invite.mail-rate-limit.window must be positive (got %s) — it is the window the "+
				"per-address cap is counted over, and a zero window would count nothing",
			c.MailRateLimit.Window)
	}
	return nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// ceremony_lifespans.go — СРОКИ АРТЕФАКТОВ собственной церемонии OAuth 2.1
// `authorization_code`, объявленные установкой (задача PRO-Robotech/kaname#318;
// приёмка `ceremony-lifespans-are-declared-within-their-ceilings.md`, Р1–Р5).
//
// # Две ручки, два потолка фундамента
//
//	authn.ceremony.code-ttl     срок кода авторизации от его выдачи;
//	                            потолок tokenpolicy.MaxAuthorizationCodeTTL
//	authn.ceremony.refresh-ttl  срок СЕМЕЙСТВА токенов обновления от первой
//	                            выдачи; оборот его не продлевает; потолок
//	                            tokenpolicy.MaxRefreshTokenFamilyTTL
//
// Допустимый диапазон — `0 < срок ≤ потолок`, потолок входит (Р4). Судит его
// страж старта константами фундамента: своей копии числа у службы нет, и потолок
// в тексте отказа печатается из той же константы.
//
// # Умолчания нет: ноль значит «не названо» (Р3)
//
// Величина, которую подставляет построение, предметом стража быть не может: он
// зелен при любом входе. Поэтому умолчания нет ни здесь, ни в `defaults.go`, а
// ключи привязаны к окружению явно в `load.go` — `AutomaticEnv` разрешает
// переменную только для ключа, который viper уже знает. Незаданная величина
// доезжает до стража нулём и отвергает старт.
//
// # Только под посадкой `own` (Р5)
//
// Церемония собирается только там (`cmd/kaname/ceremony.go`). Под `external`
// ручки не требуются и не судятся: названная величина, даже выше потолка, там
// никем не читается.

import (
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
)

// CeremonyConfig — сроки собственной церемонии; ключи под `authn.ceremony.*`.
type CeremonyConfig struct {
	// CodeTTL — срок кода авторизации от его выдачи.
	CodeTTL time.Duration `mapstructure:"code-ttl"`
	// RefreshTTL — срок семейства токенов обновления от первой выдачи. Его
	// читают и срок одного токена обновления, и граница семейства: оборот
	// выпускает преемника, но предел семейства не сдвигает.
	RefreshTTL time.Duration `mapstructure:"refresh-ttl"`
}

// ceremonyLifespanKnob — одна ручка срока: ключ, переменная, потолок и доступ к
// полю. Таблица — единственное место, где ключ связан с потолком.
type ceremonyLifespanKnob struct {
	// Key — путь ключа в файле настроек; координата, которую называет отказ.
	Key string
	// Env — имя переменной окружения; привязывается в `Load`.
	Env string
	// Ceiling — потолок фундамента. Значение константы, а не копия числа.
	Ceiling time.Duration
	// CeilingName — имя той же константы для текста отказа.
	CeilingName string
	// What — что называет срок, словами оператора.
	What string
	// Value — доступ к полю.
	Value func(CeremonyConfig) time.Duration
}

const ceremonyKeyPrefix = "authn.ceremony."

// CeremonyLifespanKnobs — ТАБЛИЦА ручек сроков. Читается `Load` (привязка
// окружения), стражем (имя в отказе) и таблицей обязательных величин.
var CeremonyLifespanKnobs = []ceremonyLifespanKnob{
	{
		Key:         ceremonyKeyPrefix + "code-ttl",
		Env:         "KANAME_AUTHN__CEREMONY__CODE_TTL",
		Ceiling:     tokenpolicy.MaxAuthorizationCodeTTL,
		CeilingName: "tokenpolicy.MaxAuthorizationCodeTTL",
		What:        "срок кода авторизации от его выдачи",
		Value:       func(c CeremonyConfig) time.Duration { return c.CodeTTL },
	},
	{
		Key:         ceremonyKeyPrefix + "refresh-ttl",
		Env:         "KANAME_AUTHN__CEREMONY__REFRESH_TTL",
		Ceiling:     tokenpolicy.MaxRefreshTokenFamilyTTL,
		CeilingName: "tokenpolicy.MaxRefreshTokenFamilyTTL",
		What:        "срок семейства токенов обновления от первой выдачи",
		Value:       func(c CeremonyConfig) time.Duration { return c.RefreshTTL },
	},
}

// Validate — страж сроков: каждая ручка названа положительной и не выше своего
// потолка. Отказ по КАЖДОЙ ручке сразу (multierr): оператор узнаёт обе за один
// перезапуск. Соотношений между ручками и с соседними сроками страж не судит:
// граница семейства и так сужает все три вида артефактов гранта, и короткий срок
// ничего не расширяет.
func (c CeremonyConfig) Validate() error {
	var errs error
	for _, k := range CeremonyLifespanKnobs {
		v := k.Value(c)
		switch {
		case v <= 0:
			errs = multierr.Append(errs, fmt.Errorf(
				"%s не задан (%s): %s — величина посадки без умолчания в коде, не выше %s (%s); "+
					"незаданная, нулевая и отрицательная не принимаются",
				k.Key, k.Env, k.What, k.CeilingName, k.Ceiling))
		case v > k.Ceiling:
			errs = multierr.Append(errs, fmt.Errorf(
				"%s = %s (%s) выше потолка %s = %s: %s не бывает длиннее потолка фундамента",
				k.Key, v, k.Env, k.CeilingName, k.Ceiling, k.What))
		}
	}
	return errs
}

// ceremonyLifespanRequirement — строка таблицы обязательных величин, ПОРОЖДЁННАЯ
// из таблицы ручек сроков: ключ, переменная и потолок берутся у неё, а не
// пишутся второй раз — смена потолка в фундаменте меняет и документ установки.
// Подстрока отказа — сам ключ: он стоит в тексте обеих ветвей стража.
func ceremonyLifespanRequirement(short, sample, why string) RequiredSetting {
	key := ceremonyKeyPrefix + short
	row := RequiredSetting{
		Key:     key,
		Supply:  SupplyEnv,
		Sample:  sample,
		Why:     why,
		Refusal: key,
	}
	for _, k := range CeremonyLifespanKnobs {
		if k.Key == key {
			row.Env = k.Env
			row.Why = fmt.Sprintf("%s. Не выше потолка фундамента %s (%s); ноль и отрицательный не принимаются. "+
				"Умолчания нет: величину выбирает тот, кто ставит службу", why, k.CeilingName, k.Ceiling)
		}
	}
	return row
}

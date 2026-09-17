// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

// registration.go — НАСТРОЙКА регистрации нашей полосой (фаза Ф4, задача
// PRO-Robotech/kacho#1270; решение Р5, сценарии Ф4-17…Ф4-19).
//
// # Потолок ТЕМПА заведения — величина ПОСАДКИ `own`
//
// Рубеж в дереве есть: триггер `accounts_rate_admission` считает заведения
// аккаунтов одной личностью за окно и ключуется тем, чем человек представился.
// До Ф4 ключом был идентификатор у чужого поставщика; на полосе `own` его нет,
// носителем стал адрес (миграция `registration_carrier_keys_the_admission_rate`).
// Величина при этом объявляется профилем и незаданная даёт отказ старта (Ф1 §7
// инв. 4): подставленная построением она предметом стража быть не может.
//
// Первое заведение носителя — сама регистрация — проходит БЕЗУСЛОВНО, при
// любой объявленной величине (ветвь вставки триггера): отказ по темпу на
// первом заведении был бы отказом завестись. Величина ограничивает N+1-е
// заведение в окне: повторную регистрацию адресом, чья строка снята, и
// последующие `Account.Create` того же человека. Ноль законен: сверх первого —
// ни одного.
//
// # Почему под `own`, и что под `external`
//
// Требование предъявляется ПОСАДКЕ `own` строкой таблицы полос: только там
// ключом служит адрес, и только там служба сама проецирует величину в схему
// на старте (`cmd/kaname`). Под `external` строка авторитета
// (`account_admission_rate_limits`) остаётся у администратора облака, как и
// прежде, — второго писателя у неё не заводится.

import (
	"fmt"
	"time"

	"go.uber.org/multierr"
)

// RegistrationConfig — ручки регистрации; все под `authn.registration.*`.
type RegistrationConfig struct {
	// AdmissionsPerWindow — сколько заведений аккаунтов одна личность делает за
	// окно СВЕРХ первого. Указатель: ноль законен и отличим от «не задано».
	AdmissionsPerWindow *int64 `mapstructure:"admissions-per-window"`
	// AdmissionWindow — окно счёта.
	AdmissionWindow time.Duration `mapstructure:"admission-window"`
}

// registrationKnob — пара «ключ настройки ↔ переменная среды» одной ручки.
type registrationKnob struct {
	Key string
	Env string
}

const registrationKeyPrefix = "authn.registration."

// RegistrationKnobs — перечень ручек регистрации одним объявлением. Читается
// `Load` (привязка окружения), документом оператора и стражами (имя в отказе).
var RegistrationKnobs = []registrationKnob{
	{registrationKeyPrefix + "admissions-per-window", "KANAME_AUTHN__REGISTRATION__ADMISSIONS_PER_WINDOW"},
	{registrationKeyPrefix + "admission-window", "KANAME_AUTHN__REGISTRATION__ADMISSION_WINDOW"},
}

func registrationEnv(key string) string {
	for _, k := range RegistrationKnobs {
		if k.Key == key {
			return k.Env
		}
	}
	return ""
}

// ValidateAdmissionRate — величина темпа объявлена и годна (Ф4-18): предел —
// неотрицательное целое, окно — положительное; незаданное названо своей ручкой.
func (r RegistrationConfig) ValidateAdmissionRate() error {
	var errs error
	maxKey, winKey := registrationKeyPrefix+"admissions-per-window", registrationKeyPrefix+"admission-window"
	switch {
	case r.AdmissionsPerWindow == nil:
		errs = multierr.Append(errs, fmt.Errorf("%s не задан (%s): потолок темпа заведения аккаунтов одной личностью объявляет "+
			"ПОСАДКА; первое заведение (регистрация) проходит безусловно, величина ограничивает следующие за окно. "+
			"Задайте неотрицательное целое; 0 означает «сверх первого — ни одного»", maxKey, registrationEnv(maxKey)))
	case *r.AdmissionsPerWindow < 0:
		errs = multierr.Append(errs, fmt.Errorf("%s = %d (%s): предел обязан быть неотрицательным; отрицательное НЕ означает "+
			"«без ограничения»", maxKey, *r.AdmissionsPerWindow, registrationEnv(maxKey)))
	}
	if r.AdmissionWindow <= 0 {
		errs = multierr.Append(errs, fmt.Errorf("%s не задан (%s): окно счёта заведений — положительная длительность",
			winKey, registrationEnv(winKey)))
	}
	return errs
}

// AdmissionRate — объявленная величина: предел и окно. Страж выше не допускает
// незаданной; здесь незаданный предел читается нулём, чтобы проекция не могла
// молча расширить рубеж.
func (r RegistrationConfig) AdmissionRate() (maxEvents int64, window time.Duration) {
	if r.AdmissionsPerWindow != nil {
		maxEvents = *r.AdmissionsPerWindow
	}
	return maxEvents, r.AdmissionWindow
}
